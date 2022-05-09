use array_init::array_init;
use bus_mapping::{circuit_input_builder::CopyDetails, constants::MAX_COPY_BYTES};
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::plonk::Error;

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
            math_gadget::ComparisonGadget,
            memory_gadget::BufferReaderGadget,
            CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
/// This gadget is responsible for copying bytes from an account's code to
/// memory. This is an internal gadget used by the `CodeCopyGadget`.
pub(crate) struct CopyCodeToMemoryGadget<F> {
    /// Offset in the source (bytecode) to read from.
    src_addr: Cell<F>,
    /// Offset in the destination (memory) to write to.
    dst_addr: Cell<F>,
    /// Number of bytes left to be copied in this iteration.
    bytes_left: Cell<F>,
    /// Source (bytecode) bytes end here.
    src_addr_end: Cell<F>,
    /// Keccak-256 hash of the bytecode source.
    code_source: Word<F>,
    /// Array of booleans to mark whether or not the byte in question is an
    /// opcode byte or an argument that follows the opcode. For example,
    /// `is_code = true` for `POP`, `is_code = true` for `PUSH32`, but
    /// `is_code = false` for the 32 bytes that follow the `PUSH32` opcode.
    is_codes: [Cell<F>; MAX_COPY_BYTES],
    /// Gadget to assign bytecode to buffer and read byte-by-byte.
    buffer_reader: BufferReaderGadget<F, MAX_COPY_BYTES, N_BYTES_MEMORY_ADDRESS>,
    /// Comparison gadget to conditionally stop this iterative internal step
    /// once all the bytes have been copied.
    finish_gadget: ComparisonGadget<F, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: Field> ExecutionGadget<F> for CopyCodeToMemoryGadget<F> {
    const NAME: &'static str = "COPYCODETOMEMORY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CopyCodeToMemory;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Query cells for the internal step's auxiliary data and construct the buffer
        // reader.
        let src_addr = cb.query_cell();
        let dst_addr = cb.query_cell();
        let bytes_left = cb.query_cell();
        let src_addr_end = cb.query_cell();
        let code_source = cb.query_word();
        let is_codes = array_init(|_| cb.query_bool());
        let buffer_reader = BufferReaderGadget::construct(cb, src_addr.expr(), src_addr_end.expr());

        // For every byte in the bytecode's span covered in this iteration.
        for (idx, is_code) in is_codes.iter().enumerate() {
            // Lookup the bytecode table for the byte value read at the appropriate source
            // memory address from the buffer.
            cb.condition(buffer_reader.read_flag(idx), |cb| {
                cb.bytecode_lookup(
                    code_source.expr(),
                    src_addr.expr() + idx.expr(),
                    is_code.expr(),
                    buffer_reader.byte(idx),
                );
            });
            // Lookup the RW table for a memory write operation at the appropriate
            // destination memory address.
            cb.condition(buffer_reader.has_data(idx), |cb| {
                cb.memory_lookup(
                    1.expr(),
                    dst_addr.expr() + idx.expr(),
                    buffer_reader.byte(idx),
                    None,
                );
            });
        }

        // Construct the comparison gadget using the number of bytes copied in this
        // iteration and the number bytes that were left to be copied before the
        // start of this iteration.
        let copied_size = buffer_reader.num_bytes();
        let finish_gadget = ComparisonGadget::construct(cb, copied_size.clone(), bytes_left.expr());
        let (lt, finished) = finish_gadget.expr();

        // We should have continued only until there were no more bytes left to be
        // copied. In case the copied size was less than the number of bytes
        // left, the iterative process should not be finished.
        cb.add_constraint(
            "Constrain num_bytes <= bytes_left",
            (1.expr() - lt) * (1.expr() - finished.clone()),
        );

        // If the iterative process has not yet finished, we constrain the next step to
        // be another `CopyCodeToMemory` while adding some additional
        // constraints to the auxiliary data.
        cb.constrain_next_step(
            ExecutionState::CopyCodeToMemory,
            Some(1.expr() - finished),
            |cb| {
                let next_src_addr = cb.query_cell();
                let next_dst_addr = cb.query_cell();
                let next_bytes_left = cb.query_cell();
                let next_src_addr_end = cb.query_cell();
                let next_code_source = cb.query_word();

                cb.require_equal(
                    "next_src_addr == src_addr + copied_size",
                    next_src_addr.expr(),
                    src_addr.expr() + copied_size.clone(),
                );
                cb.require_equal(
                    "dst_addr + copied_size == next_dst_addr",
                    next_dst_addr.expr(),
                    dst_addr.expr() + copied_size.clone(),
                );
                cb.require_equal(
                    "next_bytes_left == bytes_left - copied_size",
                    next_bytes_left.expr(),
                    bytes_left.expr() - copied_size.clone(),
                );
                cb.require_equal(
                    "next_src_addr_end == src_addr_end",
                    next_src_addr_end.expr(),
                    src_addr_end.expr(),
                );
                cb.require_equal(
                    "next_code_sourcec == code_source",
                    next_code_source.expr(),
                    code_source.expr(),
                );
            },
        );

        // Since this is an internal step for `CODECOPY` opcode, we only increment the
        // RW counter. The program counter, stack pointer, and other fields do
        // not change.
        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset()),
            ..Default::default()
        };
        cb.require_step_state_transition(step_state_transition);

        Self {
            src_addr,
            dst_addr,
            bytes_left,
            src_addr_end,
            code_source,
            is_codes,
            buffer_reader,
            finish_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        // Read the auxiliary data.
        let aux = if step.aux_data.is_none() {
            // TODO: Handle error correctly returning err
            unreachable!("could not find aux_data for this step")
        } else {
            step.aux_data.unwrap()
        };

        let code_source = match aux.copy_details() {
            CopyDetails::Code(code) => code,
            _ => unreachable!("the source has to come from code not calldata"),
        };

        let code = block
            .bytecodes
            .iter()
            .find(|b| b.hash == code_source)
            .unwrap_or_else(|| panic!("could not find bytecode for source {:?}", code_source));
        // Assign to the appropriate cells.
        self.src_addr
            .assign(region, offset, Some(F::from(aux.src_addr())))?;
        self.dst_addr
            .assign(region, offset, Some(F::from(aux.dst_addr())))?;
        self.bytes_left
            .assign(region, offset, Some(F::from(aux.bytes_left())))?;
        self.src_addr_end
            .assign(region, offset, Some(F::from(aux.src_addr_end())))?;
        self.code_source
            .assign(region, offset, Some(code.hash.to_le_bytes()))?;

        // Initialise selectors and bytes for the buffer reader.
        let mut selectors = vec![false; MAX_COPY_BYTES];
        let mut bytes = vec![0u8; MAX_COPY_BYTES];
        let is_codes = code
            .table_assignments(block.randomness)
            .iter()
            .skip(1)
            .map(|c| c[3])
            .collect::<Vec<F>>();
        for idx in 0..std::cmp::min(aux.bytes_left() as usize, MAX_COPY_BYTES) {
            selectors[idx] = true;
            let addr = aux.src_addr() as usize + idx;
            bytes[idx] = if addr < aux.src_addr_end() as usize {
                assert!(addr < code.bytes.len());
                self.is_codes[idx].assign(region, offset, Some(is_codes[addr]))?;
                code.bytes[addr]
            } else {
                0
            };
        }

        self.buffer_reader.assign(
            region,
            offset,
            aux.src_addr(),
            aux.src_addr_end(),
            &bytes,
            &selectors,
        )?;

        // The number of bytes copied here will be the sum of 1s over the selector
        // vector.
        let num_bytes_copied = std::cmp::min(aux.bytes_left(), MAX_COPY_BYTES as u64);

        // Assign the comparison gadget.
        self.finish_gadget.assign(
            region,
            offset,
            F::from(num_bytes_copied),
            F::from(aux.bytes_left()),
        )?;

        Ok(())
    }
}
