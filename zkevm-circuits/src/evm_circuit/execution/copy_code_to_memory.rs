use array_init::array_init;
use bus_mapping::{
    circuit_input_builder::{CopyCodeToMemoryAuxData, StepAuxiliaryData},
    constants::MAX_COPY_BYTES,
};
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{circuit::Region, plonk::Error};

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
            math_gadget::ComparisonGadget,
            memory_gadget::BufferReaderGadget,
            Cell, Word,
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
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        // Read the auxiliary data.
        let CopyCodeToMemoryAuxData {
            src_addr,
            dst_addr,
            bytes_left,
            src_addr_end,
            code_source,
        } = match step.aux_data {
            Some(StepAuxiliaryData::CopyCodeToMemory(aux)) => aux,
            _ => unreachable!("could not find CopyCodeToMemory aux_data for COPYCODETOMEMORY"),
        };

        let code = block
            .bytecodes
            .iter()
            .find(|b| b.hash == code_source)
            .unwrap_or_else(|| panic!("could not find bytecode for source {:?}", code_source));
        // Assign to the appropriate cells.
        self.src_addr
            .assign(region, offset, Some(F::from(src_addr)))?;
        self.dst_addr
            .assign(region, offset, Some(F::from(dst_addr)))?;
        self.bytes_left
            .assign(region, offset, Some(F::from(bytes_left)))?;
        self.src_addr_end
            .assign(region, offset, Some(F::from(src_addr_end)))?;
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
        for idx in 0..std::cmp::min(bytes_left as usize, MAX_COPY_BYTES) {
            selectors[idx] = true;
            let addr = src_addr as usize + idx;
            bytes[idx] = if addr < src_addr_end as usize {
                assert!(addr < code.bytes.len());
                self.is_codes[idx].assign(region, offset, Some(is_codes[addr]))?;
                code.bytes[addr]
            } else {
                0
            };
        }

        self.buffer_reader
            .assign(region, offset, src_addr, src_addr_end, &bytes, &selectors)?;

        // The number of bytes copied here will be the sum of 1s over the selector
        // vector.
        let num_bytes_copied = std::cmp::min(bytes_left, MAX_COPY_BYTES as u64);

        // Assign the comparison gadget.
        self.finish_gadget.assign(
            region,
            offset,
            F::from(num_bytes_copied),
            F::from(bytes_left),
        )?;

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::MAX_COPY_BYTES;
    use std::collections::HashMap;

    use bus_mapping::{
        circuit_input_builder::{CopyCodeToMemoryAuxData, StepAuxiliaryData},
        evm::OpcodeId,
    };
    use eth_types::{bytecode, Word};
    use halo2_proofs::arithmetic::BaseExt;
    use pairing::bn256::Fr;

    use crate::evm_circuit::{
        step::ExecutionState,
        table::RwTableTag,
        test::run_test_circuit_incomplete_fixed_table,
        witness::{Block, Bytecode, Call, CodeSource, ExecStep, Rw, RwMap, Transaction},
    };

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn make_copy_code_step(
        call_id: usize,
        src_addr: u64,
        dst_addr: u64,
        src_addr_end: u64,
        bytes_left: usize,
        program_counter: u64,
        stack_pointer: usize,
        memory_size: u64,
        rw_counter: usize,
        rws: &mut RwMap,
        bytes_map: &HashMap<u64, u8>,
        code: &Bytecode,
    ) -> (ExecStep, usize) {
        let mut rw_offset = 0usize;
        let memory_rws: &mut Vec<_> = rws.0.entry(RwTableTag::Memory).or_insert_with(Vec::new);
        let rw_idx_start = memory_rws.len();

        for idx in 0..std::cmp::min(bytes_left, MAX_COPY_BYTES) {
            let addr = src_addr + idx as u64;
            let byte = if addr < src_addr_end {
                assert!(bytes_map.contains_key(&addr));
                bytes_map[&addr]
            } else {
                0
            };
            memory_rws.push(Rw::Memory {
                rw_counter: rw_counter + rw_offset,
                is_write: true,
                call_id,
                memory_address: dst_addr + idx as u64,
                byte,
            });
            rw_offset += 1;
        }

        let rw_idx_end = rws.0[&RwTableTag::Memory].len();
        let aux_data = StepAuxiliaryData::CopyCodeToMemory(CopyCodeToMemoryAuxData {
            src_addr,
            dst_addr,
            bytes_left: bytes_left as u64,
            src_addr_end,
            code_source: code.hash,
        });
        let step = ExecStep {
            execution_state: ExecutionState::CopyCodeToMemory,
            rw_indices: (rw_idx_start..rw_idx_end)
                .map(|idx| (RwTableTag::Memory, idx))
                .collect(),
            rw_counter,
            program_counter,
            stack_pointer,
            memory_size,
            gas_cost: 0,
            aux_data: Some(aux_data),
            ..Default::default()
        };

        (step, rw_offset)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn make_copy_code_steps(
        call_id: usize,
        code: &Bytecode,
        src_addr: u64,
        dst_addr: u64,
        length: usize,
        program_counter: u64,
        stack_pointer: usize,
        memory_size: u64,
        rw_counter: &mut usize,
        rws: &mut RwMap,
        steps: &mut Vec<ExecStep>,
    ) {
        let bytes_map = (0..(code.bytes.len() as u64))
            .zip(code.bytes.iter().copied())
            .collect();

        let mut copied = 0;
        while copied < length {
            let (step, rw_offset) = make_copy_code_step(
                call_id,
                src_addr + copied as u64,
                dst_addr + copied as u64,
                code.bytes.len() as u64,
                length - copied,
                program_counter,
                stack_pointer,
                memory_size,
                *rw_counter,
                rws,
                &bytes_map,
                code,
            );
            steps.push(step);
            *rw_counter += rw_offset;
            copied += MAX_COPY_BYTES;
        }
    }

    fn test_ok(src_addr: u64, dst_addr: u64, length: usize) {
        let randomness = Fr::rand();
        let call_id = 1;
        let mut rws = RwMap::default();
        let mut rw_counter = 1;
        let mut steps = Vec::new();
        let memory_size = (dst_addr + length as u64 + 31) / 32 * 32;

        // generate random bytecode longer than `src_addr_end`
        let code = bytecode! {
            PUSH32(Word::from(0x123))
            POP
            PUSH32(Word::from(0x213))
            POP
            PUSH32(Word::from(0x321))
            POP
            PUSH32(Word::from(0x12349AB))
            POP
            PUSH32(Word::from(0x1928835))
            POP
        };

        let code = Bytecode::new(code.to_vec());
        let dummy_code = Bytecode::new(vec![OpcodeId::STOP.as_u8()]);

        let program_counter = 0;
        let stack_pointer = 1024;
        make_copy_code_steps(
            call_id,
            &code,
            src_addr,
            dst_addr,
            length,
            program_counter,
            stack_pointer,
            memory_size,
            &mut rw_counter,
            &mut rws,
            &mut steps,
        );

        steps.push(ExecStep {
            execution_state: ExecutionState::STOP,
            rw_counter,
            program_counter,
            stack_pointer,
            memory_size,
            opcode: Some(OpcodeId::STOP),
            ..Default::default()
        });

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: 1,
                calls: vec![Call {
                    id: call_id,
                    is_root: true,
                    is_create: false,
                    code_source: CodeSource::Account(dummy_code.hash),
                    ..Default::default()
                }],
                steps,
                ..Default::default()
            }],
            rws,
            bytecodes: vec![dummy_code, code],
            ..Default::default()
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn copy_code_to_memory_single_step() {
        test_ok(
            0x00, // src_addr
            0x00, // dst_addr
            54,   // length
        );
    }

    #[test]
    fn copy_code_to_memory_multi_step() {
        test_ok(
            0x00, // src_addr
            0x40, // dst_addr
            123,  // length
        );
    }

    #[test]
    fn copy_code_to_memory_oob() {
        // since the bytecode we construct above is (34 * 5) = 170 bytes long, copying
        // 200 bytes means we go out-of-bounds.
        test_ok(
            0x10, // src_addr
            0x20, // dst_addr
            200,  // length
        );
    }
}
