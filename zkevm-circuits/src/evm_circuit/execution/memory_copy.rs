use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        table::TxContextFieldTag,
        util::{
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::ComparisonGadget,
            memory_gadget::BufferReaderGadget,
            Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::{
    circuit_input_builder::{CopyToMemoryAuxData, StepAuxiliaryData},
    constants::MAX_COPY_BYTES,
};
use eth_types::Field;
use halo2_proofs::{circuit::Region, plonk::Error};

/// Multi-step gadget for copying data from memory or Tx calldata to memory
#[derive(Clone, Debug)]
pub(crate) struct CopyToMemoryGadget<F> {
    // The src memory address to copy from
    src_addr: Cell<F>,
    // The dst memory address to copy to
    dst_addr: Cell<F>,
    // The number of bytes left to copy
    bytes_left: Cell<F>,
    // The src address bound of the buffer
    src_addr_end: Cell<F>,
    // Indicate whether src is from Tx Calldata
    from_tx: Cell<F>,
    // Source from where we read the bytes. This equals the tx ID in case of a root call, or caller
    // ID in case of an internal call
    src_id: Cell<F>,
    // Buffer reader gadget
    buffer_reader: BufferReaderGadget<F, MAX_COPY_BYTES, N_BYTES_MEMORY_ADDRESS>,
    // The comparison gadget between num bytes copied and bytes_left
    finish_gadget: ComparisonGadget<F, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: Field> ExecutionGadget<F> for CopyToMemoryGadget<F> {
    const NAME: &'static str = "COPYTOMEMORY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CopyToMemory;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let src_addr = cb.query_cell();
        let dst_addr = cb.query_cell();
        let bytes_left = cb.query_cell();
        let src_addr_end = cb.query_cell();
        let from_tx = cb.query_bool();
        let src_id = cb.query_cell();
        let buffer_reader = BufferReaderGadget::construct(cb, src_addr.expr(), src_addr_end.expr());
        let from_memory = 1.expr() - from_tx.expr();

        // Copy bytes from src and dst
        for i in 0..MAX_COPY_BYTES {
            let read_flag = buffer_reader.read_flag(i);
            // Read bytes[i] from memory
            cb.condition(from_memory.clone() * read_flag.clone(), |cb| {
                cb.memory_lookup(
                    0.expr(),
                    src_addr.expr() + i.expr(),
                    buffer_reader.byte(i),
                    Some(src_id.expr()),
                )
            });
            // Read bytes[i] from Tx
            cb.condition(from_tx.expr() * read_flag.clone(), |cb| {
                cb.tx_context_lookup(
                    src_id.expr(),
                    TxContextFieldTag::CallData,
                    Some(src_addr.expr() + i.expr()),
                    buffer_reader.byte(i),
                )
            });
            // Write bytes[i] to memory when selectors[i] != 0
            cb.condition(buffer_reader.has_data(i), |cb| {
                cb.memory_lookup(
                    1.expr(),
                    dst_addr.expr() + i.expr(),
                    buffer_reader.byte(i),
                    None,
                )
            });
        }

        let copied_size = buffer_reader.num_bytes();
        let finish_gadget = ComparisonGadget::construct(cb, copied_size.clone(), bytes_left.expr());
        let (lt, finished) = finish_gadget.expr();
        // Constrain lt == 1 or finished == 1
        cb.add_constraint(
            "Constrain num_bytes <= bytes_left",
            (1.expr() - lt) * (1.expr() - finished.clone()),
        );

        // When finished == 0, constraint the CopyToMemory state in next step
        cb.constrain_next_step(
            ExecutionState::CopyToMemory,
            Some(1.expr() - finished),
            |cb| {
                let next_src_addr = cb.query_cell();
                let next_dst_addr = cb.query_cell();
                let next_bytes_left = cb.query_cell();
                let next_src_addr_end = cb.query_cell();
                let next_from_tx = cb.query_cell();
                let next_src_id = cb.query_cell();
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
                    "next_from_tx == from_tx",
                    next_from_tx.expr(),
                    from_tx.expr(),
                );
                cb.require_equal("next_src_id == src_id", next_src_id.expr(), src_id.expr());
            },
        );

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
            ..Default::default()
        };
        cb.require_step_state_transition(step_state_transition);

        Self {
            src_addr,
            dst_addr,
            bytes_left,
            src_addr_end,
            from_tx,
            src_id,
            buffer_reader,
            finish_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let CopyToMemoryAuxData {
            src_addr,
            dst_addr,
            bytes_left,
            src_addr_end,
            from_tx,
        } = match step.aux_data {
            Some(StepAuxiliaryData::CopyToMemory(aux)) => aux,
            _ => unreachable!("could not find CopyToMemory aux_data for COPYTOMEMORY"),
        };

        self.src_addr
            .assign(region, offset, Some(F::from(src_addr)))?;
        self.dst_addr
            .assign(region, offset, Some(F::from(dst_addr)))?;
        self.bytes_left
            .assign(region, offset, Some(F::from(bytes_left)))?;
        self.src_addr_end
            .assign(region, offset, Some(F::from(src_addr_end)))?;
        self.from_tx
            .assign(region, offset, Some(F::from(from_tx as u64)))?;
        let src_id = if call.is_root { tx.id } else { call.caller_id };
        self.src_id
            .assign(region, offset, Some(F::from(src_id as u64)))?;

        // Fill in selectors and bytes
        let mut rw_idx = 0;
        let mut bytes = vec![0u8; MAX_COPY_BYTES];
        let mut selectors = vec![false; MAX_COPY_BYTES];
        for idx in 0..std::cmp::min(bytes_left as usize, MAX_COPY_BYTES) {
            let src_addr = src_addr as usize + idx;
            selectors[idx] = true;
            bytes[idx] = if selectors[idx] && src_addr < src_addr_end as usize {
                if from_tx {
                    tx.call_data[src_addr]
                } else {
                    rw_idx += 1;
                    block.rws[step.rw_indices[rw_idx]].memory_value()
                }
            } else {
                0
            };
            // increase rw_idx for writing back to memory
            rw_idx += 1
        }

        self.buffer_reader
            .assign(region, offset, src_addr, src_addr_end, &bytes, &selectors)?;

        let num_bytes_copied = std::cmp::min(bytes_left, MAX_COPY_BYTES as u64);
        self.finish_gadget.assign(
            region,
            offset,
            F::from(num_bytes_copied),
            F::from(bytes_left),
        )?;

        Ok(())
    }
}
