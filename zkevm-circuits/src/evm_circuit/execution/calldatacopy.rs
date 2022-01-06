use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::MAX_GAS_SIZE_IN_BYTES,
        step::ExecutionState,
        table::{CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            memory_gadget::MemoryExpansionGadget,
            from_bytes, Cell, MemoryAddress, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::convert::TryInto;

const MAX_COPY_BYTES: usize = 32;

#[derive(Clone, Debug)]
pub(crate) struct CallDataCopyGadget<F> {
    same_context: SameContextGadget<F>,
    memory_offset: MemoryAddress<F>,
    data_offset: MemoryAddress<F>,
    length: RandomLinearCombination<F, 4>,
    tx_id: Cell<F>,
    calldata_length: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, MAX_GAS_SIZE_IN_BYTES>,
}


impl<F: FieldExt> ExecutionGadget<F> for CallDataCopyGadget<F> {
    const NAME: &'static str = "CALLDATACOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATACOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let bytes_memory_offset = MemoryAddress::new(cb.query_bytes(), cb.randomness());
        let bytes_data_offset = MemoryAddress::new(cb.query_bytes(), cb.randomness());
        let bytes_length = RandomLinearCombination::new(cb.query_bytes(), cb.randomness());
        let memory_offset = from_bytes::expr(&bytes_memory_offset.cells);
        let data_offset = from_bytes::expr(&bytes_data_offset.cells);
        let length = from_bytes::expr(&bytes_length.cells);

        let tx_id = cb.query_cell();
        cb.call_context_lookup(0.expr(), None, CallContextFieldTag::TxId, tx_id.expr());

        let calldata_length = cb.query_cell();
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            cb.tx_lookup(
                tx_id.expr(),
                TxContextFieldTag::CallDataLength,
                None,
                calldata_length.expr())
        });
        cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            cb.call_context_lookup(
                0.expr(),
                None,
                CallContextFieldTag::CallDataLength,
                calldata_length.expr())
        });

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_size.expr(),
            memory_offset.clone() + length.clone(),
        );

        // Pop memory_offset, data_offset, length from stack
        cb.stack_pop(bytes_memory_offset.expr());
        cb.stack_pop(bytes_data_offset.expr());
        cb.stack_pop(bytes_length.expr());

        // Transition to internal state CopyToMemory
        let next_src_addr = cb.query_cell_next_step();
        let next_dst_addr = cb.query_cell_next_step();
        let next_bytes_left = cb.query_cell_next_step();
        let next_src_addr_end = cb.query_cell_next_step();
        let next_from_tx = cb.query_cell_next_step();
        let next_tx_id = cb.query_cell_next_step();
        cb.require_next_state(ExecutionState::CopyToMemory);
        cb.add_constraint(
            "next_src_addr = data_offset",
            next_src_addr.expr() - data_offset.clone(),
        );
        cb.add_constraint(
            "next_dst_addr = memory_offset",
            next_dst_addr.expr() - memory_offset,
        );
        cb.add_constraint(
            "next_bytes_left = length",
            next_bytes_left.expr() - length,
        );
        cb.add_constraint(
            "next_src_addr_end = data_offset + calldata_length",
            next_src_addr_end.expr() - data_offset - calldata_length.expr(),
        );
        cb.add_constraint(
            "next_from_tx = is_root",
            next_from_tx.expr() - cb.curr.state.is_root.expr(),
        );
        cb.add_constraint(
            "next_tx_id = tx_id",
            next_tx_id.expr() - tx_id.expr(),
        );

        // State transition
        let step_state_transition = StepStateTransition {
            // We keep the program_counter same because Calldatacopy hasn't
            // finished the copy yet
            rw_counter: Delta(3.expr()), // 3 stack pop
            //program_counter: Delta(1.expr()),
            stack_pointer: Delta(3.expr()),
            memory_size: To(memory_expansion.next_memory_size()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            Some(memory_expansion.gas_cost()),
        );

        Self {
            same_context,
            memory_offset: bytes_memory_offset,
            data_offset: bytes_data_offset,
            length: bytes_length,
            tx_id,
            calldata_length,
            memory_expansion,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [memory_offset, data_offset, length] =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
            .map(|idx| block.rws[idx].stack_value());
        self.memory_offset.assign(
            region,
            offset,
            Some(memory_offset.to_le_bytes()[..5].try_into().unwrap()),
        )?;
        self.data_offset.assign(
            region,
            offset,
            Some(data_offset.to_le_bytes()[..5].try_into().unwrap()),
        )?;
        self.length.assign(
            region,
            offset,
            Some(length.to_le_bytes()[..4].try_into().unwrap()),
        )?;
        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;
        self.calldata_length.assign(
            region,
            offset,
            Some(F::from(tx.call_data_length as u64)),
        )?;

        // Memory expansion
        self.memory_expansion.assign(
            region,
            offset,
            step.memory_size,
            memory_offset.as_u64() + length.as_u64(),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        step::ExecutionState,
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
        witness::{
            Block, Bytecode, Call, ExecStep, Rw, Transaction,
        },
    };
    use bus_mapping::{
        bytecode,
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr as Fp;

    fn test_ok(
        memory_offset: Word,
        data_offset: Word,
        length: Word,
    ) {
        let bytecode = bytecode! {
            #[start]
            .calldatacopy(memory_offset, data_offset, length)
            STOP
        };
    }

    #[test]
    fn add_gadget_simple() {

    }
}
