use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            from_bytes,
            math_gadget::IsEqualGadget,
            storage_gadget::StorageGasGadget,
            Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct StorageGadget<F> {
    same_context: SameContextGadget<F>,
    address: Word<F>,
    value: Word<F>,
    storage_gas: StorageGasGadget<F>,
    is_sload: IsEqualGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for StorageGadget<F> {
    const NAME: &'static str = "STORAGE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::STORAGE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let address = cb.query_word();
        let value = cb.query_word();

        // Check if this is an SLOAD
        let is_sload =
            IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::SLOAD.expr());
        // This is an SSTORE
        let is_sstore = 1.expr() - is_sload.expr();

        // Calculate the gas cost for this storage access
        let storage_gas = StorageGasGadget::construct();
        let storage_gas_cost = storage_gas.expr();

        /* Stack operations */
        // Pop the address from the stack
        cb.stack_pop(address.expr());

        // For SLOAD push the value to the stack
        // FOR SSTORE pop the value from the stack
        cb.stack_lookup(
            is_sload.expr(),
            cb.stack_pointer_offset().expr() - is_sload.expr(),
            value.expr(),
        );

        /* Storage operations */
        // Read/Write the value from storage at the specified address
        cb.storage_lookup(is_sstore.clone(), address.expr(), value.expr());

        // State transition
        // - `rw_counter` needs to be increased by 3
        // - `program_counter` needs to be increased by 1
        // - `stack_pointer` needs to be increased by 2 when is_sstore,
        //   otherwise to be same
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(is_sstore * 2.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            Some(storage_gas_cost),
        );

        Self {
            same_context,
            address,
            value,
            storage_gas,
            is_sload,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();

        // Inputs/Outputs
        // consistent with bus_mapping
        // TODO: fix for SSTORE
        let [address, value] = [step.rw_indices[0], step.rw_indices[2]]
            .map(|idx| block.rws[idx].stack_value());
        self.address
            .assign(region, offset, Some(address.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        // Check if this is an SLOAD
        self.is_sload.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::SLOAD.as_u64()),
        )?;

        self.storage_gas
            .assign(self.is_sload.expr(), address, value)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        witness,
    };
    use bus_mapping::{
        bytecode,
        eth_types::Word,
        evm::{Gas, GasCost, OpcodeId},
    };
    use std::iter;

    fn test_ok(opcode: OpcodeId, address: Word, value: Word) {
        let bytecode = bytecode! {
            PUSH32(value)
            PUSH32(address)
            #[start]
            .write_op(opcode)
            STOP
        };

        let gas = Gas(100_000);
        let mut block_trace =
            bus_mapping::mock::BlockData::new_single_tx_trace_code_gas(
                &bytecode, gas,
            )
            .unwrap();
        block_trace.geth_trace.struct_logs = block_trace.geth_trace.struct_logs
            [bytecode.get_pos("start")..]
            .to_vec();
        let mut builder = block_trace.new_circuit_input_builder();
        builder
            .handle_tx(&block_trace.eth_tx, &block_trace.geth_trace)
            .unwrap();
        let block = witness::block_convert(&bytecode, &builder.block);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn storage_gadget_simple() {
        // test_ok(
        //     OpcodeId::MSTORE,
        //     Word::from(0x12FFFF),
        //     Word::from_big_endian(&(1..33).collect::<Vec<_>>()),
        //     38913,
        //     3074206,
        // );

        test_ok(
            OpcodeId::SLOAD,
            Word::from(0x12FFFF),
            Word::from_big_endian(&(1..33).collect::<Vec<_>>()),
        );

        test_ok(
            OpcodeId::SLOAD,
            Word::from(0x12FFFF) + 16,
            Word::from_big_endian(
                &(17..33).chain(iter::repeat(0).take(16)).collect::<Vec<_>>(),
            ),
        );

        // test_ok(
        //     OpcodeId::MSTORE8,
        //     Word::from(0x12FFFF),
        //     Word::from_big_endian(&(1..33).collect::<Vec<_>>()),
        //     38912,
        //     3074051,
        // );
    }
}
