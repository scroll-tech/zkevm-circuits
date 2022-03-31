use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::{
    operation::{StorageOp, RW},
    Error,
};
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::SLOAD`](crate::evm::OpcodeId::SLOAD)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Sload;

impl Opcode for Sload {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        // First stack read
        let stack_value_read = geth_step.stack.last()?;
        let stack_position = geth_step.stack.last_filled();

        // Manage first stack read at latest stack position
        state.push_stack_op(&mut exec_step, RW::READ, stack_position, stack_value_read)?;

        // Storage read
        let storage_value_read = geth_step.storage.get_or_err(&stack_value_read)?;
        state.push_op(
            &mut exec_step,
            RW::READ,
            StorageOp::new(
                state.call()?.address,
                stack_value_read,
                storage_value_read,
                storage_value_read,
                state.tx_ctx.id(),
                storage_value_read, // TODO: committed_value
            ),
        );

        // First stack write
        state.push_stack_op(
            &mut exec_step,
            RW::WRITE,
            stack_position,
            storage_value_read,
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod sload_tests {
    use super::*;
    use crate::{circuit_input_builder::ExecState, mock::BlockData, operation::StackOp};
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        Word,
    };
    use mock::{
        test_ctx::{helpers::*, TestContext},
        MOCK_ACCOUNTS,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn sload_opcode_impl() {
        let code = bytecode! {
            // Write 0x6f to storage slot 0
            PUSH1(0x6fu64)
            PUSH1(0x00u64)
            SSTORE

            // Load storage slot 0
            PUSH1(0x00u64)
            SLOAD
            STOP
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::SLOAD))
            .unwrap();

        assert_eq!(
            [0, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x0u32))
                ),
                (
                    RW::WRITE,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x6fu32))
                )
            ]
        );

        let storage_op = &builder.block.container.storage[step.bus_mapping_instance[1].as_usize()];
        assert_eq!(
            (storage_op.rw(), storage_op.op()),
            (
                RW::READ,
                &StorageOp::new(
                    MOCK_ACCOUNTS[0],
                    Word::from(0x0u32),
                    Word::from(0x6fu32),
                    Word::from(0x6fu32),
                    1,
                    Word::from(0x6fu32),
                )
            )
        )
    }
}
