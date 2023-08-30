use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::CallContextField,
    Error,
};
use eth_types::GethExecStep;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Address;

impl Opcode for Address {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        // Get address result from next step.
        let address = geth_steps[1].stack.last()?;

        // Read the callee address in call context.
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CalleeAddress,
            address,
        )?;

        // Write the address to stack.
        state.stack_write(
            &mut exec_step,
            geth_step.stack.last_filled().map(|a| a - 1),
            address,
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod address_tests {
    use super::*;
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{CallContextOp, StackOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        ToWord,
    };
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn address_opcode_impl() {
        let code = bytecode! {
            ADDRESS
            STOP
        };

        // Get the execution steps from the external tracer.
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafe_u64),
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::ADDRESS))
            .unwrap();

        let call_id = builder.block.txs()[0].calls()[0].call_id;
        let address = block.eth_block.transactions[0].to.unwrap().to_word();
        assert_eq!(
            {
                let operation =
                    &builder.block.container.call_context[step.bus_mapping_instance[0].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::CalleeAddress,
                    value: address,
                }
            )
        );
        assert_eq!(
            {
                let operation =
                    &builder.block.container.stack[step.bus_mapping_instance[1].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::WRITE,
                &StackOp::new(1, StackAddress::from(1023), address)
            )
        );
    }
}
