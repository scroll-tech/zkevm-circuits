use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::{CallContextField, CallContextOp, RW},
    Error,
};

use eth_types::GethExecStep;

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Calldatasize;

impl Opcode for Calldatasize {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        let value = geth_steps[1].stack.last()?;
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::CallDataLength,
                value,
            },
        );
        state.push_stack_op(
            &mut exec_step,
            RW::WRITE,
            geth_step.stack.last_filled().map(|a| a - 1),
            value,
        )?;
        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod calldatasize_tests {
    use crate::{
        evm::opcodes::test_util::TestCase,
        operation::{CallContextField, CallContextOp, StackOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
    };

    use pretty_assertions::assert_eq;

    #[test]
    fn calldatasize_opcode_impl() {
        let code = bytecode! {
            CALLDATASIZE
            STOP
        };

        let test = TestCase::new_from_bytecode(code);
        let step = test.step_witness(OpcodeId::CALLDATASIZE, 0);
        let call_id = test.tx_witness().calls()[0].call_id;
        let call_data_size = test.tx_input().input.as_ref().len().into();
        assert_eq!(
            {
                let operation = &step.rws.call_context[0];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::CallDataLength,
                    value: call_data_size,
                }
            )
        );
        assert_eq!(
            {
                let operation = &step.rws.stack[0];
                (operation.rw(), operation.op())
            },
            (
                RW::WRITE,
                &StackOp::new(1, StackAddress::from(1023), call_data_size)
            )
        );
    }
}
