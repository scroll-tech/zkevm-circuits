use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::{CallContextField, CallContextOp, RW};
use crate::Error;
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::PC`](crate::evm::OpcodeId::PC) `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Caller;

impl Opcode for Caller {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        // Get caller_address result from next step
        let value = geth_steps[1].stack.last()?;
        // CallContext read of the caller_address
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::CallerAddress,
                value,
            },
        );
        // Stack write of the caller_address
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
mod caller_tests {
    use super::*;
    use crate::{evm::opcodes::test_util::TestCase, operation::StackOp};
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        ToWord,
    };

    use pretty_assertions::assert_eq;

    #[test]
    fn caller_opcode_impl() {
        let code = bytecode! {
            CALLER
            STOP
        };
        let test = TestCase::new_from_bytecode(code);

        let step = test.step_witness(OpcodeId::CALLER, 0);

        let call_id = test.tx_witness().calls()[0].call_id;
        let caller_address = test.tx_input().from.to_word();
        assert_eq!(
            {
                let operation = &step.rws.call_context[0];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::CallerAddress,
                    value: caller_address,
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
                &StackOp::new(1, StackAddress::from(1023), caller_address)
            )
        );
    }
}
