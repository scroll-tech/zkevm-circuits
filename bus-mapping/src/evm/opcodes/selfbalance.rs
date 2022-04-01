use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::{AccountField, AccountOp, CallContextField, CallContextOp, RW};
use crate::Error;
use eth_types::{GethExecStep, ToWord};

#[derive(Debug, Copy, Clone)]
pub(crate) struct Selfbalance;

impl Opcode for Selfbalance {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        let self_balance = geth_steps[1].stack.last()?;
        let callee_address = state.call()?.address;

        // CallContext read of the callee_address
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::CalleeAddress,
                value: callee_address.to_word(),
            },
        );

        // Account read for the balance of the callee_address
        state.push_op(
            &mut exec_step,
            RW::READ,
            AccountOp {
                address: callee_address,
                field: AccountField::Balance,
                value: self_balance,
                value_prev: self_balance,
            },
        );

        // Stack write of self_balance
        state.push_stack_op(
            &mut exec_step,
            RW::WRITE,
            geth_step.stack.last_filled().map(|a| a - 1),
            self_balance,
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod selfbalance_tests {
    use super::*;
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
    fn selfbalance_opcode_impl() {
        let code = bytecode! {
            SELFBALANCE
            STOP
        };
        let test = TestCase::new_from_bytecode(code);
        let step = test.step_witness(OpcodeId::SELFBALANCE, 0);

        let call_id = test.tx_witness().calls()[0].call_id;
        let callee_address = test.tx_witness().to;
        let self_balance = test.state_db().get_account(&callee_address).1.balance;

        assert_eq!(
            {
                let operation = &step.rws.call_context[0];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::CalleeAddress,
                    value: callee_address.to_word(),
                }
            )
        );
        assert_eq!(
            {
                let operation = &step.rws.account[0];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &AccountOp {
                    address: callee_address,
                    field: AccountField::Balance,
                    value: self_balance,
                    value_prev: self_balance,
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
                &StackOp::new(1, StackAddress::from(1023), self_balance)
            )
        );
    }
}
