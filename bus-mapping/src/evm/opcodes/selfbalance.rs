use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::{AccountField, CallContextField},
    Error,
};
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
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CalleeAddress,
            callee_address.to_word(),
        );

        // Account read for the balance of the callee_address
        state.account_read(
            &mut exec_step,
            callee_address,
            AccountField::Balance,
            self_balance,
        );

        // Stack write of self_balance
        state.stack_write(
            &mut exec_step,
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
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{AccountOp, CallContextField, CallContextOp, StackOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
    };
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn selfbalance_opcode_impl() {
        let code = bytecode! {
            SELFBALANCE
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::SELFBALANCE))
            .unwrap();

        let call_id = builder.block.txs()[0].calls()[0].call_id;
        let callee_address = builder.block.txs()[0].to.unwrap();
        let self_balance = builder.sdb.get_account(&callee_address).1.balance;

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
                    value: callee_address.to_word(),
                }
            )
        );
        assert_eq!(
            {
                let operation =
                    &builder.block.container.account[step.bus_mapping_instance[1].as_usize()];
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
                let operation =
                    &builder.block.container.stack[step.bus_mapping_instance[2].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::WRITE,
                &StackOp::new(1, StackAddress::from(1023), self_balance)
            )
        );
    }
}
