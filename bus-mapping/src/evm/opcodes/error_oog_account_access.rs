use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    error::{ExecError, OogError},
    evm::{Opcode, OpcodeId},
    operation::{CallContextField, TxAccessListAccountOp, RW},
    Error,
};
use eth_types::{GethExecStep, ToAddress, U256};

#[derive(Debug, Copy, Clone)]
pub struct ErrorOOGAccountAccess;

impl Opcode for ErrorOOGAccountAccess {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::OutOfGas(OogError::AccountAccess));

        // assert op code is BALANCE | EXTCODESIZE | EXTCODEHASH
        assert!([
            OpcodeId::BALANCE,
            OpcodeId::EXTCODESIZE,
            OpcodeId::EXTCODEHASH
        ]
        .contains(&geth_step.op));
        // Read account address from stack.
        let address_word = geth_step.stack.last()?;
        let address = address_word.to_address();
        state.stack_read(&mut exec_step, geth_step.stack.last_filled(), address_word)?;

        // Read transaction ID from call context.
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::TxId,
            U256::from(state.tx_ctx.id()),
        )?;

        // transaction access list for account address.
        let is_warm = state.sdb.check_account_in_access_list(&address);
        // read `is_warm` state
        state.push_op(
            &mut exec_step,
            RW::READ,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address,
                is_warm,
                is_warm_prev: is_warm,
            },
        )?;

        // common error handling
        state.handle_return(&mut [&mut exec_step], geth_steps, true)?;
        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod oog_account_access_tests {
    use crate::{
        circuit_input_builder::ExecState,
        error::{ExecError, OogError},
        mock::BlockData,
        operation::{StackOp, RW},
    };
    use eth_types::{
        address, bytecode, evm_types::OpcodeId, geth_types::GethData, Bytecode, ToWord, Word,
    };
    use mock::TestContext;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_balance_of_warm_address() {
        test_ok(true, false);
        test_ok(false, false);
        test_ok(true, true);
    }

    // test balance opcode as an example
    fn test_ok(exists: bool, is_warm: bool) {
        let address = address!("0xaabbccddee000000000000000000000000000000");

        // Pop balance first for warm account.
        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                PUSH20(address.to_word())
                BALANCE
                POP
            });
        }
        code.append(&bytecode! {
            PUSH20(address.to_word())
            BALANCE
            STOP
        });

        let balance = if exists {
            Word::from(800u64)
        } else {
            Word::zero()
        };

        // Get the execution steps from the external tracer.
        let block: GethData = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20))
                    .code(code.clone());
                if exists {
                    accs[1].address(address).balance(balance);
                } else {
                    accs[1]
                        .address(address!("0x0000000000000000000000000000000000000020"))
                        .balance(Word::from(1u64 << 20));
                }
                accs[2]
                    .address(address!("0x0000000000000000000000000000000000cafe01"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0]
                    .to(accs[0].address)
                    .from(accs[2].address)
                    .gas(21005.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        // Check if account address is in access list as a result of bus mapping.
        assert!(builder.sdb.add_account_to_access_list(address));

        let tx_id = 1;
        let transaction = &builder.block.txs()[tx_id - 1];
        let call_id = transaction.calls()[0].call_id;

        let step = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::BALANCE))
            .last()
            .unwrap();

        // check expected error occurs
        assert_eq!(
            step.error,
            Some(ExecError::OutOfGas(OogError::AccountAccess))
        );

        let container = builder.block.container.clone();
        let operation = &container.stack[step.bus_mapping_instance[0].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: 1023.into(),
                value: address.to_word(),
            }
        );
    }
}
