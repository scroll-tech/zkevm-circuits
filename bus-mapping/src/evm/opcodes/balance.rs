use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::Opcode;
use crate::operation::{AccountField, CallContextField, TxAccessListAccountOp, RW};
use crate::Error;
use eth_types::{GethExecStep, ToAddress, ToWord, H256, U256};

#[derive(Debug, Copy, Clone)]
pub(crate) struct Balance;

impl Opcode for Balance {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        // Read account address from stack.
        let address_word = geth_step.stack.last()?;
        let address = address_word.to_address();
        state.stack_read(&mut exec_step, geth_step.stack.last_filled(), address_word)?;

        // Read transaction ID, rw_counter_end_of_reversion, and is_persistent
        // from call context.
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::TxId,
            U256::from(state.tx_ctx.id()),
        );
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::RwCounterEndOfReversion,
            U256::from(state.call()?.rw_counter_end_of_reversion as u64),
        );
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::IsPersistent,
            U256::from(state.call()?.is_persistent as u64),
        );

        // Update transaction access list for account address.
        let is_warm = state.sdb.check_account_in_access_list(&address);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        // Read account balance.
        let account = state.sdb.get_account(&address).1;
        let exists = !account.is_empty();
        let balance = account.balance;
        let code_hash = if exists {
            account.code_hash
        } else {
            H256::zero()
        };
        state.account_read(
            &mut exec_step,
            address,
            AccountField::CodeHash,
            code_hash.to_word(),
            code_hash.to_word(),
        );
        if exists {
            state.account_read(
                &mut exec_step,
                address,
                AccountField::Balance,
                balance,
                balance,
            );
        }

        // Write the BALANCE result to stack.
        state.stack_write(
            &mut exec_step,
            geth_steps[1].stack.nth_last_filled(0),
            geth_steps[1].stack.nth_last(0)?,
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod balance_tests {
    use super::*;
    use crate::circuit_input_builder::ExecState;
    use crate::mock::BlockData;
    use crate::operation::{AccountOp, CallContextOp, StackOp};
    use eth_types::evm_types::{OpcodeId, StackAddress};
    use eth_types::geth_types::GethData;
    use eth_types::{address, bytecode, Bytecode, ToWord, Word, U256};
    use keccak256::EMPTY_HASH_LE;
    use mock::TestContext;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_balance_of_non_existing_address() {
        test_ok(false, false);
    }

    #[test]
    fn test_balance_of_cold_address() {
        test_ok(true, false);
    }

    #[test]
    fn test_balance_of_warm_address() {
        test_ok(true, true);
    }

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
                txs[0].to(accs[0].address).from(accs[2].address);
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

        let indices = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::BALANCE))
            .last()
            .unwrap()
            .bus_mapping_instance
            .clone();

        let container = builder.block.container;

        let operation = &container.stack[indices[0].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: StackAddress::from(1023u32),
                value: address.to_word()
            }
        );

        let operation = &container.call_context[indices[1].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &CallContextOp {
                call_id,
                field: CallContextField::TxId,
                value: tx_id.into()
            }
        );

        let operation = &container.call_context[indices[2].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &CallContextOp {
                call_id,
                field: CallContextField::RwCounterEndOfReversion,
                value: U256::zero()
            }
        );

        let operation = &container.call_context[indices[3].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &CallContextOp {
                call_id,
                field: CallContextField::IsPersistent,
                value: U256::one()
            }
        );

        let operation = &container.tx_access_list_account[indices[4].as_usize()];
        assert_eq!(operation.rw(), RW::WRITE);
        assert_eq!(
            operation.op(),
            &TxAccessListAccountOp {
                tx_id,
                address,
                is_warm: true,
                is_warm_prev: is_warm
            }
        );

        let code_hash = Word::from_little_endian(&*EMPTY_HASH_LE);
        let operation = &container.account[indices[5].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &AccountOp {
                address,
                field: AccountField::CodeHash,
                value: if exists { code_hash } else { U256::zero() },
                value_prev: if exists { code_hash } else { U256::zero() },
            }
        );
        if exists {
            let operation = &container.account[indices[6].as_usize()];
            assert_eq!(operation.rw(), RW::READ);
            assert_eq!(
                operation.op(),
                &AccountOp {
                    address,
                    field: AccountField::Balance,
                    value: balance,
                    value_prev: balance,
                }
            );
        }

        let operation = &container.stack[indices[6 + if exists { 1 } else { 0 }].as_usize()];
        assert_eq!(operation.rw(), RW::WRITE);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: 1023u32.into(),
                value: balance,
            }
        );
    }
}
