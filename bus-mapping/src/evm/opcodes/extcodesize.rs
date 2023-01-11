use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::Opcode;
use crate::operation::{AccountField, CallContextField, TxAccessListAccountOp, RW};
use crate::Error;
use eth_types::{GethExecStep, ToAddress, ToWord, Word};

#[derive(Debug, Copy, Clone)]
pub(crate) struct Extcodesize;

impl Opcode for Extcodesize {
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

        // Read transaction ID, rw_counter_end_of_reversion, and is_persistent from call
        // context.
        for (field, value) in [
            (CallContextField::TxId, state.tx_ctx.id().to_word()),
            (
                CallContextField::RwCounterEndOfReversion,
                state.call()?.rw_counter_end_of_reversion.to_word(),
            ),
            (
                CallContextField::IsPersistent,
                state.call()?.is_persistent.to_word(),
            ),
        ] {
            state.call_context_read(&mut exec_step, state.call()?.call_id, field, value);
        }

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

        // Read account code hash and get code length.
        let account = state.sdb.get_account(&address).1;
        let code_size = if !account.is_empty() {
            let code_hash = account.code_hash;
            let code_hash_word = code_hash.to_word();
            state.account_read(
                &mut exec_step,
                address,
                AccountField::CodeHash,
                code_hash_word,
                code_hash_word,
            )?;
            state.code(code_hash)?.len()
        } else {
            state.account_read(
                &mut exec_step,
                address,
                AccountField::NonExisting,
                Word::zero(),
                Word::zero(),
            )?;
            0
        };

        // Write the EXTCODESIZE result to stack.
        debug_assert_eq!(code_size, geth_steps[1].stack.last()?.as_usize());
        state.stack_write(
            &mut exec_step,
            geth_steps[1].stack.nth_last_filled(0),
            code_size.into(),
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod extcodesize_tests {
    use super::*;
    use crate::circuit_input_builder::ExecState;
    use crate::mock::BlockData;
    use crate::operation::{AccountOp, CallContextOp, StackOp};
    use eth_types::evm_types::{OpcodeId, StackAddress};
    use eth_types::geth_types::{Account, GethData};
    use eth_types::{bytecode, Bytecode, Word, U256};
    use ethers_core::utils::keccak256;
    use mock::{TestContext, MOCK_1_ETH, MOCK_ACCOUNTS, MOCK_CODES};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_extcodesize_opcode() {
        let account = Account {
            address: MOCK_ACCOUNTS[4],
            code: MOCK_CODES[4].clone(),
            ..Default::default()
        };

        // Test for empty account.
        test_ok(&Account::default(), false);
        // Test for cold account.
        test_ok(&account, false);
        // Test for warm account.
        test_ok(&account, true);
    }

    fn test_ok(account: &Account, is_warm: bool) {
        let account_exists = !account.is_empty();

        let mut bytecode = Bytecode::default();
        if is_warm {
            bytecode.append(&bytecode! {
                PUSH20(account.address.to_word())
                EXTCODESIZE
                POP
            });
        }
        bytecode.append(&bytecode! {
            PUSH20(account.address.to_word())
            EXTCODESIZE
            STOP
        });

        // Get the execution steps from the external tracer.
        let block: GethData = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(MOCK_ACCOUNTS[0])
                    .balance(*MOCK_1_ETH)
                    .code(bytecode);
                if account_exists {
                    accs[1].address(account.address).code(account.code.clone());
                } else {
                    accs[1].address(MOCK_ACCOUNTS[1]).balance(*MOCK_1_ETH);
                }
                accs[2].address(MOCK_ACCOUNTS[2]).balance(*MOCK_1_ETH);
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
        assert!(builder.sdb.add_account_to_access_list(account.address));

        let tx_id = 1;
        let transaction = &builder.block.txs()[tx_id - 1];
        let call_id = transaction.calls()[0].call_id;

        let indices = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::EXTCODESIZE))
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
                value: account.address.to_word()
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
                address: account.address,
                is_warm: true,
                is_warm_prev: is_warm
            }
        );

        let operation = &container.account[indices[5].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &(if account_exists {
                let code_hash = Word::from(keccak256(account.code.clone()));
                AccountOp {
                    address: account.address,
                    field: AccountField::CodeHash,
                    value: code_hash,
                    value_prev: code_hash,
                }
            } else {
                AccountOp {
                    address: account.address,
                    field: AccountField::NonExisting,
                    value: Word::zero(),
                    value_prev: Word::zero(),
                }
            })
        );

        let operation = &container.stack[indices[6].as_usize()];
        assert_eq!(operation.rw(), RW::WRITE);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: 1023u32.into(),
                value: (if account_exists {
                    account.code.len()
                } else {
                    0
                })
                .into(),
            }
        );
    }
}
