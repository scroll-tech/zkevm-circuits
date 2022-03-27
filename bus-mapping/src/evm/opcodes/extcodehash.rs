use super::Opcode;
use crate::{
    circuit_input_builder::CircuitInputStateRef,
    evm::opcodes::ExecStep,
    operation::{
        AccountField, AccountOp, CallContextField, CallContextOp, TxAccessListAccountOp, RW,
    },
    state_db::Account,
    Error,
};
use eth_types::{evm_types::GasCost, GethExecStep, ToAddress, ToWord, U256};

#[derive(Debug, Copy, Clone)]
pub(crate) struct Extcodehash;

impl Opcode for Extcodehash {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let step = &steps[0];
        let mut exec_step = state.new_step(step)?;
        let stack_address = step.stack.last_filled();

        // Pop external address off stack
        let external_address = step.stack.last()?.to_address();
        state.push_stack_op(
            &mut exec_step,
            RW::READ,
            stack_address,
            external_address.to_word(),
        )?;

        // Read transaction id, rw_counter_end_of_reversion, and is_persistent from call
        // context
        let call = state.call()?;
        let call_id = call.call_id;
        for (field, value) in [
            (CallContextField::TxId, U256::from(state.tx_ctx.id())),
            (
                CallContextField::RwCounterEndOfReversion,
                U256::from(call.rw_counter_end_of_reversion as u64),
            ),
            (
                CallContextField::IsPersistent,
                U256::from(call.is_persistent as u64),
            ),
        ] {
            state.push_op(
                &mut exec_step,
                RW::READ,
                CallContextOp {
                    call_id,
                    field,
                    value,
                },
            );
        }

        // Update transaction access list for external_address
        let is_warm = match step.gas_cost {
            GasCost::WARM_STORAGE_READ_COST => true,
            GasCost::COLD_ACCOUNT_ACCESS_COST => false,
            _ => unreachable!(),
        };
        state.sdb.add_account_to_access_list(external_address);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address: external_address,
                value: true,
                value_prev: is_warm,
            },
        )?;

        // These three lookups are required to determine the existence of the external
        // account
        let &Account {
            nonce,
            code_hash,
            balance,
            ..
        } = state.sdb.get_account(&external_address).1;
        state.push_op(
            &mut exec_step,
            RW::READ,
            AccountOp {
                address: external_address,
                field: AccountField::Nonce,
                value: nonce,
                value_prev: nonce,
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            AccountOp {
                address: external_address,
                field: AccountField::Balance,
                value: balance,
                value_prev: balance,
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            AccountOp {
                address: external_address,
                field: AccountField::CodeHash,
                value: code_hash.to_word(),
                value_prev: code_hash.to_word(),
            },
        );

        // Stack write of the result of EXTCODEHASH.
        state.push_stack_op(
            &mut exec_step,
            RW::WRITE,
            stack_address,
            steps[1].stack.last()?,
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod extcodehash_tests {
    use super::*;
    use crate::circuit_input_builder::ExecState;
    use crate::mock::BlockData;
    use crate::operation::StackOp;
    use eth_types::{
        address, bytecode, evm_types::OpcodeId, geth_types::Account as GethAccount, Address,
        Bytecode, Bytes, U256,
    };
    use ethers_core::utils::keccak256;
    use mock::new_single_tx_trace_accounts;
    use pretty_assertions::assert_eq;

    #[test]
    fn cold_empty_account() -> Result<(), Error> {
        test_ok(false, false)
    }

    #[test]
    fn warm_empty_account() -> Result<(), Error> {
        test_ok(false, true)
    }

    #[test]
    fn cold_existing_account() -> Result<(), Error> {
        test_ok(true, false)
    }

    #[test]
    fn warm_existing_account() -> Result<(), Error> {
        test_ok(true, true)
    }

    fn test_ok(exists: bool, is_warm: bool) -> Result<(), Error> {
        // In each test case, this is the external address we will call EXTCODEHASH on.
        let external_address = address!("0xaabbccddee000000000000000000000000000000");

        // Make the external account warm, if needed, by first getting its balance.
        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                PUSH20(external_address.to_word())
                BALANCE
                POP
            });
        }
        code.append(&bytecode! {
            PUSH20(external_address.to_word())
            EXTCODEHASH
            STOP
        });

        let mut accounts = vec![GethAccount {
            address: Address::default(), // This is the address of the executing account
            code: Bytes::from(code.to_vec()),
            ..Default::default()
        }];

        // Let the external account exist, if needed, by making its code non-empty
        let (mut nonce, mut balance, mut code) = (U256::zero(), U256::zero(), Bytes::default());
        if exists {
            nonce = U256::from(300u64);
            balance = U256::from(800u64);
            code = Bytes::from([34, 54, 56]);

            accounts.push(GethAccount {
                address: external_address,
                nonce,
                balance,
                code: code.clone(),
                ..Default::default()
            })
        }
        let code_hash = keccak256(&code).into();

        // Get the execution steps from the external tracer
        let geth_data = new_single_tx_trace_accounts(accounts)?;
        let block = BlockData::new_from_geth_data(geth_data);

        let mut builder = block.new_circuit_input_builder();
        builder.handle_block(&block.eth_block, &block.geth_traces)?;

        // Check that `external_address` is in access list as a result of bus mapping.
        assert!(builder.sdb.add_account_to_access_list(external_address));

        let tx_id = 1;
        let transaction = &builder.block.txs()[tx_id - 1];
        let call_id = transaction.calls()[0].call_id;

        let indices = transaction
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::EXTCODEHASH))
            .unwrap()
            .bus_mapping_instance
            .clone();
        let container = builder.block.container;
        assert_eq!(
            {
                let operation = &container.stack[indices[0].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &StackOp {
                    call_id,
                    address: 1023.into(),
                    value: external_address.to_word()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.call_context[indices[1].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::TxId,
                    value: tx_id.into()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.call_context[indices[2].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::RwCounterEndOfReversion,
                    value: U256::zero()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.call_context[indices[3].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::IsPersistent,
                    value: U256::one()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.tx_access_list_account[indices[4].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::WRITE,
                &TxAccessListAccountOp {
                    tx_id,
                    address: external_address,
                    value: true,
                    value_prev: is_warm
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.account[indices[5].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &AccountOp {
                    address: external_address,
                    field: AccountField::Nonce,
                    value: if exists { nonce } else { U256::zero() },
                    value_prev: if exists { nonce } else { U256::zero() },
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.account[indices[6].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &AccountOp {
                    address: external_address,
                    field: AccountField::Balance,
                    value: if exists { balance } else { U256::zero() },
                    value_prev: if exists { balance } else { U256::zero() },
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.account[indices[7].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &AccountOp {
                    address: external_address,
                    field: AccountField::CodeHash,
                    value: code_hash,
                    value_prev: code_hash,
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.stack[indices[8].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::WRITE,
                &StackOp {
                    call_id,
                    address: 1023.into(),
                    value: if exists { code_hash } else { U256::zero() }
                }
            )
        );

        Ok(())
    }
}
