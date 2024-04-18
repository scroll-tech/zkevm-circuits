use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::{CallContextField, StorageOp, TxAccessListAccountStorageOp, TxRefundOp},
    Error,
};

use crate::operation::RW;
use eth_types::{evm_types::GasCost, GethExecStep, ToWord, Word};

/// Calculate the refund of a sstore op, base on EIP-3529 (the SSTORE_CLEARS_SCHEDULE
/// has been updated to 4800)
pub fn calc_expected_tx_refund(
    tx_refund_old: u64,
    value: eth_types::Word,
    value_prev: eth_types::Word,
    original_value: eth_types::Word,
) -> u64 {
    // Same clause tags(like "delete slot (2.1.2b)") used as [`makeGasSStoreFunc` in go-ethereum](https://github.com/ethereum/go-ethereum/blob/9fd8825d5a196edde6d8ef81382979875145b346/core/vm/operations_acl.go#L27)
    // Control flow of this function try to follow `makeGasSStoreFunc` for better
    // understanding and comparison.

    let mut tx_refund_new = tx_refund_old;

    // The "clearing slot refund" and "resetting value refund" are ADDED together,
    // they are NOT MUTUALLY EXCLUSIVE.
    // Search "Apply both of the following clauses" in EIP-2200 for more details.
    // There can be five total kinds of refund:
    // 1. -SSTORE_CLEARS_SCHEDULE
    // 2. SSTORE_CLEARS_SCHEDULE
    // 3. SSTORE_SET - WARM_ACCESS
    // 4. SSTORE_RESET - WARM_ACCESS
    // 5. -SSTORE_CLEARS_SCHEDULE + SSTORE_RESET - WARM_ACCESS
    // The last case can happen if (original_value, prev_value, value) be (v,0,v)
    // where v != 0,
    // then both "clearing slot refund" and "resetting value refund" are non zero.

    if value_prev != value {
        // refund related to clearing slot
        // "delete slot (2.1.2b)" can be safely merged in "delete slot (2.2.1.2)"
        if !original_value.is_zero() {
            if value_prev.is_zero() {
                // recreate slot (2.2.1.1)
                tx_refund_new -= GasCost::SSTORE_CLEARS_SCHEDULE.as_u64()
            }
            if value.is_zero() {
                // delete slot (2.2.1.2)
                tx_refund_new += GasCost::SSTORE_CLEARS_SCHEDULE.as_u64()
            }
        }

        // refund related to resetting value
        if original_value == value {
            if original_value.is_zero() {
                // reset to original inexistent slot (2.2.2.1)
                tx_refund_new += GasCost::SSTORE_SET.as_u64() - GasCost::WARM_ACCESS.as_u64();
            } else {
                // reset to original existing slot (2.2.2.2)
                tx_refund_new += GasCost::SSTORE_RESET.as_u64() - GasCost::WARM_ACCESS.as_u64();
            }
        }
    }

    tx_refund_new
}

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::SSTORE`](crate::evm::OpcodeId::SSTORE)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Sstore;

impl Opcode for Sstore {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let contract_addr = state.call()?.address;

        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::TxId,
            Word::from(state.tx_ctx.id()),
        )?;
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::IsStatic,
            Word::from(state.call()?.is_static as u8),
        )?;

        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::RwCounterEndOfReversion,
            Word::from(state.call()?.rw_counter_end_of_reversion),
        )?;

        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::IsPersistent,
            Word::from(state.call()?.is_persistent as u8),
        )?;

        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CalleeAddress,
            state.call()?.address.to_word(),
        )?;

        let key = state.stack_pop(&mut exec_step)?;
        let value = state.stack_pop(&mut exec_step)?;
        #[cfg(feature = "enable-stack")]
        {
            assert_eq!(key, geth_step.stack.nth_last(0)?);
            assert_eq!(value, geth_step.stack.nth_last(1)?);
        }

        let is_warm = state
            .sdb
            .check_account_storage_in_access_list(&(contract_addr, key));

        let (_, value_prev) = state.sdb.get_storage(&contract_addr, &key);
        let value_prev = *value_prev;
        let (_, committed_value) = state.sdb.get_committed_storage(&contract_addr, &key);
        let committed_value = *committed_value;

        state.push_op_reversible(
            &mut exec_step,
            StorageOp::new(
                state.call()?.address,
                key,
                value,
                value_prev,
                state.tx_ctx.id(),
                committed_value,
            ),
        )?;

        state.push_op(
            &mut exec_step,
            RW::READ,
            TxAccessListAccountStorageOp {
                tx_id: state.tx_ctx.id(),
                address: state.call()?.address,
                key,
                is_warm,
                is_warm_prev: is_warm,
            },
        )?;
        state.push_op_reversible(
            &mut exec_step,
            TxAccessListAccountStorageOp {
                tx_id: state.tx_ctx.id(),
                address: state.call()?.address,
                key,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        let refund = exec_step.gas_refund.0;
        let refund_expected =
            calc_expected_tx_refund(state.sdb.refund(), value, value_prev, committed_value);

        #[cfg(not(feature = "fix-refund"))]
        assert_eq!(
            refund, refund_expected,
            "expected refund {refund_expected} is not equal to current {refund}"
        );
        #[cfg(feature = "fix-refund")]
        let refund = if refund != refund_expected {
            exec_step.gas_refund.0 = refund_expected;
            log::debug!(
                "correct sstore refund from {} -> {}, prev {}",
                refund,
                refund_expected,
                state.sdb.refund()
            );
            refund_expected
        } else {
            refund
        };

        state.push_op_reversible(
            &mut exec_step,
            TxRefundOp {
                tx_id: state.tx_ctx.id(),
                value_prev: state.sdb.refund(),
                value: refund,
            },
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod sstore_tests {
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
        Word,
    };
    use mock::{test_ctx::helpers::tx_from_1_to_0, TestContext, MOCK_ACCOUNTS};
    use pretty_assertions::assert_eq;

    fn test_ok(is_warm: bool) {
        let code = if is_warm {
            bytecode! {
                    // Write 0x00 to storage slot 0
                    PUSH1(0x00u64)
                    PUSH1(0x00u64)
                    SSTORE
                // Write 0x6f to storage slot 0
                PUSH1(0x6fu64)
                PUSH1(0x00u64)
                SSTORE
                STOP
            }
        } else {
            bytecode! {
                // Write 0x6f to storage slot 0
                PUSH1(0x6fu64)
                PUSH1(0x00u64)
                SSTORE
                STOP
            }
        };
        let expected_prev_value = if !is_warm { 0x6fu64 } else { 0x00u64 };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(MOCK_ACCOUNTS[0])
                    .balance(Word::from(10u64.pow(19)))
                    .code(code)
                    .storage(vec![(0x00u64.into(), 0x6fu64.into())].into_iter());
                accs[1]
                    .address(MOCK_ACCOUNTS[1])
                    .balance(Word::from(10u64.pow(19)));
            },
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
            .rev() // find last sstore
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::SSTORE))
            .unwrap();

        assert_eq!(
            [0, 1, 2, 3, 4]
                .map(|idx| &builder.block.container.call_context
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &CallContextOp::new(1, CallContextField::TxId, Word::from(0x01)),
                ),
                (
                    RW::READ,
                    &CallContextOp::new(1, CallContextField::IsStatic, Word::from(0x00)),
                ),
                (
                    RW::READ,
                    &CallContextOp::new(
                        1,
                        CallContextField::RwCounterEndOfReversion,
                        Word::from(0x00)
                    ),
                ),
                (
                    RW::READ,
                    &CallContextOp::new(1, CallContextField::IsPersistent, Word::from(0x01)),
                ),
                (
                    RW::READ,
                    &CallContextOp::new(
                        1,
                        CallContextField::CalleeAddress,
                        MOCK_ACCOUNTS[0].to_word(),
                    ),
                ),
            ]
        );

        assert_eq!(
            [5, 6]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1022), Word::from(0x0u32))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x6fu32))
                ),
            ]
        );

        let storage_op = &builder.block.container.storage[step.bus_mapping_instance[7].as_usize()];
        assert_eq!(
            (storage_op.rw(), storage_op.op()),
            (
                RW::WRITE,
                &StorageOp::new(
                    MOCK_ACCOUNTS[0],
                    Word::from(0x0u32),
                    Word::from(0x6fu32),
                    Word::from(expected_prev_value),
                    1,
                    Word::from(0x6fu32),
                )
            )
        );
        let refund_op =
            &builder.block.container.tx_refund[step.bus_mapping_instance[10].as_usize()];
        assert_eq!(
            (refund_op.rw(), refund_op.op()),
            (
                RW::WRITE,
                &TxRefundOp {
                    tx_id: 1,
                    value_prev: if is_warm { 0x12c0 } else { 0 },
                    value: if is_warm { 0xaf0 } else { 0 }
                }
            )
        );
    }

    #[test]
    fn sstore_opcode_impl_warm() {
        test_ok(true)
    }

    #[test]
    fn sstore_opcode_impl_cold() {
        test_ok(false)
    }
}
