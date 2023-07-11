use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::{CallContextField, StorageOp, TxAccessListAccountStorageOp, RW},
    Error,
};
use eth_types::{GethExecStep, ToWord, Word};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::SLOAD`](crate::evm::OpcodeId::SLOAD)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Sload;

impl Opcode for Sload {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let call_id = state.call()?.call_id;
        let contract_addr = state.call()?.address;

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::TxId,
            Word::from(state.tx_ctx.id()),
        );

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::RwCounterEndOfReversion,
            Word::from(state.call()?.rw_counter_end_of_reversion),
        );

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::IsPersistent,
            Word::from(state.call()?.is_persistent as u8),
        );

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::CalleeAddress,
            contract_addr.to_word(),
        );

        // First stack read
        let key = geth_step.stack.last()?;
        let stack_position = geth_step.stack.last_filled();

        // Manage first stack read at latest stack position
        state.stack_read(&mut exec_step, stack_position, key)?;

        // Storage read
        let value_from_statedb = *state.sdb.get_storage(&contract_addr, &key).1;
        {
            let value_from_step = geth_step.storage.get_or_err(&key)?;
            let value_from_stack = geth_steps[1].stack.last().unwrap();
            if !(value_from_step == value_from_statedb && value_from_step == value_from_stack) {
                panic!(
                    "inconsistent sload: step proof {:?}, local statedb {:?}, result {:?} in contract {:?}, key {:?}",
                    value_from_step,
                    value_from_statedb,
                    value_from_stack,
                    contract_addr,
                    key,
                );
            }
        }
        let value = value_from_statedb;

        let is_warm = state
            .sdb
            .check_account_storage_in_access_list(&(contract_addr, key));

        let (_, committed_value) = state.sdb.get_committed_storage(&contract_addr, &key);
        let committed_value = *committed_value;
        state.push_op(
            &mut exec_step,
            RW::READ,
            StorageOp::new(
                contract_addr,
                key,
                value,
                value,
                state.tx_ctx.id(),
                committed_value,
            ),
        );

        // First stack write
        state.stack_write(&mut exec_step, stack_position, value)?;
        state.push_op(
            &mut exec_step,
            RW::READ,
            TxAccessListAccountStorageOp {
                tx_id: state.tx_ctx.id(),
                address: contract_addr,
                key,
                is_warm,
                is_warm_prev: is_warm,
            },
        );
        state.push_op_reversible(
            &mut exec_step,
            TxAccessListAccountStorageOp {
                tx_id: state.tx_ctx.id(),
                address: contract_addr,
                key,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod sload_tests {
    use super::*;
    use crate::{circuit_input_builder::ExecState, mock::BlockData, operation::StackOp};
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        Word,
    };
    use mock::{
        test_ctx::{helpers::*, TestContext},
        MOCK_ACCOUNTS,
    };
    use pretty_assertions::assert_eq;

    fn test_ok(is_warm: bool) {
        let code = if is_warm {
            bytecode! {
                // Write 0x6f to storage slot 0
                PUSH1(0x6fu64)
                PUSH1(0x00u64)
                SSTORE
                // Load storage slot 0
                PUSH1(0x00u64)
                SLOAD
                STOP
            }
        } else {
            bytecode! {
                // Load storage slot 0
                PUSH1(0x00u64)
                SLOAD
                STOP
            }
        };
        let expected_loaded_value = if is_warm { 0x6fu64 } else { 0 };

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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::SLOAD))
            .unwrap();

        assert_eq!(
            [4, 6]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x0u32))
                ),
                (
                    RW::WRITE,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(expected_loaded_value))
                )
            ]
        );

        let storage_op = &builder.block.container.storage[step.bus_mapping_instance[5].as_usize()];
        assert_eq!(
            (storage_op.rw(), storage_op.op()),
            (
                RW::READ,
                &StorageOp::new(
                    MOCK_ACCOUNTS[0],
                    Word::from(0x0u32),
                    Word::from(expected_loaded_value),
                    Word::from(expected_loaded_value),
                    1,
                    Word::from(0x0u32),
                )
            )
        );

        assert_eq!(
            [7, 8]
                .map(
                    |idx| &builder.block.container.tx_access_list_account_storage
                        [step.bus_mapping_instance[idx].as_usize()]
                )
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &TxAccessListAccountStorageOp {
                        tx_id: 1,
                        address: MOCK_ACCOUNTS[0],
                        key: Word::from(0x0u32),
                        is_warm,
                        is_warm_prev: is_warm,
                    },
                ),
                (
                    RW::WRITE,
                    &TxAccessListAccountStorageOp {
                        tx_id: 1,
                        address: MOCK_ACCOUNTS[0],
                        key: Word::from(0x0u32),
                        is_warm: true,
                        is_warm_prev: is_warm,
                    },
                )
            ]
        )
    }

    #[test]
    fn sload_opcode_impl_warm() {
        test_ok(true)
    }

    #[test]
    fn sload_opcode_impl_cold() {
        test_ok(false)
    }
}
