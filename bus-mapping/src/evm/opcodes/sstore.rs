use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::{CallContextField, CallContextOp, TxRefundOp};
use crate::{
    operation::{StorageOp, TxAccessListAccountStorageOp, RW},
    Error,
};

use eth_types::{GethExecStep, ToWord, Word};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::SSTORE`](crate::evm::OpcodeId::SSTORE)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Sstore;

impl Opcode for Sstore {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let step = &steps[0];
        let _next_step = &steps[1];
        let mut exec_step = state.new_step(step)?;

        let _call_id = state.call()?.call_id;
        let contract_addr = state.call()?.address;

        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::TxId,
                value: Word::from(state.tx_ctx.id()),
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::RwCounterEndOfReversion,
                value: Word::from(state.call()?.rw_counter_end_of_reversion),
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::IsPersistent,
                value: Word::from(state.call()?.is_persistent as u8),
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::CalleeAddress,
                value: state.call()?.address.to_word(),
            },
        );

        let key = step.stack.nth_last(0)?;
        let key_stack_position = step.stack.nth_last_filled(0);
        let value = step.stack.nth_last(1)?;
        let value_stack_position = step.stack.nth_last_filled(1);

        state.push_stack_op(&mut exec_step, RW::READ, key_stack_position, key)?;
        state.push_stack_op(&mut exec_step, RW::READ, value_stack_position, value)?;

        let warm = state
            .sdb
            .check_account_storage_in_access_list(&(contract_addr, key));

        let (_, value_prev) = state.sdb.get_storage(&contract_addr, &key);
        let value_prev = *value_prev;
        let (_, committed_value) = state.sdb.get_committed_storage(&contract_addr, &key);
        let committed_value = *committed_value;

        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            StorageOp::new(
                state.call()?.address,
                key,
                value,
                value_prev,
                state.tx_ctx.id(),
                committed_value,
            ),
        )?;

        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountStorageOp {
                tx_id: state.tx_ctx.id(),
                address: state.call()?.address,
                key,
                value: true,
                value_prev: warm,
            },
        )?;

        let last_step_refund = state.tx.steps().last().unwrap().gas_refund;
        let cur_step_refund = step.refund;
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxRefundOp {
                tx_id: state.tx_ctx.id(),
                value_prev: last_step_refund.0,
                value: cur_step_refund.0,
            },
        )?;

        exec_step.gas_refund = cur_step_refund;
        Ok(vec![exec_step])
    }
}

/*
#[cfg(test)]
mod sload_tests {
    use super::*;
    use crate::operation::StackOp;
    use eth_types::bytecode;
    use eth_types::evm_types::{OpcodeId, StackAddress};
    use eth_types::{Address, Word};
    use pretty_assertions::assert_eq;

    #[test]
    fn sload_opcode_impl() {
        let code = bytecode! {
            // Write 0x6f to storage slot 0
            PUSH1(0x6fu64)
            PUSH1(0x00u64)
            SSTORE

            // Load storage slot 0
            PUSH1(0x00u64)
            SLOAD
            STOP
        };

        // Get the execution steps from the external tracer
        let block = crate::mock::BlockData::new_from_geth_data(
            mock::new_single_tx_trace_code(&code).unwrap(),
        );

        let mut builder = block.new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.op == OpcodeId::SLOAD)
            .unwrap();

        assert_eq!(
            [0, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x0u32))
                ),
                (
                    RW::WRITE,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x6fu32))
                )
            ]
        );

        let storage_op = &builder.block.container.storage[step.bus_mapping_instance[1].as_usize()];
        assert_eq!(
            (storage_op.rw(), storage_op.op()),
            (
                RW::READ,
                &StorageOp::new(
                    Address::from([0u8; 20]),
                    Word::from(0x0u32),
                    Word::from(0x6fu32),
                    Word::from(0x6fu32),
                    1,
                    Word::from(0x6fu32),
                )
            )
        )
    }
}

*/
