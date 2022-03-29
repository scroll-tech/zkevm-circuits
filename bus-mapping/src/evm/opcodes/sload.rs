use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::{CallContextField, CallContextOp};
use crate::{
    operation::{StorageOp, TxAccessListAccountStorageOp, RW},
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
        let cur_step = &geth_steps[0];
        let _next_step = &geth_steps[1];
        let mut exec_step = state.new_step(cur_step)?;

        let call_id = state.call()?.call_id;
        let contract_addr = state.call()?.address;

        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id,
                field: CallContextField::TxId,
                value: Word::from(state.tx_ctx.id()),
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id,
                field: CallContextField::RwCounterEndOfReversion,
                value: Word::from(state.call()?.rw_counter_end_of_reversion),
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id,
                field: CallContextField::IsPersistent,
                value: Word::from(state.call()?.is_persistent as u8),
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id,
                field: CallContextField::CalleeAddress,
                value: contract_addr.to_word(),
            },
        );

        // First stack read
        let key = cur_step.stack.last()?;
        let stack_position = cur_step.stack.last_filled();

        // Manage first stack read at latest stack position
        state.push_stack_op(&mut exec_step, RW::READ, stack_position, key)?;

        // Storage read
        let storage_value_read = cur_step.storage.get_or_err(&key)?;

        let warm = match state.tx.warm_storage.get(&(contract_addr, key)) {
            Some(_v) => (true),
            None => (false),
        };
        state
            .tx
            .warm_storage
            .insert((contract_addr, key), storage_value_read);

        let (_, committed_value) = state.sdb.get_storage(&contract_addr, &key);
        let committed_value = Word::from(committed_value);
        //assert!(found, "committed_value should be in state db");

        state.push_op(
            &mut exec_step,
            RW::READ,
            StorageOp::new(
                contract_addr,
                key,
                storage_value_read,
                storage_value_read,
                state.tx_ctx.id(),
                committed_value,
            ),
        );

        // First stack write
        state.push_stack_op(
            &mut exec_step,
            RW::WRITE,
            stack_position,
            storage_value_read,
        )?;
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountStorageOp {
                tx_id: state.tx_ctx.id(),
                address: contract_addr,
                key,
                value: true,
                value_prev: warm,
            },
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod sload_tests {
    use super::*;
    use crate::circuit_input_builder::ExecState;
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
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x6fu32))
                )
            ]
        );

        let storage_op = &builder.block.container.storage[step.bus_mapping_instance[5].as_usize()];
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
                    Word::from(0x0u32),
                )
            )
        )
    }
}
