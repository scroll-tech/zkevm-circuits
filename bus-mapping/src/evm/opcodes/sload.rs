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
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

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
        let key = geth_step.stack.last()?;
        let stack_position = geth_step.stack.last_filled();

        // Manage first stack read at latest stack position
        state.push_stack_op(&mut exec_step, RW::READ, stack_position, key)?;

        // Storage read
        let value = geth_step.storage.get_or_err(&key)?;

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
        state.push_stack_op(&mut exec_step, RW::WRITE, stack_position, value)?;
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountStorageOp {
                tx_id: state.tx_ctx.id(),
                address: contract_addr,
                key,
                value: true,
                value_prev: is_warm,
            },
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod sload_tests {
    use super::*;
    use crate::{evm::opcodes::test_util::step_witness_for_bytecode, operation::StackOp};
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        Word,
    };
    use mock::MOCK_ACCOUNTS;
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

        let step = step_witness_for_bytecode(code, OpcodeId::SLOAD);

        assert_eq!(
            [0, 1]
                .map(|idx| &step.rws.stack[idx])
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

        let storage_op = &step.rws.storage[0];
        assert_eq!(
            (storage_op.rw(), storage_op.op()),
            (
                RW::READ,
                &StorageOp::new(
                    MOCK_ACCOUNTS[0],
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
