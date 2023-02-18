use super::{Opcode, OpcodeId};
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::error::{ExecError, OogError};
use crate::operation::{CallContextField, RW};
use crate::operation::{StorageOp, TxAccessListAccountStorageOp};
use crate::Error;
use eth_types::{GethExecStep, ToWord};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the
/// [`OogError::SloadSstore`](crate::error::OogError::SloadSstore).
#[derive(Clone, Copy, Debug)]
pub(crate) struct OOGSloadSstore;

impl Opcode for OOGSloadSstore {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        debug_assert!([OpcodeId::SLOAD, OpcodeId::SSTORE].contains(&geth_step.op));

        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::OutOfGas(OogError::SloadSstore));

        let call_id = state.call()?.call_id;
        let callee_address = state.call()?.address;
        let tx_id = state.tx_ctx.id();

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::TxId,
            tx_id.into(),
        );

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::IsStatic,
            (state.call()?.is_static as u8).into(),
        );

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::CalleeAddress,
            callee_address.to_word(),
        );

        let key = geth_step.stack.last()?;
        state.stack_read(&mut exec_step, geth_step.stack.last_filled(), key)?;

        let is_warm = state
            .sdb
            .check_account_storage_in_access_list(&(callee_address, key));
        state.push_op(
            &mut exec_step,
            RW::READ,
            TxAccessListAccountStorageOp {
                tx_id,
                address: callee_address,
                key,
                is_warm,
                is_warm_prev: is_warm,
            },
        );

        // Special operations are only used for SSTORE.
        if geth_step.op == OpcodeId::SSTORE {
            let value = geth_step.stack.nth_last(1)?;
            state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), value)?;

            let (_, value_prev) = state.sdb.get_storage(&callee_address, &key);
            let (_, original_value) = state.sdb.get_committed_storage(&callee_address, &key);

            state.push_op(
                &mut exec_step,
                RW::READ,
                StorageOp::new(
                    callee_address,
                    key,
                    *value_prev,
                    *value_prev,
                    tx_id,
                    *original_value,
                ),
            );
        }

        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;

        Ok(vec![exec_step])
    }
}
