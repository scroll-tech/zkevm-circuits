use super::{Opcode, OpcodeId};
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::TxAccessListAccountStorageOp;
use crate::operation::{CallContextField, RW};
use crate::Error;
use eth_types::{GethExecStep, ToWord};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OogError::Sload`](crate::error::OogError::Sload).
#[derive(Debug, Copy, Clone)]
pub(crate) struct OOGSload;

impl Opcode for OOGSload {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        debug_assert!(geth_step.op == OpcodeId::SLOAD);

        let mut exec_step = state.new_step(geth_step)?;
        let next_step = geth_steps.get(1);
        exec_step.error = state.get_step_err(geth_step, next_step).unwrap();

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

        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;

        Ok(vec![exec_step])
    }
}
