use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::{AccountField, CallContextField, TxAccessListAccountOp, RW};
use crate::Error;
use eth_types::evm_types::OpcodeId;
use eth_types::{GethExecStep, ToAddress, ToWord, Word};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the out of gas errors for [`OpcodeId::CALL`],
/// [`OpcodeId::CALLCODE`], [`OpcodeId::DELEGATECALL`] and
/// [`OpcodeId::STATICCALL`].
#[derive(Debug, Copy, Clone)]
pub(crate) struct OOGCall;

impl Opcode for OOGCall {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let stack_input_num = match geth_step.op {
            OpcodeId::CALL | OpcodeId::CALLCODE => 7,
            OpcodeId::DELEGATECALL | OpcodeId::STATICCALL => 6,
            op => unreachable!("{op} should not happen in OOGCall"),
        };

        let mut exec_step = state.new_step(geth_step)?;
        let next_step = if geth_steps.len() > 1 {
            Some(&geth_steps[1])
        } else {
            None
        };
        exec_step.error = state.get_step_err(geth_step, next_step).unwrap();

        let tx_id = state.tx_ctx.id();
        let call_address = geth_step.stack.nth_last(1)?.to_address();

        let current_call = state.call()?.clone();
        for (field, value) in [
            (CallContextField::TxId, tx_id.into()),
            (
                CallContextField::IsStatic,
                (current_call.is_static as u64).into(),
            ),
        ] {
            state.call_context_read(&mut exec_step, current_call.call_id, field, value);
        }

        for i in 0..stack_input_num {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        state.stack_write(
            &mut exec_step,
            geth_step.stack.nth_last_filled(stack_input_num - 1),
            // Must fail.
            (0_u64).into(),
        )?;

        let (_, callee_account) = state.sdb.get_account(&call_address);
        let callee_exists = !callee_account.is_empty();
        let callee_code_hash = callee_account.code_hash;
        let callee_code_hash_word = if callee_exists {
            callee_code_hash.to_word()
        } else {
            Word::zero()
        };

        state.account_read(
            &mut exec_step,
            call_address,
            AccountField::CodeHash,
            callee_code_hash_word,
            callee_code_hash_word,
        )?;

        let is_warm = state.sdb.check_account_in_access_list(&call_address);
        state.push_op(
            &mut exec_step,
            RW::READ,
            TxAccessListAccountOp {
                tx_id,
                address: call_address,
                is_warm,
                is_warm_prev: is_warm,
            },
        );

        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;
        Ok(vec![exec_step])
    }
}
