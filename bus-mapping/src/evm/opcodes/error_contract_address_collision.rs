use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::{AccountField, AccountOp};
use crate::Error;
use eth_types::{GethExecStep, Word};

/// ..
#[derive(Debug, Copy, Clone)]
pub(crate) struct ContractAddressCollision<const IS_CREATE2: bool>;

impl<const IS_CREATE2: bool> Opcode for ContractAddressCollision<IS_CREATE2> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let offset = geth_step.stack.nth_last(1)?.as_usize();
        let length = geth_step.stack.nth_last(2)?.as_usize();

        if length != 0 {
            state
                .call_ctx_mut()?
                .memory
                .extend_at_least(offset + length);
        }

        let n_pop = if IS_CREATE2 { 4 } else { 3 };
        for i in 0..n_pop {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        let _address = if IS_CREATE2 {
            state.create2_address(&geth_steps[0])?
        } else {
            state.create_address()?
        };
        // TODO: assert address is collision

        state.stack_write(
            &mut exec_step,
            geth_step.stack.nth_last_filled(n_pop - 1),
            Word::zero(),
        )?;

        let caller = state.call()?.clone();

        // Increase caller's nonce
        let caller_nonce = state.sdb.get_nonce(&caller.address);
        state.push_op_reversible(
            &mut exec_step,
            AccountOp {
                address: caller.address,
                field: AccountField::Nonce,
                value: (caller_nonce + 1).into(),
                value_prev: caller_nonce.into(),
            },
        )?;

        Ok(vec![exec_step])
    }
}
