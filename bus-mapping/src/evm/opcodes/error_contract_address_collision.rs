use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::{AccountField, AccountOp},
    Error,
};
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

        let [offset, length] = {
            let stack = &state.call_ctx()?.stack;
            let offset = stack.nth_last(1)?.as_usize();
            let length = stack.nth_last(2)?.as_usize();
            [offset, length]
        };

        if length != 0 {
            state
                .call_ctx_mut()?
                .memory
                .extend_at_least(offset + length);
        }

        let n_pop = if IS_CREATE2 { 4 } else { 3 };
        let _stack_inputs = state.stack_pops(&mut exec_step, n_pop)?;
        #[cfg(feature = "enable-stack")]
        for (i, value) in _stack_inputs.iter().enumerate() {
            assert_eq!(*value, geth_step.stack.nth_last(i)?);
        }

        let _address = if IS_CREATE2 {
            state.create2_address(&geth_steps[0])?
        } else {
            state.create_address()?
        };
        // TODO: assert address is collision

        state.stack_push(&mut exec_step, Word::zero())?;

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
