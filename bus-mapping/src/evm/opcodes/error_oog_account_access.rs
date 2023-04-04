use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    error::{ExecError, OogError},
    evm::{Opcode, OpcodeId},
    operation::{AccountField, CallContextField, TxAccessListAccountOp, RW},
    Error,
};
use eth_types::{GethExecStep, ToAddress, ToWord, H256, U256, };

#[derive(Debug, Copy, Clone)]
pub struct ErrorOOGAccountAccess;

impl Opcode for ErrorOOGAccountAccess {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::OutOfGas(OogError::AccountAccess));

        // assert op code is BALANCE | EXTCODESIZE | EXTCODEHASH
        assert!([OpcodeId::BALANCE, OpcodeId::EXTCODESIZE, OpcodeId::EXTCODEHASH].contains(&geth_step.op));
        // Read account address from stack.
        let address_word = geth_step.stack.last()?;
        let address = address_word.to_address();
        state.stack_read(&mut exec_step, geth_step.stack.last_filled(), address_word)?;

        // Read transaction ID from call context.
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::TxId,
            U256::from(state.tx_ctx.id()),
        );

        // transaction access list for account address.
        let is_warm = state.sdb.check_account_in_access_list(&address);
        // read `is_warm` state
        state.push_op(
            &mut exec_step,
            RW::READ,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address: address,
                is_warm,
                is_warm_prev: is_warm,
            },
        );

        // common error handling
        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;
        Ok(vec![exec_step])
    }
}
