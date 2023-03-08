use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    error::ExecError,
    evm::Opcode,
    operation::CallContextField,
    Error,
};
use eth_types::GethExecStep;

#[derive(Debug, Copy, Clone)]
pub struct ErrorCodeStore;

impl Opcode for ErrorCodeStore {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        let next_step = geth_steps.get(1);

        exec_step.error = state.get_step_err(geth_step, next_step)?;

        assert!(
            exec_step.error == Some(ExecError::CodeStoreOutOfGas)
                || exec_step.error == Some(ExecError::MaxCodeSizeExceeded)
        );

        let offset = geth_step.stack.nth_last(0)?;
        let length = geth_step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), offset)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), length)?;

        // in internal call context
        let call = state.call()?;
        let call_id = call.call_id;
        let is_success = call.is_success;

        // create context check
        assert!(call.is_create());

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::IsSuccess,
            (is_success as u64).into(),
        );

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::RwCounterEndOfReversion,
            0u64.into(),
        );

        // refer to return_revert Case C
        state.handle_restore_context(geth_steps, &mut exec_step)?;

        //state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;
        Ok(vec![exec_step])
    }
}
