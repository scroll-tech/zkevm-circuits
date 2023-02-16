use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    error::ExecError,
    evm::Opcode,
    operation::CallContextField,
    Error,
};
use eth_types::GethExecStep;

#[derive(Debug, Copy, Clone)]
pub struct ErrorOOGCodeStore;

impl Opcode for ErrorOOGCodeStore {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        exec_step.error = Some(ExecError::CodeStoreOutOfGas);

        let offset = geth_step.stack.nth_last(0)?;
        let length = geth_step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), offset)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), length)?;

        // in internal call context
        let call = state.call()?;
        assert!(call.is_create() && !call.is_root);

        // must be in create context
        state.call_context_read(
            &mut exec_step,
            call.call_id,
            CallContextField::IsCreate,
            (call.is_create() as u64).into(),
        );
        // refer to return_revert Case C
        state.handle_restore_context(geth_steps, &mut exec_step)?;

        //state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;
        Ok(vec![exec_step])
    }
}
