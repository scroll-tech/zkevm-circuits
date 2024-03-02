use crate::{
    circuit_input_builder::{Call, CircuitInputStateRef, ExecStep},
    error::{ExecError, OogError},
    operation::CallContextField,
    Error,
};
use eth_types::{GethExecStep, ToWord};

#[derive(Copy, Clone, Debug)]
pub struct ErrorOOGPrecompile;

impl ErrorOOGPrecompile {
    pub fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_step: &GethExecStep,
        call: Call,
    ) -> Result<ExecStep, Error> {
        Self::gen_ops(state, state.new_step(geth_step)?, call)
    }

    pub fn gen_ops(
        state: &mut CircuitInputStateRef,
        mut exec_step: ExecStep,
        call: Call,
    ) -> Result<ExecStep, Error> {
        exec_step.error = Some(ExecError::OutOfGas(OogError::Precompile));

        // callee_address
        state.call_context_read(
            &mut exec_step,
            call.call_id,
            CallContextField::CalleeAddress,
            call.code_address().unwrap().to_word(),
        )?;
        state.call_context_read(
            &mut exec_step,
            call.call_id,
            CallContextField::CallDataLength,
            call.call_data_length.into(),
        )?;
        state.call_context_read(
            &mut exec_step,
            call.call_id,
            CallContextField::IsRoot,
            (call.is_root as u64).into(),
        )?;

        Ok(exec_step)
    }
}
