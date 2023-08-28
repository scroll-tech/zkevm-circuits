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
        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::OutOfGas(OogError::Precompile));

        // callee_address
        state.call_context_read(
            &mut exec_step,
            call.call_id,
            CallContextField::CalleeAddress,
            call.code_address().unwrap().to_word(),
        );
        state.call_context_read(
            &mut exec_step,
            call.call_id,
            CallContextField::CallDataLength,
            call.call_data_length.into(),
        );

        Ok(exec_step)
    }
}
