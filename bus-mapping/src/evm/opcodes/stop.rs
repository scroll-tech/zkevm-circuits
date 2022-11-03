use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::CallContextField,
    Error,
};
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::STOP`](crate::evm::OpcodeId::STOP)
/// `OpcodeId`. This is responsible of generating all of the associated
/// operations and place them inside the trace's
/// [`OperationContainer`](crate::operation::OperationContainer). In the case of
/// STOP, it simply does not add anything.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Stop;

impl Opcode for Stop {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let call = state.call()?.clone();

        state.call_context_read(
            &mut exec_step,
            call.call_id,
            CallContextField::IsSuccess,
            1.into(),
        );

        if !call.is_root {
            state.caller_ctx_mut()?.return_data = vec![];

            // The following part corresponds to
            // Instruction.step_state_transition_to_restored_context
            // in python spec, and should be reusable among all expected halting opcodes or
            // exceptions.
            state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        }

        state.handle_return(geth_step)?;

        Ok(vec![exec_step])
    }
}
