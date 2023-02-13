use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::error::ExecError;
use crate::evm::Opcode;
use crate::Error;
use eth_types::GethExecStep;

#[derive(Debug, Copy, Clone)]
pub(crate) struct InvalidOpcode;

impl Opcode for InvalidOpcode {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::InvalidOpcode);

        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;

        Ok(vec![exec_step])
    }
}
