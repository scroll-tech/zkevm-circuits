use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::RETURN`](crate::evm::OpcodeId::RETURN).
#[derive(Debug, Copy, Clone)]
pub(crate) struct Return;

impl Opcode for Return {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let exec_step = state.new_step(&geth_steps[0])?;
        state.handle_return()?;
        Ok(vec![exec_step])
    }
}
