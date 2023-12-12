use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to all the Stack pop only operations: take N words and return nothing.
/// The following cases exist in the EVM:
/// - N = 1: UnaryOpcode
/// - N = 2: BinaryOpcode
/// - N = 3: TernaryOpcode
#[derive(Debug, Copy, Clone)]
pub(crate) struct StackPopOnlyOpcode<const N_POP: usize, const IS_ERR: bool = { false }>;

impl<const N_POP: usize, const IS_ERR: bool> Opcode for StackPopOnlyOpcode<N_POP, IS_ERR> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        // N_POP stack reads
        for i in 0..N_POP {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        if IS_ERR {
            let next_step = geth_steps.get(1);
            let err = state.get_step_err(geth_step, next_step);
            exec_step.error = err.unwrap();
            state.handle_return(&mut [&mut exec_step], geth_steps, true)?;
        }

        Ok(vec![exec_step])
    }
}
