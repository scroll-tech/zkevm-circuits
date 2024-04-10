use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::GethExecStep;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Jumpi;

impl Opcode for Jumpi {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let pc = state.stack_pop(&mut exec_step)?;
        let condition = state.stack_pop(&mut exec_step)?;

        if let Some(next_step) = geth_steps.get(1) {
            if condition == 0.into() {
                assert_eq!(
                    next_step.pc.0,
                    geth_step.pc.0 + 1,
                    "jumpi should not jump: current step {:?} next step {:?}",
                    geth_step,
                    next_step
                );
            } else {
                assert_eq!(
                    next_step.pc.0 as u64,
                    pc.low_u64(),
                    "jumpi should jump: current step {:?} next step {:?}",
                    geth_step,
                    next_step
                );
            }
        }

        #[cfg(feature = "enable-stack")]
        for (i, v) in [pc, condition].into_iter().enumerate() {
            assert_eq!(v, geth_step.stack.nth_last(i)?);
        }

        Ok(vec![exec_step])
    }
}
