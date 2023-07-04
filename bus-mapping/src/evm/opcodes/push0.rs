use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::{GethExecStep, U256};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Push0;

impl Opcode for Push0 {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        state.stack_write(
            &mut exec_step,
            geth_steps[1].stack.last_filled(),
            U256::zero(),
        )?;

        Ok(vec![exec_step])
    }
}
