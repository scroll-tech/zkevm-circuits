use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    evm::{Opcode, OpcodeId},
    Error,
};
use eth_types::{GethExecStep, Word};

#[derive(Debug, Copy, Clone)]
pub(crate) struct InvalidJump;

impl Opcode for InvalidJump {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        let next_step = if geth_steps.len() > 1 {
            Some(&geth_steps[1])
        } else {
            None
        };
        exec_step.error = state.get_step_err(geth_step, next_step).unwrap();
        // assert op code can only be JUMP or JUMPI
        assert!(geth_step.op == OpcodeId::JUMP || geth_step.op == OpcodeId::JUMPI);
        let _counter = state.stack_pop(&mut exec_step)?;
        let is_jumpi = geth_step.op == OpcodeId::JUMPI;
        let _condition: Word = if is_jumpi {
            state.stack_pop(&mut exec_step)?
        } else {
            Word::zero()
        };
        #[cfg(feature = "enable-stack")]
        {
            assert_eq!(_counter, geth_step.stack.last()?);
            if is_jumpi {
                assert_eq!(_condition, geth_step.stack.nth_last(1)?);
            }
        }

        // `IsSuccess` call context operation is added in handle_return
        state.handle_return((None, None), &mut [&mut exec_step], geth_steps, true)?;
        Ok(vec![exec_step])
    }
}
