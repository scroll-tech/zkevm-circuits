use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::{Opcode, OpcodeId};
use crate::Error;
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
        let is_jumpi = geth_step.op == OpcodeId::JUMPI;
        let mut condition: Word = Word::zero();
        if is_jumpi {
            condition = geth_step.stack.nth_last(1)?;
        }
        state.stack_read(
            &mut exec_step,
            geth_step.stack.last_filled(),
            geth_step.stack.last()?,
        )?;
        if is_jumpi {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(1),
                condition,
            )?;
        }
        // `IsSuccess` call context operation is added in gen_restore_context_ops

        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;
        Ok(vec![exec_step])
    }
}
