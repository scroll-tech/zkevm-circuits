use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::error::{ExecError, OogError};
use crate::evm::Opcode;
use crate::Error;
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;

#[derive(Clone, Copy, Debug)]
pub(crate) struct OOGDynamicMemory {}

impl Opcode for OOGDynamicMemory {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        debug_assert!(
            [OpcodeId::CREATE, OpcodeId::RETURN, OpcodeId::REVERT].contains(&geth_step.op)
        );

        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::OutOfGas(OogError::DynamicMemoryExpansion));

        if geth_step.op == OpcodeId::CREATE {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.last_filled(),
                geth_step.stack.last()?,
            )?;
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(1),
                geth_step.stack.nth_last(1)?,
            )?;
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(2),
                geth_step.stack.nth_last(2)?,
            )?;
        } else {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.last_filled(),
                geth_step.stack.last()?,
            )?;
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(1),
                geth_step.stack.nth_last(1)?,
            )?;
        }

        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;

        Ok(vec![exec_step])
    }
}
