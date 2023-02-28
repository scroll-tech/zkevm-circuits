use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::Opcode;
use crate::Error;
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the
/// [`OogError::MemoryCopy`](crate::error::OogError::MemoryCopy).
#[derive(Clone, Copy, Debug)]
pub(crate) struct OOGMemoryCopy;

impl Opcode for OOGMemoryCopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        debug_assert!([
            OpcodeId::CALLDATACOPY,
            OpcodeId::CODECOPY,
            OpcodeId::RETURNDATACOPY
        ]
        .contains(&geth_step.op));

        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = state.get_step_err(geth_step, geth_steps.get(1))?;

        // CALLDATACOPY, CODECOPY and RETURNDATACOPY are same for stack pop. Each has
        // three stack read values.
        for i in 0..3 {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;

        Ok(vec![exec_step])
    }
}
