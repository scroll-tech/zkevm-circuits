use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::Opcode;
use crate::Error;
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;

#[derive(Clone, Copy, Debug)]
pub(crate) struct OOGStaticMemory {}

impl Opcode for OOGStaticMemory {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        debug_assert!(
            [OpcodeId::MLOAD, OpcodeId::MSTORE, OpcodeId::MSTORE8].contains(&geth_step.op)
        );

        let mut exec_step = state.new_step(geth_step)?;
        let next_step = geth_steps.get(1);
        exec_step.error = state.get_step_err(geth_step, next_step).unwrap();

        state.stack_read(
            &mut exec_step,
            geth_step.stack.last_filled(),
            geth_step.stack.last()?,
        )?;

        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;

        Ok(vec![exec_step])
    }
}
