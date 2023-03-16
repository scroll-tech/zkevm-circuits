use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::error::{ExecError, OogError};
use crate::evm::Opcode;
use crate::Error;
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;

#[derive(Clone, Copy, Debug)]
pub(crate) struct OOGCreate2 {}

impl Opcode for OOGCreate2 {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        debug_assert!(geth_step.op == OpcodeId::CREATE2);

        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::OutOfGas(OogError::Create2));

        for i in 0..4 {
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
