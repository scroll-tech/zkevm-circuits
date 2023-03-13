use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    error::{ExecError, OogError},
    evm::Opcode,
    Error,
};
use eth_types::{evm_types::OpcodeId, GethExecStep};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OogError::Sha3`](crate::error::OogError::Sha3).
#[derive(Clone, Copy, Debug)]
pub(crate) struct OOGSha3;

impl Opcode for OOGSha3 {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        debug_assert_eq!(geth_step.op, OpcodeId::SHA3);

        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::OutOfGas(OogError::Sha3));

        for i in 0..2 {
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
