use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::opcodes::stackonlyop::StackOnlyOpcode;
use crate::evm::Opcode;
use crate::Error;
use eth_types::GethExecStep;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Sha3;

impl Opcode for Sha3 {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        // TODO: add rw operations needed, like memory reads and other lookups
        let geth_step = &geth_steps[0];

        log::debug!("incomplete SHA3 implementation");
        let steps = StackOnlyOpcode::<2, 1>::gen_associated_ops(state, geth_steps)?;

        // reconstruction
        let offset = geth_step.stack.nth_last(0)?.as_usize();
        let length = geth_step.stack.nth_last(1)?.as_usize();

        if length != 0 {
            state
                .call_ctx_mut()?
                .memory
                .extend_at_least(offset + length);
        }
        Ok(steps)
    }
}
