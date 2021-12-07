use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::eth_types::GethExecStep;
use crate::{
    operation::{StackOp, RW},
    Error,
};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::JUMP`](crate::evm::OpcodeId::JUMP)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Jump;

impl Opcode for Jump {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];

        // `JUMP` needs only one read operation
        let op = StackOp::new(
            RW::READ,
            step.stack.nth_last_filled(0),
            step.stack.nth_last(0)?,
        );
        state.push_op(op);

        Ok(())
    }
}
