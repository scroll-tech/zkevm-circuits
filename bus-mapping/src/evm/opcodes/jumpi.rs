use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::eth_types::GethExecStep;
use crate::{
    operation::{StackOp, RW},
    Error,
};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::JUMPI`](crate::evm::OpcodeId::JUMPI)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Jumpi;

impl Opcode for Jumpi {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];
        // `JUMPI` needs two read operation
        state.push_op(StackOp::new(
            RW::READ,
            step.stack.nth_last_filled(0),
            step.stack.nth_last(0)?,
        ));
        state.push_op(StackOp::new(
            RW::READ,
            step.stack.nth_last_filled(1),
            step.stack.nth_last(1)?,
        ));

        Ok(())
    }
}
