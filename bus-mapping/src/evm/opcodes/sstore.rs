use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::eth_types::GethExecStep;
use crate::{
    operation::{StackOp, StorageOp, RW},
    Error,
};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::SSTORE`](crate::evm::OpcodeId::SSTORE)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Sstore;

impl Opcode for Sstore {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];

        // First stack read (key)
        let key = step.stack.nth_last(0)?;
        let key_pos = step.stack.nth_last_filled(0);
        state.push_stack_op(RW::READ, key_pos, key);

        // Second stack read (value)
        let value = step.stack.nth_last(1)?;
        let value_pos = step.stack.nth_last_filled(1);
        state.push_stack_op(RW::READ, value_pos, value);

        // Storage write
        let value_prev = step.storage.get_or_err(&key)?;
        state.push_op(StorageOp::new(
            RW::WRITE,
            state.call().address,
            key,
            value,
            value_prev,
        ));

        Ok(())
    }
}
