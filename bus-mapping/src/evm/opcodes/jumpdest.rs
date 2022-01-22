use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::Error;
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::JUMPDEST`](crate::evm::OpcodeId::JUMPDEST)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Jumpdest;

impl Opcode for Jumpdest {
    fn gen_associated_ops(
        _state: &mut CircuitInputStateRef,
        _steps: &[GethExecStep],
    ) -> Result<(), Error> {
        // Jumpdest does not generate any operations
        Ok(())
    }
}
