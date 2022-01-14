use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use types::eth_types::GethExecStep;
use crate::Error;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::JUMPDEST`](crate::evm_types::OpcodeId::JUMPDEST)
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
