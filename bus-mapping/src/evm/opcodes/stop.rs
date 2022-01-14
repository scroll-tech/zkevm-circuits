use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use types::eth_types::GethExecStep;
use crate::Error;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::STOP`](crate::evm_types::OpcodeId::STOP)
/// `OpcodeId`. This is responsible of generating all of the associated
/// operations and place them inside the trace's
/// [`OperationContainer`](crate::operation::OperationContainer). In the case of
/// STOP, it simply does not add anything.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Stop;

impl Opcode for Stop {
    fn gen_associated_ops(
        _state: &mut CircuitInputStateRef,
        _steps: &[GethExecStep],
    ) -> Result<(), Error> {
        // Stop does not generate any operations
        Ok(())
    }
}
