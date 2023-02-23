use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};

use eth_types::{evm_types::OpcodeId, GethExecStep};

use super::{callop::CallOpcode, create::Create, Opcode};

#[derive(Clone, Debug)]
pub(crate) struct InsufficientBalance;

impl Opcode for InsufficientBalance {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        match geth_steps[0].op {
            OpcodeId::CALL | OpcodeId::CALLCODE => {
                CallOpcode::<7>::gen_associated_ops(state, geth_steps)
            }
            OpcodeId::CREATE => Create::<false>::gen_associated_ops(state, geth_steps),
            OpcodeId::CREATE2 => Create::<true>::gen_associated_ops(state, geth_steps),
            op => unreachable!("{op} should not be encountered for InsufficientBalance error"),
        }
    }
}
