use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::{evm_types::OpcodeId, GethExecStep, U256};

#[derive(Clone, Copy, Debug)]
pub(crate) struct PushN;

impl Opcode for PushN {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let code_hash = state.call()?.code_hash;
        let code = state.code(code_hash)?;
        let codesize = code.len();
        let pc = geth_step.pc;
        let max_len = codesize - (pc.0 + 1usize);

        let data_len = geth_step.op.data_len();

        let real_value = geth_steps[1].stack.last()?;

        let value = if data_len <= max_len {
            real_value
        } else {
            let missing_bits = (data_len - max_len) * 8;
            real_value >> missing_bits
        };

        state.stack_write(&mut exec_step, geth_steps[1].stack.last_filled(), value)?;

        Ok(vec![exec_step])
    }
}
