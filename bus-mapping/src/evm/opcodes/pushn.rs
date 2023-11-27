use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::{GethExecStep, Word};

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
        let code_size = code.len();
        let pc = geth_step.pc.0;
        let data_len = geth_step.op.data_len();
        let data_start = pc + 1;
        let max_len = code_size - data_start;
        let mut value_bytes = [0u8; 32];
        if data_len <= max_len {
            value_bytes[32 - data_len..].copy_from_slice(&code[data_start..data_start + data_len]);
        } else {
            value_bytes[32 - data_len..32 - data_len + max_len]
                .copy_from_slice(&code[data_start..]);
        };
        let real_value = Word::from_big_endian(&value_bytes);
        #[cfg(feature = "enable-stack")]
        assert_eq!(real_value, geth_steps[1].stack.last()?);
        let missing_bits = data_len.saturating_sub(max_len) * 8;

        state.call_ctx_mut()?.stack.push(real_value)?;

        // If the bytecode is truncated, the bytecode circuit interprets only the actual data
        // without zero-padding.
        state.stack_write(
            &mut exec_step,
            state.call_ctx()?.stack.last_filled(),
            real_value >> missing_bits,
        )?;

        Ok(vec![exec_step])
    }
}
