use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    error::ExecError,
    evm::Opcode,
    Error,
};
use eth_types::{GethExecStep, Word, U256};

#[derive(Debug, Copy, Clone)]
pub struct ErrorCreationCode;

impl Opcode for ErrorCreationCode {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        exec_step.error = Some(ExecError::InvalidCreationCode);

        let offset = geth_step.stack.nth_last(0)?;
        let length = geth_step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), offset)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), length)?;

        // in create context
        let call = state.call()?;

        // create context check
        assert!(call.is_create());

        assert!(length > U256::zero());

        // read first byte and assert it is 0xef
        let byte = state.call_ctx()?.memory.0[offset.as_usize()];
        assert!(byte == 0xef);

        let mut memory = state.call_ctx_mut()?.memory.clone();
        println!("before mload memory length is {}", memory.0.len());

        let offset = offset.as_u64();
        // expand to offset + 32 as need one word at least.
        let minimal_length = offset + 32;

        memory.extend_at_least(minimal_length as usize);

        let shift = offset % 32;
        let slot = offset - shift;
        println!(
            "minimal_length {} , slot {},  shift {}, memory_length {}",
            minimal_length,
            slot,
            shift,
            memory.0.len()
        );

        //state.memory_read(&mut exec_step, offset.try_into()?, byte)?;
        state.memory_read_word(&mut exec_step, slot.into())?;

        // refer to return_revert Case C
        state.handle_return(&mut exec_step, geth_steps, true)?;
        Ok(vec![exec_step])
    }
}
