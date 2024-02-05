use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    error::ExecError,
    evm::Opcode,
    Error,
};
use eth_types::{GethExecStep, U256};

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

        let offset = state.stack_pop(&mut exec_step)?;
        let length = state.stack_pop(&mut exec_step)?;
        #[cfg(feature = "enable-stack")]
        {
            assert_eq!(offset, geth_step.stack.nth_last(0)?);
            assert_eq!(length, geth_step.stack.nth_last(1)?);
        }

        // in create context
        let call = state.call()?;

        // create context check
        assert!(call.is_create());

        assert!(length > U256::zero());

        // read first byte and assert it is 0xef
        let byte = state.call_ctx()?.memory.0[offset.as_usize()];
        assert!(byte == 0xef);

        let shift = offset.as_u64() % 32;
        let slot = offset.as_u64() - shift;

        //state.memory_read(&mut exec_step, offset.try_into()?, byte)?;
        state.memory_read_word(&mut exec_step, slot.into())?;

        // refer to return_revert Case C
        state.handle_return(
            (Some(offset), Some(length)),
            &mut [&mut exec_step],
            geth_steps,
            true,
        )?;
        Ok(vec![exec_step])
    }
}
