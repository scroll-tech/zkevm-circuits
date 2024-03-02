use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    error::ExecError,
    evm::Opcode,
    operation::CallContextField,
    Error,
};
use eth_types::{evm_types::OpcodeId, GethExecStep};

#[derive(Debug, Copy, Clone)]
pub(crate) struct PrecompileFailed;

impl Opcode for PrecompileFailed {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let stack_input_num = match geth_step.op {
            OpcodeId::CALL | OpcodeId::CALLCODE => 7,
            OpcodeId::DELEGATECALL | OpcodeId::STATICCALL => 6,
            op => unreachable!("{op} should not happen in PrecompileFailed"),
        };

        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::PrecompileFailed);

        let [args_offset, args_length, ret_offset, ret_length] = {
            let stack = &state.call_ctx()?.stack;
            let args_offset = stack.nth_last(stack_input_num - 4)?.low_u64() as usize;
            let args_length = stack.nth_last(stack_input_num - 3)?.as_usize();
            let ret_offset = stack.nth_last(stack_input_num - 2)?.low_u64() as usize;
            let ret_length = stack.nth_last(stack_input_num - 1)?.as_usize();
            [args_offset, args_length, ret_offset, ret_length]
        };

        // we need to keep the memory until parse_call complete
        state.call_expand_memory(args_offset, args_length, ret_offset, ret_length)?;

        let call = state.parse_call(geth_step)?;
        state.push_call(call.clone());
        state.caller_ctx_mut()?.return_data.clear();
        state.handle_return((None, None), &mut [&mut exec_step], geth_steps, false)?;

        let _stack_inputs = state.stack_pops(&mut exec_step, stack_input_num)?;
        #[cfg(feature = "enable-stack")]
        for (i, v) in _stack_inputs.into_iter().enumerate() {
            assert_eq!(v, geth_step.stack.nth_last(i)?);
        }

        // Must fail.
        state.stack_push(&mut exec_step, (0_u64).into())?;

        for (field, value) in [
            (CallContextField::LastCalleeId, call.call_id.into()),
            (CallContextField::LastCalleeReturnDataOffset, 0.into()),
            (CallContextField::LastCalleeReturnDataLength, 0.into()),
        ] {
            state.call_context_write(&mut exec_step, call.caller_id, field, value)?;
        }

        Ok(vec![exec_step])
    }
}
