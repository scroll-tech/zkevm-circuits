use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::error::ExecError;
use crate::evm::Opcode;
use crate::Error;
use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;

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

        let args_offset = geth_step.stack.nth_last(stack_input_num - 4)?.as_usize();
        let args_length = geth_step.stack.nth_last(stack_input_num - 3)?.as_usize();
        let ret_offset = geth_step.stack.nth_last(stack_input_num - 2)?.as_usize();
        let ret_length = geth_step.stack.nth_last(stack_input_num - 1)?.as_usize();

        // we need to keep the memory until parse_call complete
        state.call_expand_memory(args_offset, args_length, ret_offset, ret_length)?;

        let call = state.parse_call(geth_step)?;
        state.push_call(call);
        state.handle_return(geth_step)?;

        for i in 0..stack_input_num {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        state.stack_write(
            &mut exec_step,
            geth_step.stack.nth_last_filled(stack_input_num - 1),
            // Must fail.
            (0_u64).into(),
        )?;

        Ok(vec![exec_step])
    }
}
