use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
    },
    evm::Opcode,
    operation::{AccountField, AccountOp, CallContextField, MemoryOp, RW},
    Error,
};
use eth_types::{
    evm_types::gas_utils::memory_expansion_gas_cost, Bytecode, GethExecStep, ToBigEndian, ToWord,
    Word, H160, H256,
};
use ethers_core::utils::{get_create2_address, keccak256, rlp};

#[derive(Debug, Copy, Clone)]
pub struct ErrorCreate<const IS_CREATE2: bool>;

impl<const IS_CREATE2: bool> Opcode for ErrorCreate<IS_CREATE2> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        let next_step = if geth_steps.len() > 1 {
            Some(&geth_steps[1])
        } else {
            None
        };
        exec_step.error = state.get_step_err(geth_step, next_step).unwrap();

        let offset = geth_step.stack.nth_last(0)?;
        let length = geth_step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), offset)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), length)?;

        // must be in internal call context
        let call = state.call()?;
        assert!(call.is_create()&& !call.is_root);
        println!("call success is {}, is root {}, is_create {}", call.is_success,
            call.is_root, call.is_create());

        // refer to return_revert Case C
        state.handle_restore_context(geth_steps, &mut exec_step)?;

        // not sure, if can do it. 
        //state.gen_restore_context_ops(&mut exec_step, geth_steps);
        state.handle_return(geth_step)?;
        Ok(vec![exec_step])
    }
}