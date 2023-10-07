use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::{
    evm_types::block_utils::{calculate_block_hash, is_valid_block_number},
    GethExecStep,
};

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Blockhash;

impl Opcode for Blockhash {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let block_number = geth_step.stack.nth_last(0)?;
        assert_eq!(block_number, state.stack_pop(&mut exec_step)?);

        let current_block_number = state.tx.block_num;
        let block_hash = if is_valid_block_number(block_number, current_block_number.into()) {
            let (sha3_input, sha3_output) =
                calculate_block_hash(state.block.chain_id, block_number);
            state.block.sha3_inputs.push(sha3_input);
            sha3_output
        } else {
            0.into()
        };
        assert_eq!(block_hash, geth_steps[1].stack.last()?);
        state.stack_push(&mut exec_step, block_hash)?;

        Ok(vec![exec_step])
    }
}
