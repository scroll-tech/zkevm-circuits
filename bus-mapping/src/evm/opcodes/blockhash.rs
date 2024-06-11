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

        let block_number = state.stack_pop(&mut exec_step)?;
        #[cfg(feature = "enable-stack")]
        assert_eq!(block_number, geth_step.stack.last()?);

        let current_block_number = state.tx.block_num;
        let block_hash = if is_valid_block_number(block_number, current_block_number.into()) {
            if cfg!(feature = "scroll") {
                let (sha3_input, sha3_output) =
                    calculate_block_hash(state.block.chain_id, block_number);
                state.block.sha3_inputs.push(sha3_input);
                sha3_output
            } else {
                let block_head = state.block.blocks.get(&current_block_number).unwrap();
                let offset = (current_block_number - block_number.as_u64()) as usize;
                let total_history_hashes = block_head.history_hashes.len();
                block_head.history_hashes[total_history_hashes - offset]
            }
        } else {
            0.into()
        };
        #[cfg(feature = "enable-stack")]
        assert_eq!(block_hash, geth_steps[1].stack.last()?);
        state.stack_push(&mut exec_step, block_hash)?;

        Ok(vec![exec_step])
    }
}
