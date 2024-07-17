//! Helper constants and utility functions for block

use crate::{keccak256, U256};

/// Maximum range of previous blocks allowed inside BLOCKHASH opcode
pub const NUM_PREV_BLOCK_ALLOWED: u64 = 256;

/// Calculate block hash by chain ID and block number (only for scroll).
/// Return a pair of input and output.
pub fn calculate_block_hash(chain_id: u64, block_number: U256) -> (Vec<u8>, U256) {
    let mut input = vec![0; 16];

    let chain_id = chain_id.to_be_bytes();
    let block_number = block_number.to::<u64>().to_be_bytes();
    input[..8].copy_from_slice(&chain_id);
    input[8..].copy_from_slice(&block_number);

    let output = U256::from_be_slice(keccak256(&input).as_slice());

    (input, output)
}

/// Check if a block number is valid corresponding to the current block number.
pub fn is_valid_block_number(block_number: U256, current_block_number: U256) -> bool {
    block_number < current_block_number
        && block_number
            >= current_block_number
                .checked_sub(U256::from_limbs([NUM_PREV_BLOCK_ALLOWED, 0, 0, 0]))
                .unwrap_or_default()
}
