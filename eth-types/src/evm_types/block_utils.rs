//! Helper constants and utility functions for block

use crate::{U256, U64};
use ethers_core::utils::keccak256;

/// Maximum range of previous blocks allowed inside BLOCKHASH opcode
pub const NUM_PREV_BLOCK_ALLOWED: u64 = 256;

/// Calculate block hash by chain ID and block number (only for scroll).
/// Return a pair of input and output.
pub fn calculate_block_hash(chain_id: U256, block_number: U256) -> (Vec<u8>, U256) {
    let mut input = vec![0; 16];

    U64([chain_id.low_u64()]).to_big_endian(&mut input[..8]);
    U64([block_number.low_u64()]).to_big_endian(&mut input[8..]);

    let output = U256::from_big_endian(&keccak256(&input));

    (input, output)
}

/// Check if a block number is valid corresponding to the current block number.
pub fn is_valid_block_number(block_number: U256, current_block_number: U256) -> bool {
    block_number < current_block_number
        && block_number
            >= current_block_number
                .checked_sub(NUM_PREV_BLOCK_ALLOWED.into())
                .unwrap_or_default()
}
