//! Utility functions to help calculate gas

use super::GasCost;
use crate::{AccessList, Word};

/// Calculate memory expansion gas cost by current and next memory word size.
pub fn memory_expansion_gas_cost(curr_memory_word_size: u64, next_memory_word_size: u64) -> u64 {
    if next_memory_word_size == curr_memory_word_size {
        0
    } else {
        GasCost::MEMORY_EXPANSION_LINEAR_COEFF.0 * (next_memory_word_size - curr_memory_word_size)
            + next_memory_word_size * next_memory_word_size
                / GasCost::MEMORY_EXPANSION_QUAD_DENOMINATOR.0
            - curr_memory_word_size * curr_memory_word_size
                / GasCost::MEMORY_EXPANSION_QUAD_DENOMINATOR.0
    }
}

/// Calculate memory copier gas cost by current and next memory word size, and
/// number of bytes to copy.
pub fn memory_copier_gas_cost(
    curr_memory_word_size: u64,
    next_memory_word_size: u64,
    num_copy_bytes: u64,
    per_word_copy_gas: u64,
) -> u64 {
    let num_words = (num_copy_bytes + 31) / 32;
    num_words * per_word_copy_gas +
        // Note that opcodes with a byte size parameter of 0 will not trigger
        // memory expansion, regardless of their offset parameters.
        if num_words > 0 {
            memory_expansion_gas_cost(curr_memory_word_size, next_memory_word_size)
        } else {
            0
        }
}

/// Calculate EIP 150 gas passed to callee.
pub fn eip150_gas(gas_left: u64, gas_specified: Word) -> u64 {
    let capped_gas = gas_left - gas_left / 64;

    if gas_specified.bits() <= 64 {
        let gas_specified = gas_specified.low_u64();
        if gas_specified < capped_gas {
            return gas_specified;
        }
    }

    capped_gas
}

/// Calculate gas cost for access list (EIP 2930).
pub fn tx_access_list_gas_cost(access_list: &Option<AccessList>) -> u64 {
    access_list.as_ref().map_or(0, |access_list| {
        access_list.0.len() as u64 * GasCost::ACCESS_LIST_PER_ADDRESS.as_u64()
            + access_list
                .0
                .iter()
                .fold(0, |acc, item| acc + item.storage_keys.len() as u64)
                * GasCost::ACCESS_LIST_PER_STORAGE_KEY.as_u64()
    })
}

/// Calculate gas cost for transaction data.
pub fn tx_data_gas_cost(data: &[u8]) -> u64 {
    data.iter()
        .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 })
}
