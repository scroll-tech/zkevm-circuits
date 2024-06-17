//! Scroll EVM related constants

use std::str::FromStr;

use ethers_core::types::{Address, U256};

use crate::l2_types::BlockTrace;

/// Read env var with default value
pub fn read_env_var<T: Clone + FromStr>(var_name: &'static str, default: T) -> T {
    std::env::var(var_name)
        .map(|s| s.parse::<T>().unwrap_or_else(|_| default.clone()))
        .unwrap_or(default)
}

/// Scroll coinbase
pub const SCROLL_COINBASE: &str = "0x5300000000000000000000000000000000000005";

/// Get COINBASE constant used for circuit
pub fn get_coinbase_constant() -> Address {
    let default_coinbase = if cfg!(feature = "scroll") {
        Address::from_str(SCROLL_COINBASE).unwrap()
    } else {
        Address::zero()
    };
    read_env_var("COINBASE", default_coinbase)
}

/// Set COINBASE env var
pub fn set_env_coinbase(coinbase: &Address) -> String {
    let coinbase = format!("0x{}", hex::encode(coinbase));
    std::env::set_var("COINBASE", &coinbase);
    coinbase
}

/// Get DIFFICULTY constant used for circuit
pub fn get_difficulty_constant() -> U256 {
    read_env_var("DIFFICULTY", U256::zero())
}

///  Set scroll block constants using trace
pub fn set_scroll_block_constants_with_trace(trace: &BlockTrace) {
    set_scroll_block_constants(&trace.coinbase.address, trace.chain_id, U256::zero())
}

/// Set scroll block constants
pub fn set_scroll_block_constants(coinbase: &Address, chain_id: u64, difficulty: U256) {
    set_env_coinbase(coinbase);
    std::env::set_var("CHAIN_ID", format!("{}", chain_id));
    std::env::set_var("DIFFICULTY", difficulty.to_string());
}
