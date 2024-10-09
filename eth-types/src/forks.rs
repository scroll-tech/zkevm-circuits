//! Hardfork related codes for Scroll networks

use crate::constants::read_env_var;

/// Hardfork ID for scroll networks
#[derive(Debug, PartialEq, Eq)]
pub enum HardforkId {
    /// Bernoulli hardfork
    Bernoulli = 2,
    /// Curie hardfork
    Curie = 3,
}

/// Scroll devnet chain id
pub const SCROLL_DEVNET_CHAIN_ID: u64 = 222222;
/// Scroll testnet chain id
pub const SCROLL_TESTNET_CHAIN_ID: u64 = 534351;
/// Scroll mainnet chain id
pub const SCROLL_MAINNET_CHAIN_ID: u64 = 534352;

/// Get hardforks of Scroll networks.
/// Returns a list of triplets of (hardfork id, chain id, block number)
pub fn hardfork_heights() -> Vec<(HardforkId, u64, u64)> {
    vec![
        (HardforkId::Bernoulli, SCROLL_DEVNET_CHAIN_ID, 0), // devnet
        (HardforkId::Bernoulli, SCROLL_TESTNET_CHAIN_ID, 3747132), // testnet
        (
            HardforkId::Bernoulli,
            SCROLL_MAINNET_CHAIN_ID,
            read_env_var("SCROLL_MAINNET_BERNOULLI_BLOCK", 5220340),
        ), // mainnet
        (HardforkId::Curie, SCROLL_DEVNET_CHAIN_ID, 5),     // devnet
        (HardforkId::Curie, SCROLL_TESTNET_CHAIN_ID, 4740239), // testnet
        (
            HardforkId::Curie,
            SCROLL_MAINNET_CHAIN_ID,
            read_env_var("SCROLL_MAINNET_CURIE_BLOCK", 7096836),
        ), // mainnet
    ]
}
