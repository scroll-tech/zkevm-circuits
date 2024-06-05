//! Hardfork related codes for Scroll networks

/// Hardfork ID for scroll networks
#[derive(Debug, PartialEq, Eq)]
pub enum HardforkId {
    /// Curie hardfork
    Curie = 3,
}

/// Scroll mainnet chain id
pub const SCROLL_MAINNET_CHAIN_ID: u64 = 534352;
/// Scroll devnet chain id
pub const SCROLL_DEVNET_CHAIN_ID: u64 = 222222;

/// Get hardforks of Scroll networks.
/// Returns a list of triplets of (hardfork id, chain id, block number)
pub fn hardfork_heights() -> Vec<(HardforkId, u64, u64)> {
    vec![
        (HardforkId::Curie, SCROLL_DEVNET_CHAIN_ID, 5), // dev net
        (HardforkId::Curie, SCROLL_MAINNET_CHAIN_ID, u64::MAX), // mainnet
    ]
}
