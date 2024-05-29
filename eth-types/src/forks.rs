//! Hardfork related codes for Scroll networks

/// Hardfork ID for scroll networks
#[derive(Debug, PartialEq, Eq)]
pub enum HardforkId {
    /// Curie hardfork
    Curie = 3,
}


/// Get hardforks of Scroll networks.
/// Returns a list of triplets of (hardfork id, chain id, block number)
pub fn hardfork_heights() -> Vec<(HardforkId, u64, u64)> {
    vec![
        (HardforkId::Curie, 222222, 5), // dev net
    ]
}