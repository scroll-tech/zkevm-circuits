//! ..
pub use eth_types::{KECCAK_CODE_HASH_EMPTY, POSEIDON_CODE_HASH_EMPTY};
use std::{convert::Infallible, str::FromStr, sync::LazyLock};

/// ..
pub fn read_env_var<T: Clone + FromStr>(var_name: &'static str, default: T) -> T {
    std::env::var(var_name)
        .map(|s| s.parse::<T>().unwrap_or_else(|_| default.clone()))
        .unwrap_or(default)
}
/// env var for Geth trace sanity check level
pub static GETH_TRACE_CHECK_LEVEL: LazyLock<GethTraceSanityCheckLevel> =
    LazyLock::new(|| read_env_var("GETH_TRACE_CHECK_LEVEL", GethTraceSanityCheckLevel::None));

/// Geth trace sanity check level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GethTraceSanityCheckLevel {
    /// No sanity check
    None,
    /// Check sanity and log error
    Check,
    /// Panic on error
    Strict,
}

impl GethTraceSanityCheckLevel {
    /// Whether to do sanity check
    pub fn should_check(&self) -> bool {
        *self != GethTraceSanityCheckLevel::None
    }

    /// Whether to panic on error
    pub fn should_panic(&self) -> bool {
        *self == GethTraceSanityCheckLevel::Strict
    }
}

impl FromStr for GethTraceSanityCheckLevel {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "strict" => Ok(GethTraceSanityCheckLevel::Strict),
            _ if !s.is_empty() => Ok(GethTraceSanityCheckLevel::Check),
            _ => Ok(GethTraceSanityCheckLevel::None),
        }
    }
}
