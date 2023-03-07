//! ..
use once_cell::sync::Lazy;
use std::str::FromStr;

/// ..
pub fn read_env_var<T: Clone + FromStr>(var_name: &'static str, default: T) -> T {
    std::env::var(var_name)
        .map(|s| s.parse::<T>().unwrap_or_else(|_| default.clone()))
        .unwrap_or(default)
}
/// ..
pub static CHECK_MEM_STRICT: Lazy<bool> = Lazy::new(|| read_env_var("CHECK_MEM_STRICT", false));
