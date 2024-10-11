//! Some handy helpers

use crate::Address;
use revm_precompile::Precompiles;

mod codehash;
pub use codehash::*;

/// Check if address is a precompiled or not.
pub fn is_precompiled(address: &Address) -> bool {
    #[cfg(feature = "scroll")]
    let precompiles = Precompiles::bernoulli();
    #[cfg(not(feature = "scroll"))]
    let precompiles = Precompiles::berlin();
    precompiles.get(address.as_fixed_bytes().into()).is_some()
}
