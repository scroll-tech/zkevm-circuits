#[cfg(feature = "scroll")]
mod capacity_checker;
pub mod circuit;
mod prover;
mod verifier;

pub use self::prover::Prover;
#[cfg(feature = "scroll")]
pub use capacity_checker::{CircuitCapacityChecker, RowUsage};
use serde::{Deserialize, Serialize};
pub use verifier::Verifier;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubCircuitRowUsage {
    pub name: String,
    pub row_number: usize,
}
