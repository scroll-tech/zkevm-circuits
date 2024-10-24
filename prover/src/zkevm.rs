#[cfg(feature = "scroll")]
mod capacity_checker;
#[cfg(feature = "scroll")]
pub use capacity_checker::{CircuitCapacityChecker, RowUsage, SubCircuitRowUsage};

pub mod circuit;

mod error;
pub use error::ChunkProverError;

mod prover;
pub use prover::Prover;

mod verifier;
pub use verifier::Verifier;

/// Alias to be re-exported.
pub type ChunkProver<'a> = Prover<'a>;

/// Alias to be re-exported.
pub type ChunkVerifier<'a> = Verifier<'a>;
