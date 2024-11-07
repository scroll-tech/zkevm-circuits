mod error;
pub use error::BatchProverError;

mod prover;
pub use prover::{check_chunk_hashes, Prover};

mod recursion;
pub use recursion::RecursionTask;

mod verifier;
pub use verifier::Verifier;

/// Re-export some types from the [`aggregator`] crate.
pub use aggregator::{get_blob_bytes, BatchData, BatchHash, BatchHeader, MAX_AGG_SNARKS};

/// Alias for convenience.
pub type BatchProver<'a> = Prover<'a>;

/// Alias for convenience.
pub type BatchVerifier<'a> = Verifier<'a>;
