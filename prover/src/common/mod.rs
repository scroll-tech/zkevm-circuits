mod prover;
pub use prover::Prover;

mod verifier;
pub use verifier::Verifier;

// Re-export from the aggregator crate.
pub use aggregator::{ChunkInfo, CompressionCircuit};
