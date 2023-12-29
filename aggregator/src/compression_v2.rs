//! Input a proof, a compression circuit generates a new proof that may have smaller size.
//!
//! It re-exposes same public inputs from the input snark.
//! All this circuit does is to reduce the proof size.

/// Circuit implementation of compression circuit.
mod circuit;

/// Config for compression circuit
mod config;

pub(crate) use circuit::CompressionCircuit;
pub(crate) use config::CompressionConfig;