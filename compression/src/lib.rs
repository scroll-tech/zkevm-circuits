//! Input a proof, a compression circuit generates a new proof that may have smaller size.
//!
//! It re-exposes same public inputs from the input snark.
//! All this circuit does is to reduce the proof size.

/// Circuit implementation of compression circuit.
mod circuit;
mod params;
pub mod utils;

#[cfg(test)]
mod tests;

pub use circuit::CompressionCircuit;
