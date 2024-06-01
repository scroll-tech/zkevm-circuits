#![feature(lazy_cell)]

/// Meaning of each circuit:
///   inner: first layer EVM super circuit
///   layer1: compression circuit of "inner"
///   layer2: comppresion circuit of "layer1"
///   layer3: batch circuit. Proving many "layer2" circuits, plus blob/kzg handling.
///   layer4: compression circuit of "layer3". Final layer circuit currently.

/// proof aggregation
mod aggregation;
/// This module implements `Batch` related data types.
/// A batch is a list of chunk.
mod batch;
/// blob struct and constants
mod blob;
// This module implements `Chunk` related data types.
// A chunk is a list of blocks.
mod chunk;
/// proof compression
mod compression;
/// Configurations
mod constants;
/// Core module for circuit assignment
mod core;
/// Parameters for compression circuit
mod param;
/// utilities
mod util;

#[cfg(test)]
mod tests;

pub use self::core::extract_proof_and_instances_with_pairing_check;
pub use aggregation::*;
pub use batch::BatchHash;
pub use chunk::ChunkInfo;
pub use compression::*;
pub use constants::MAX_AGG_SNARKS;
pub(crate) use constants::*;
pub use param::*;
