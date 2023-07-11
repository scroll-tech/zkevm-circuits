/// proof aggregation
mod aggregation;
/// This module implements `Batch` related data types.
/// A batch is a list of chunk.
mod batch;
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
/// modules for RLCs
mod rlc;
/// utilities
mod util;

#[cfg(test)]
mod tests;

pub use aggregation::*;
pub use chunk::ChunkHash;
pub use compression::*;
pub(crate) use constants::*;
pub use param::*;
