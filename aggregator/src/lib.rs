// This module implements `Chunk` related data types.
// A chunk is a list of blocks.
mod chunk;
// This module implements `Batch` related data types.
// A batch is a list of chunk.
mod batch;
/// Core module for circuit assignment
mod core;
/// Parameters for compression circuit
mod param;
/// proof aggregation
mod proof_aggregation;
/// proof compression
mod proof_compression;
/// utilities
mod util;

#[cfg(test)]
mod tests;

pub use batch::BatchHash;
pub use chunk::ChunkHash;
pub use param::*;
pub use proof_aggregation::*;
pub use proof_compression::*;
