#![allow(clippy::doc_lazy_continuation)]
/// proof aggregation
mod aggregation;
/// This module implements `Batch` related data types.
/// A batch is a list of chunk.
mod batch;
/// blob struct and constants
mod blob;
/// Config to recursive aggregate multiple aggregations
mod recursion;
// This module implements `Chunk` related data types.
// A chunk is a list of blocks.
mod chunk;
/// proof compression
mod compression;
/// Configurations
mod constants;
/// Core module for circuit assignment
mod core;
/// EIP-4844 related utils.
pub mod eip4844;
/// Parameters for compression circuit
mod param;
/// utilities
mod util;

#[cfg(test)]
mod tests;

pub use self::core::extract_proof_and_instances_with_pairing_check;
pub use aggregation::*;
pub use batch::{BatchHash, BatchHeader};
pub use blob::BatchData;
pub use chunk::ChunkInfo;
pub use compression::*;
pub use constants::MAX_AGG_SNARKS;
pub(crate) use constants::*;
pub use param::*;
pub use recursion::*;
