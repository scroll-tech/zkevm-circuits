// This module implements `Chunk` related data types.
// A chunk is a list of blocks.
mod chunk;
/// proof compression
mod compression;
/// Core module for circuit assignment
mod core;
/// Parameters for compression circuit
mod param;

#[cfg(test)]
mod tests;

pub use chunk::ChunkHash;
pub use compression::*;
pub use param::*;

// A chain_id is u64 and uses 8 bytes
#[allow(dead_code)]
pub(crate) const CHAIN_ID_LEN: usize = 8;

// TODO(ZZ): update to the right degree
#[allow(dead_code)]
pub(crate) const LOG_DEGREE: u32 = 19;
