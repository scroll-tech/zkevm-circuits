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

#[cfg(test)]
mod tests;

pub use chunk::ChunkHash;
pub use compression::*;
pub(crate) use constants::*;
pub use param::*;
