//! This module implements circuits that aggregates public inputs of many blocks/txs into a single
//! one.

// This module implements `Chunk` related data types.
// A chunk is a list of blocks.
mod chunk;
// This module implements `MultiBatch` related data types.
// A multi_batch is a list of chunk.
mod multi_batch;
// Circuit implementation of `MultiBatch` public input hashes.
mod multi_batch_circuit;
// Subcircuit implementation of `MultiBatch` public input hashes.
mod multi_batch_sub_circuit;

// TODO(ZZ): update to the right degree
pub(crate) const LOG_DEGREE: u32 = 19;

// TODO(ZZ): update to the right size
pub(crate) const MAX_TXS: usize = 20;

#[cfg(test)]
mod tests;
