//! This module implements circuits that aggregates public inputs of many chunks into a single
//! one.
//!
//! # Spec
//!
//! A chunk is a list of continuous blocks. It consists of 4 hashes:
//! - state root before this chunk
//! - state root after this chunk
//! - the withdraw root of this chunk
//! - the data hash of this chunk
//! Those 4 hashes are obtained from the caller.
//!
//! A chunk's public input hash is then derived from the above 4 attributes via
//!
//! - chunk_pi_hash   := keccak(chain_id || prev_state_root || post_state_root || withdraw_root ||
//!   chunk_data_hash)
//!
//! A batch is a list of continuous chunks. It consists of 2 hashes
//!
//! - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
//!
//! - batch_pi_hash   := keccak(chain_id || chunk_0.prev_state_root || chunk_k-1.post_state_root ||
//!   chunk_k-1.withdraw_root || batch_data_hash)
//!
//! Note that chain_id is used for all public input hashes. But not for any data hashes.
//!
//! # Circuit
//!
//! A BatchHashCircuit asserts that the batch is well-formed.
//!
//! ## Public Input
//! The public inputs of the circuit (132 Field elements) is constructed as
//! - first_chunk_prev_state_root: 32 Field elements
//! - last_chunk_post_state_root: 32 Field elements
//! - last_chunk_withdraw_root: 32 Field elements
//! - batch_public_input_hash: 32 Field elements
//! - chain_id: 8 Field elements
//!
//! ## Constraints
//! The circuit attests the following statements:
//!
//! 1. all hashes are computed correctly
//! 2. the relations between hash preimages and digests are satisfied
//!     - batch_data_hash is part of the input to compute batch_pi_hash
//!     - batch_pi_hash used same roots as chunk_pi_hash
//!     - same data_hash is used to compute batch_data_hash and chunk_pi_hash for all chunks
//!     - chunks are continuous: they are linked via the state roots
//!     - all hashes uses a same chain_id
//! 3. the hash data matches the circuit's public input (132 field elements) above
//!
//! # Example
//!
//! See tests::test_pi_aggregation_circuit

// Circuit implementation of `BatchHashCircuit`.
mod circuit;
// CircuitExt implementation of `BatchHashCircuit`.
mod circuit_ext;
// Circuit and SubCircuit configurations
mod config;

pub use crate::{BatchHash, ChunkHash};
pub use circuit::{BatchHashCircuit, BatchHashCircuitPublicInput};
pub use config::{BatchCircuitConfig, BatchCircuitConfigArgs};

// TODO(ZZ): update to the right degree
pub(crate) const LOG_DEGREE: u32 = 19;

// A chain_id is u64 and uses 8 bytes
pub(crate) const CHAIN_ID_LEN: usize = 8;

// Each round requires (NUM_ROUNDS+1) * DEFAULT_KECCAK_ROWS = 300 rows.
// This library is hard coded for this parameter.
// Modifying the following parameters may result into bugs.
// Adopted from keccak circuit
pub(crate) const DEFAULT_KECCAK_ROWS: usize = 12;
// Adopted from keccak circuit
pub(crate) const NUM_ROUNDS: usize = 24;
