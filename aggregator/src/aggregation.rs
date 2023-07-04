/// Circuit implementation of aggregation circuit.
mod circuit;
/// CircuitExt implementation of compression circuit.
mod circuit_ext;
/// Config for aggregation circuit
mod config;
/// utilities
mod util;

pub use circuit::AggregationCircuit;
pub use config::AggregationConfig;

// ================================
// indices for hash bytes
// ================================
//
// the preimages are arranged as
// - chain_id:          8 bytes
// - prev_state_root    32 bytes
// - post_state_root    32 bytes
// - withdraw_root      32 bytes
// - chunk_data_hash    32 bytes
//

pub(crate) const PREV_STATE_ROOT_INDEX: usize = 8;
pub(crate) const POST_STATE_ROOT_INDEX: usize = 40;
pub(crate) const WITHDRAW_ROOT_INDEX: usize = 72;
pub(crate) const CHUNK_DATA_HASH_INDEX: usize = 104;

// Each round requires (NUM_ROUNDS+1) * DEFAULT_KECCAK_ROWS = 300 rows.
// This library is hard coded for this parameter.
// Modifying the following parameters may result into bugs.
// Adopted from keccak circuit
pub(crate) const DEFAULT_KECCAK_ROWS: usize = 12;
// Adopted from keccak circuit
pub(crate) const NUM_ROUNDS: usize = 24;

/// Max number of snarks to be aggregated in a chunk.
/// If the input size is less than this, dummy snarks
/// will be padded.
// TODO: update me
pub const MAX_AGG_SNARKS: usize = 4;
