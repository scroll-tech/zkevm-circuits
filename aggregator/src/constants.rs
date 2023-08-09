// A chain_id is u64 and uses 8 bytes
#[allow(dead_code)]
pub(crate) const CHAIN_ID_LEN: usize = 8;

// ================================
// hash parameters
// ================================

/// Digest length
pub(crate) const DIGEST_LEN: usize = 32;
/// Input length per round
pub(crate) const INPUT_LEN_PER_ROUND: usize = 136;

// Each round requires (NUM_ROUNDS+1) * DEFAULT_KECCAK_ROWS = 300 rows.
// This library is hard coded for this parameter.
// Modifying the following parameters may result into bugs.
// Adopted from keccak circuit
pub(crate) const DEFAULT_KECCAK_ROWS: usize = 12;
// Adopted from keccak circuit
pub(crate) const NUM_ROUNDS: usize = 24;
pub(crate) const ROWS_PER_ROUND: usize = (NUM_ROUNDS + 1) * DEFAULT_KECCAK_ROWS;

// TODO(ZZ): update to the right degree
#[allow(dead_code)]
pub(crate) const LOG_DEGREE: u32 = 19;

// ================================
// indices for hash table
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

// ================================
// aggregator parameters
// ================================

/// An decomposed accumulator consists of 12 field elements
pub(crate) const ACC_LEN: usize = 12;

/// number of limbs when decomposing a field element in the ECC chip
pub(crate) const LIMBS: usize = 3;
/// number of bits in each limb in the ECC chip
pub(crate) const BITS: usize = 88;

/// Max number of snarks to be aggregated in a chunk.
/// If the input size is less than this, dummy snarks
/// will be padded.
// TODO: update me(?)
pub const MAX_AGG_SNARKS: usize = 10;

/// The number of keccak rounds is the sum of
/// - batch public input hash: 2 rounds
/// - chunk's public input hash: 2 * MAX_AGG_SNARKS
/// - batch data hash: (32 * MAX_AGG_SNARKS)/136 = 3
pub(crate) const MAX_KECCAK_ROUNDS: usize = 2 * MAX_AGG_SNARKS + 5;
