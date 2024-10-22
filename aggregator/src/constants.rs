// A chain_id is u64 and uses 8 bytes
pub(crate) const CHAIN_ID_LEN: usize = 8;

// ================================
// hash parameters
// ================================

/// Digest length
pub(crate) const DIGEST_LEN: usize = 32;

// TODO: make this dynamic
pub(crate) const LOG_DEGREE: u32 = 21;

// ================================
// indices for chunk pi hash table
// ================================
//
// the preimages are arranged as
// - chain_id:          8 bytes
// - prev_state_root    32 bytes
// - post_state_root    32 bytes
// - withdraw_root      32 bytes
// - chunk_data_hash    32 bytes
// - chunk_tx_data_hash 32 bytes

pub(crate) const CHUNK_CHAIN_ID_INDEX: usize = 0;
pub(crate) const PREV_STATE_ROOT_INDEX: usize = 8;
pub(crate) const POST_STATE_ROOT_INDEX: usize = 40;
pub(crate) const WITHDRAW_ROOT_INDEX: usize = 72;
pub(crate) const CHUNK_DATA_HASH_INDEX: usize = 104;
pub(crate) const CHUNK_TX_DATA_HASH_INDEX: usize = 136;

// ================================
// indices for batch hash table
// ================================
//
// the preimages are arranged as
// - version:                  1 byte
// - batch_index:              8 bytes
// - l1_message_popped         8 bytes
// - total_l1_message_popped   8 bytes
// - data_hash                 32 bytes
// - blob_versioned_hash       32 bytes
// - parent_batch_hash         32 bytes
// - last_block_timestamp      8 bytes
// - z                         32 bytes
// - y                         32 bytes

pub(crate) const BATCH_DATA_HASH_OFFSET: usize = 25;
pub(crate) const BATCH_BLOB_VERSIONED_HASH_OFFSET: usize = 57;
pub(crate) const BATCH_PARENT_BATCH_HASH: usize = 89;
pub(crate) const BATCH_Z_OFFSET: usize = 129;
pub(crate) const BATCH_Y_OFFSET: usize = 161;

// ================================
// indices for public inputs
// ================================
//
// - parent state root (2 cells: hi, lo)
// - parent batch hash ..
// - current state root ..
// - current batch hash ..
// - chain id (1 Fr cell)
// - current withdraw root ..
pub(crate) const PI_PARENT_STATE_ROOT: usize = ACC_LEN;
pub(crate) const PI_PARENT_BATCH_HASH: usize = ACC_LEN + 2;
pub(crate) const PI_CURRENT_STATE_ROOT: usize = ACC_LEN + 4;
pub(crate) const PI_CURRENT_BATCH_HASH: usize = ACC_LEN + 6;
pub(crate) const PI_CHAIN_ID: usize = ACC_LEN + 8;
pub(crate) const PI_CURRENT_WITHDRAW_ROOT: usize = ACC_LEN + 9;

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
pub const MAX_AGG_SNARKS: usize = 45;
