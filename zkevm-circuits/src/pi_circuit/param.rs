/// Fixed by the spec
pub(super) const BLOCK_LEN: usize = 9;
pub(super) const BYTE_POW_BASE: u64 = 256;
pub(super) const BLOCK_HEADER_BYTES_NUM: usize = 58;
pub(super) const KECCAK_DIGEST_SIZE: usize = 32;

pub(super) const RPI_CELL_IDX: usize = 0;
pub(super) const RPI_RLC_ACC_CELL_IDX: usize = 1;
pub(super) const RPI_LENGTH_ACC_CELL_IDX: usize = 2;

pub(super) const ZERO_BYTE_GAS_COST: u64 = 4;
pub(super) const NONZERO_BYTE_GAS_COST: u64 = 16;

/// Block table related offset constants
pub(super) const COINBASE_OFFSET: usize = 0;
pub(super) const TIMESTAMP_OFFSET: usize = 1;
pub(super) const BLOCK_NUM_OFFSET: usize = 2;
pub(super) const DIFFICULTY_OFFSET: usize = 3;
pub(super) const GAS_LIMIT_OFFSET: usize = 4;
pub(super) const BASE_FEE_OFFSET: usize = 5;
pub(super) const CHAIN_ID_OFFSET: usize = 6;
pub(super) const NUM_TXS_OFFSET: usize = 7;
pub(super) const CUM_NUM_TXS_OFFSET: usize = 8;
