// Step dimension
pub const STEP_WIDTH: usize = 32;
pub const STEP_HEIGHT: usize = 10;
pub const NUM_CELLS_STEP_STATE: usize = 10;

/// The maximum number of bytes that a field element
/// can be broken down into without causing the value it
/// represents to overflow a single field element.
pub const MAX_BYTES_FIELD: usize = 31;

pub const STACK_START_IDX: usize = 1024;
pub const MAX_GAS_SIZE_IN_BYTES: usize = 8;
// Number of bytes that will be used of the address word.
// If any of the other more signficant bytes are used it will
// always result in an out-of-gas error.
pub const NUM_ADDRESS_BYTES_USED: usize = 5; // TODO:
pub const MAX_MEMORY_SIZE_IN_BYTES: usize = 5;
pub const MAX_STORAGE_SIZE_IN_BYTES: usize = 32;
// Number of bytes that will be used of the JUMP* destination or code copy range
// check. Although the deployed code has maximum size of 0x6000, the size of
// a creation transaction could be 128KB, which needs 3 bytes to cover.
pub const MAX_CODE_SIZE_IN_BYTES: usize = 3;
