// Step dimension
pub(crate) const STEP_WIDTH: usize = 32;
/// Step height
pub const STEP_HEIGHT: usize = 16;
pub(crate) const N_CELLS_STEP_STATE: usize = 10;

/// Maximum number of bytes that an integer can fit in field without wrapping
/// around.
pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

// Number of bytes an EVM word has.
pub(crate) const N_BYTES_WORD: usize = 32;

// Number of bytes an u64 has.
pub(crate) const N_BYTES_U64: usize = 8;

pub(crate) const N_BYTES_ACCOUNT_ADDRESS: usize = 20;

// Number of bytes that will be used of the memory address and size.
// If any of the other more signficant bytes are used it will always result in
// an out-of-gas error.
pub(crate) const N_BYTES_MEMORY_ADDRESS: usize = 5;
pub(crate) const N_BYTES_MEMORY_WORD_SIZE: usize = 4;

pub(crate) const STACK_CAPACITY: usize = 1024;

// Number of bytes that will be used of prorgam counter. Although the maximum
// size of execution bytecode could be at most 128kB due to the size limit of a
// transaction, which could be covered by 3 bytes, we still support program
// counter to u64 as go-ethereum in case transaction size is allowed larger in
// the future.
pub(crate) const N_BYTES_PROGRAM_COUNTER: usize = N_BYTES_U64;

// Number of bytes that will be used for a tx's gas field.
pub(crate) const N_BYTES_GAS: usize = N_BYTES_U64;

// Number of bytes that will be used for call data's size.
pub(crate) const N_BYTES_CALLDATASIZE: usize = N_BYTES_U64;
