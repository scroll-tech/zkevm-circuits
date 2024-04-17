/// Number of bits to represent a byte.
pub const N_BITS_PER_BYTE: usize = 8;

/// Number of bytes used to specify block header.
pub const N_BLOCK_HEADER_BYTES: usize = 3;

/// Constants for zstd-compressed block
pub const N_MAX_LITERAL_HEADER_BYTES: usize = 3;
/// Maximum bytes for the jump table
pub const N_JUMP_TABLE_BYTES: usize = 6;
/// Maximum bytes for the FSE representation
pub const N_MAX_LITERAL_FSE_BYTES: usize = 8;

/// Maximum number of symbols (weights), i.e. symbol in [0, N_MAX_SYMBOLS).
pub const N_MAX_SYMBOLS: usize = 8;

/// Number of bits used to represent the symbol in binary form. This will be used as a helper
/// gadget to form equality constraints over the symbol's value.
pub const N_BITS_SYMBOL: usize = 3;

/// Number of bits used to represent the tag in binary form.
pub const N_BITS_ZSTD_TAG: usize = 4;
