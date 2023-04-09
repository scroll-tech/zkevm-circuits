pub(crate) const MAX_DEGREE: usize = 3;
pub(crate) const ABSORB_LOOKUP_RANGE: usize = 3;
pub(crate) const THETA_C_LOOKUP_RANGE: usize = 6;
pub(crate) const RHO_PI_LOOKUP_RANGE: usize = 4;
pub(crate) const CHI_BASE_LOOKUP_RANGE: usize = 5;

pub(crate) const NUM_BITS_PER_BYTE: usize = 8;
pub(crate) const NUM_BYTES_PER_WORD: usize = 8;
pub(crate) const NUM_BITS_PER_WORD: usize = NUM_BYTES_PER_WORD * NUM_BITS_PER_BYTE;
pub(crate) const KECCAK_WIDTH: usize = 5 * 5;
pub(crate) const KECCAK_WIDTH_IN_BITS: usize = KECCAK_WIDTH * NUM_BITS_PER_WORD;
pub(crate) const NUM_ROUNDS: usize = 24;
pub(crate) const NUM_WORDS_TO_ABSORB: usize = 17;
pub(crate) const NUM_WORDS_TO_SQUEEZE: usize = 4;
pub(crate) const ABSORB_WIDTH_PER_ROW: usize = NUM_BITS_PER_WORD;
pub(crate) const ABSORB_WIDTH_PER_ROW_BYTES: usize = ABSORB_WIDTH_PER_ROW / NUM_BITS_PER_BYTE;
pub(crate) const RATE: usize = NUM_WORDS_TO_ABSORB * NUM_BYTES_PER_WORD;
pub(crate) const RATE_IN_BITS: usize = RATE * NUM_BITS_PER_BYTE;
pub(crate) const THETA_C_WIDTH: usize = 5 * NUM_BITS_PER_WORD;
pub(crate) const RHO_MATRIX: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];
pub(crate) const ROUND_CST: [u64; NUM_ROUNDS + 1] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
    0x0000000000000000, // absorb round
];
// Bit positions that have a non-zero value in `IOTA_ROUND_CST`.
pub(crate) const ROUND_CST_BIT_POS: [usize; 7] = [0, 1, 3, 7, 15, 31, 63];

// The number of bits used in the sparse word representation per bit
pub(crate) const BIT_COUNT: usize = 3;
// The base of the bit in the sparse word representation
pub(crate) const BIT_SIZE: usize = 2usize.pow(BIT_COUNT as u32);

// `a ^ ((~b) & c)` is calculated by doing `lookup[3 - 2*a + b - c]`
pub(crate) const CHI_BASE_LOOKUP_TABLE: [u8; 5] = [0, 1, 1, 0, 0];
// `a ^ ((~b) & c) ^ d` is calculated by doing `lookup[5 - 2*a - b + c - 2*d]`
pub(crate) const CHI_EXT_LOOKUP_TABLE: [u8; 7] = [0, 0, 1, 1, 0, 0, 1];
