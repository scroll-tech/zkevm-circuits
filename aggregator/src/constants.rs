// A chain_id is u64 and uses 8 bytes
#[allow(dead_code)]
pub(crate) const CHAIN_ID_LEN: usize = 8;

// TODO(ZZ): update to the right degree
#[allow(dead_code)]
pub(crate) const LOG_DEGREE: u32 = 19;

/// An decomposed accumulator consists of 12 field elements
pub(crate) const ACC_LEN: usize = 12;

/// number of limbs when decomposing a field element in the ECC chip
pub(crate) const LIMBS: usize = 3;
/// number of bits in each limb in the ECC chip
pub(crate) const BITS: usize = 88;
