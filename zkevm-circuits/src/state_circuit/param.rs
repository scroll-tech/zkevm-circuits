use crate::evm_circuit::param::N_BYTES_ACCOUNT_ADDRESS;

pub(super) const N_LIMBS_ACCOUNT_ADDRESS: usize = N_BYTES_ACCOUNT_ADDRESS / 2;

pub(super) const N_BITS_TAG: u32 = 4;
pub(super) const N_BITS_ID: u32 = 32;
pub(super) const N_BITS_ADDRESS: u32 = 160;
pub(super) const N_BITS_FIELD_TAG: u32 = 5;
