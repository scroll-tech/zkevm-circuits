use crate::evm_circuit::param::N_BYTES_ACCOUNT_ADDRESS;

// We use 16 bit limbs for the the account address (key 2) so that key0, key1,
// key2, key3, and the first 4 bytes of key4 fit inside a field element.
pub(super) const N_LIMBS_ACCOUNT_ADDRESS: usize = N_BYTES_ACCOUNT_ADDRESS / 2;
