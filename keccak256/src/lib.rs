// Leave here until #105 uses all the functions that now are
// just used in tests

pub mod arith_helpers;
pub mod circuit;
pub mod common;
pub mod gate_helpers;
pub mod permutation;
// We build arith module to get test cases for the circuit
pub mod keccak_arith;
// We build plain module for the purpose of reviewing the circuit
pub mod plain;

lazy_static::lazy_static! {
    pub static ref EMPTY_HASH: [u8; 32] = {
        use std::convert::TryInto;

        let mut keccak = plain::Keccak::default();
        keccak.update(&[]);
        keccak.digest().try_into().unwrap()
    };
    pub static ref EMPTY_HASH_LE: [u8; 32] = {
        use std::convert::TryInto;
        use itertools::Itertools;

        EMPTY_HASH.iter().rev().cloned().collect_vec().try_into().unwrap()
    };
}
