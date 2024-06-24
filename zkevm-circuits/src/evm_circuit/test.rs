#![allow(unused_imports)]
pub use super::EvmCircuit;
use crate::evm_circuit::{detect_fixed_table_tags, witness::Block};

use crate::util::Field;
use eth_types::Word;
use rand::{
    distributions::uniform::{SampleRange, SampleUniform},
    random, thread_rng, Rng,
};

pub(crate) fn rand_range<T, R>(range: R) -> T
where
    T: SampleUniform,
    R: SampleRange<T>,
{
    thread_rng().gen_range(range)
}

pub(crate) fn rand_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|_| random()).collect()
}

pub(crate) fn rand_bytes_array<const N: usize>() -> [u8; N] {
    [(); N].map(|_| random())
}

pub(crate) fn rand_word() -> Word {
    Word::from_big_endian(&rand_bytes_array::<32>())
}
