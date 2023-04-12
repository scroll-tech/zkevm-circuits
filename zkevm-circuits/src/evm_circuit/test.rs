#![allow(unused_imports)]
pub use super::EvmCircuit;
use crate::evm_circuit::{detect_fixed_table_tags, witness::Block};

use eth_types::{Field, Word};
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

impl<F: Field> EvmCircuit<F> {
    pub fn get_test_cicuit_from_block(block: Block<F>) -> Self {
        let fixed_table_tags = detect_fixed_table_tags(&block);
        EvmCircuit::<F>::new_dev(block, fixed_table_tags)
    }
}
