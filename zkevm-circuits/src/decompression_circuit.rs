//! Circuit implementation for verifying assignments to the RLP finite state machine.

use std::marker::PhantomData;

use eth_types::Field;
use gadgets::comparator::ComparatorConfig;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression},
};

use crate::{
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::Block,
};

/// Tables, challenge API used to configure the Decompression circuit.
pub struct DecompressionCircuitConfigArgs<F> {
    /// Challenge API.
    pub challenges: Challenges<Expression<F>>,
}

/// The Decompression circuit's configuration. The columns used to constrain the Decompression
/// logic are defined here. Refer the [design doc][doclink] for design decisions and specifications.
///
/// [doclink]: https://www.notion.so/scrollzkp/zstd-in-circuit-decompression-23f8036538e440ebbbc17c69033d36f5?pvs=4
#[derive(Clone, Debug)]
pub struct DecompressionCircuitConfig<F> {
    /// The index of the byte being processed within the current frame. The first byte has a
    /// byte_idx == 1. byte_idx follows the relation byte_idx' >= byte_idx. That is, byte_idx is
    /// increasing, but can repeat over two or more rows if we are decoding bits from the same byte
    /// over those consecutive rows. For instance, if a Huffman Code bitstring is 2 bits long,
    /// we might end up decoding on the same byte_idx at the most 4 times.
    byte_idx: Column<Advice>,
    /// A helper gadget to check the relation: byte_idx' >= byte_idx. We also need this GTE check
    /// to know when 2 rows must be identical with their decoded data.
    byte_idx_cmp: ComparatorConfig<F, 8>,

    _data: PhantomData<F>,
}

impl<F: Field> SubCircuitConfig<F> for DecompressionCircuitConfig<F> {
    type ConfigArgs = DecompressionCircuitConfigArgs<F>;

    fn new(_meta: &mut ConstraintSystem<F>, _args: Self::ConfigArgs) -> Self {
        unimplemented!()
    }
}

/// The Decompression circuit decodes an instance of zstd compressed data.
#[derive(Clone, Debug)]
pub struct DecompressionCircuit<F> {
    _data: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for DecompressionCircuit<F> {
    type Config = DecompressionCircuitConfig<F>;

    fn new_from_block(_block: &Block<F>) -> Self {
        unimplemented!()
    }

    fn min_num_rows_block(_block: &Block<F>) -> (usize, usize) {
        unimplemented!()
    }

    fn synthesize_sub(
        &self,
        _config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        _layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}
