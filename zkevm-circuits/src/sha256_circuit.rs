//! The SHA256 circuit is a wrapper for the circuit in sha256 crate and serve for precompile SHA-256
//! calls

use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Any, Column, ConstraintSystem, Error, Expression},
};

mod circuit;
#[cfg(test)]
mod test;

pub use circuit::CircuitConfig;
use circuit::{Hasher, SHA256Table as TableTrait};
pub use halo2_gadgets::sha256::BLOCK_SIZE;

use crate::{
    table::{LookupTable, SHA256Table},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use bus_mapping::circuit_input_builder::SHA256;
use eth_types::Field;

impl TableTrait for SHA256Table {
    fn cols(&self) -> [Column<Any>; 5] {
        let tbl_cols = <Self as LookupTable<Fr>>::columns(self);
        [
            tbl_cols[0],
            tbl_cols[2],
            tbl_cols[3],
            tbl_cols[4],
            tbl_cols[1],
        ]
    }
}

/// Config args for SHA256 circuit
#[derive(Debug, Clone)]
pub struct CircuitConfigArgs<F: Field> {
    /// SHA256 Table
    pub sha256_table: SHA256Table,
    /// Challenges randomness
    pub challenges: Challenges<Expression<F>>,
}

impl SubCircuitConfig<Fr> for CircuitConfig {
    type ConfigArgs = CircuitConfigArgs<Fr>;

    /// Return a new ModExpCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<Fr>,
        Self::ConfigArgs {
            sha256_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        Self::configure(meta, sha256_table, challenges.keccak_input())
    }
}

/// ModExp circuit for precompile modexp
#[derive(Clone, Debug, Default)]
pub struct SHA256Circuit<F: Field>(Vec<SHA256>, usize, std::marker::PhantomData<F>);

const TABLE16_BLOCK_ROWS: usize = 2114;
const BLOCK_SIZE_IN_BYTES: usize = BLOCK_SIZE * 4;

impl<F: Field> SHA256Circuit<F> {
    fn expected_rows(&self) -> usize {
        self.0
            .iter()
            .map(|evnt| (evnt.input.len()) + 9 / BLOCK_SIZE_IN_BYTES + 1)
            .reduce(|acc, v| acc + v)
            .unwrap_or_default()
            * TABLE16_BLOCK_ROWS
    }

    fn with_row_limit(self, row_limit: usize) -> Self {
        if row_limit != 0 {
            let expected_rows = self.expected_rows();
            assert!(
                expected_rows <= row_limit,
                "no enough rows for sha256 circuit, expected {expected_rows}, limit {row_limit}",
            );
            log::info!("sha256 circuit work with maxium {} rows", row_limit);
        }
        let inp = self.0;
        let block_limit = row_limit / TABLE16_BLOCK_ROWS;

        Self(inp, block_limit, Default::default())
    }
}

impl SubCircuit<Fr> for SHA256Circuit<Fr> {
    type Config = CircuitConfig;

    fn unusable_rows() -> usize {
        2
    }

    fn new_from_block(block: &witness::Block<Fr>) -> Self {
        Self(block.get_sha256(), 0, Default::default())
            .with_row_limit(block.circuits_params.max_keccak_rows)
    }

    fn min_num_rows_block(block: &witness::Block<Fr>) -> (usize, usize) {
        let real_row = Self(block.get_sha256(), 0, Default::default()).expected_rows();

        (
            real_row,
            real_row
                .max(block.circuits_params.max_keccak_rows)
                .max(4096),
        )
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<Fr>>,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chng = challenges.keccak_input();
        let mut hasher = Hasher::new(config.clone(), layouter)?;

        for hash_event in &self.0 {
            hasher.update(layouter, chng, &hash_event.input)?;

            let digest = hasher.finalize(layouter, chng)?;
            let ref_digest = hash_event
                .digest
                .chunks_exact(4)
                .map(|bt| bt.iter().fold(0u32, |sum, v| sum * 256 + *v as u32))
                .collect::<Vec<_>>();
            for (w, check) in digest.into_iter().zip(ref_digest) {
                w.0.assert_if_known(|digest_word| *digest_word == check);
            }

            if hasher.blocks() > self.1 {
                log::error!("handled 512-bit block exceed limit ({})", self.1);
                return Err(Error::Synthesis);
            }
        }

        // paddings
        for _i in hasher.blocks()..self.1 {
            hasher.update(layouter, chng, &[])?;
            hasher.finalize(layouter, chng)?;
        }

        Ok(())
    }
}
