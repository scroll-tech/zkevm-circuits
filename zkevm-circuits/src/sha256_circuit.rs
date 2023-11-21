//! The SHA256 circuit is a wrapper for the circuit in sha256 crate and serve for precompile SHA-256
//! calls

use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Any, Column, ConstraintSystem, Error, Expression},
};

use sha256_circuit::{
    circuit::{Hasher, SHA256Table as TableTrait},
    BLOCK_SIZE,
};

pub use sha256_circuit::circuit::CircuitConfig;

use crate::{
    table::{LookupTable, SHA256Table},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use bus_mapping::circuit_input_builder::SHA256;
use eth_types::Field;

impl TableTrait for SHA256Table {
    fn cols(&self) -> [Column<Any>; 4] {
        <Self as LookupTable<Fr>>::columns(self)
            .as_slice()
            .try_into()
            .expect("return 4 cols")
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
pub struct SHA256Circuit<F: Field>(Vec<SHA256>, std::marker::PhantomData<F>);

const TABLE16_BLOCK_ROWS: usize = 2101;
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
}

impl SubCircuit<Fr> for SHA256Circuit<Fr> {
    type Config = CircuitConfig;

    fn unusable_rows() -> usize {
        2
    }

    fn new_from_block(block: &witness::Block<Fr>) -> Self {
        let row_limit = block.circuits_params.max_keccak_rows;

        let ret = Self(block.get_sha256(), Default::default());

        if row_limit != 0 {
            let expected_rows = ret.expected_rows();
            assert!(
                expected_rows <= row_limit,
                "no enough rows for sha256 circuit, expected {expected_rows}, limit {row_limit}",
            );
            log::info!("sha256 circuit work with maxium {} rows", row_limit);
        }

        ret
    }

    fn min_num_rows_block(block: &witness::Block<Fr>) -> (usize, usize) {
        let real_row = Self(block.get_sha256(), Default::default()).expected_rows();

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
            // TODO: verify output and digest in event
            let _ = hasher.finalize(layouter, chng)?;
        }

        Ok(())
    }
}
