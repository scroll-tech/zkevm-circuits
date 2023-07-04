#![allow(missing_docs)]
//! wrapping of mpt-circuit
use crate::{
    table::{LookupTable, MptTable, PoseidonTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed},
};
use itertools::Itertools;
use mpt_zktrie::mpt_circuits::{gadgets::poseidon::PoseidonLookup, mpt, types::Proof};

impl PoseidonLookup for PoseidonTable {
    fn lookup_columns_generic(&self) -> (Column<Fixed>, [Column<Advice>; 5]) {
        (
            self.q_enable,
            [
                self.hash_id,
                self.input0,
                self.input1,
                self.control,
                self.heading_mark,
            ],
        )
    }
}

/// Circuit wrapped with mpt table data
#[derive(Clone, Debug, Default)]
pub struct MptCircuit<F: Field> {
    row_limit: usize,
    proofs: Vec<Proof>,
    mpt_updates: witness::MptUpdates,
    _phantom: std::marker::PhantomData<F>,
}

/// Circuit configuration argument ts
pub struct MptCircuitConfigArgs {
    /// PoseidonTable
    pub poseidon_table: PoseidonTable,
    /// MptTable
    pub mpt_table: MptTable,
    /// Challenges
    pub challenges: Challenges,
}

/// re-wrapping for mpt config
#[derive(Clone)]
pub struct MptCircuitConfig<F: Field>(
    pub(crate) mpt::MptCircuitConfig,
    pub(crate) MptTable,
    std::marker::PhantomData<F>,
);

impl SubCircuitConfig<Fr> for MptCircuitConfig<Fr> {
    type ConfigArgs = MptCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<Fr>,
        Self::ConfigArgs {
            poseidon_table,
            mpt_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let conf = mpt::MptCircuitConfig::configure(meta, challenges.evm_word(), &poseidon_table);
        meta.lookup_any("updates in mpt table proven in mpt circuit", |meta| {
            mpt_table
                .table_exprs(meta)
                .into_iter()
                .zip_eq(conf.lookup_exprs(meta))
                .collect()
        });

        Self(conf, mpt_table, Default::default())
    }
}

#[cfg(any(feature = "test", test))]
impl SubCircuit<Fr> for MptCircuit<Fr> {
    type Config = MptCircuitConfig<Fr>;

    fn new_from_block(block: &witness::Block<Fr>) -> Self {
        let traces: Vec<_> = block
            .mpt_updates
            .proof_types
            .iter()
            .cloned()
            .zip_eq(block.mpt_updates.smt_traces.iter().cloned())
            .collect();

        Self {
            proofs: traces.into_iter().map(Proof::from).collect(),
            row_limit: block.circuits_params.max_mpt_rows,
            mpt_updates: block.mpt_updates.clone(),
            ..Default::default()
        }
    }

    fn min_num_rows_block(block: &witness::Block<Fr>) -> (usize, usize) {
        // FIXME
        (
            block.circuits_params.max_mpt_rows,
            block.circuits_params.max_mpt_rows,
        )
    }

    /// Make the assignments to the MptCircuit, notice it fill mpt table
    /// but not fill hash table
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<Fr>>,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), Error> {
        config.0.assign(layouter, &self.proofs, self.row_limit)?;
        config.1.load(
            layouter,
            &self.mpt_updates,
            self.row_limit,
            challenges.evm_word(),
        )?;
        Ok(())
    }

    /// powers of randomness for instance columns
    fn instance(&self) -> Vec<Vec<Fr>> {
        vec![]
    }
}

#[cfg(any(feature = "test", test))]
impl Circuit<Fr> for MptCircuit<Fr> {
    type Config = (MptCircuitConfig<Fr>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            row_limit: self.row_limit,
            ..Default::default()
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let poseidon_table = PoseidonTable::dev_construct(meta);
        let mpt_table = MptTable::construct(meta);

        let config = {
            MptCircuitConfig::new(
                meta,
                MptCircuitConfigArgs {
                    poseidon_table,
                    mpt_table,
                    challenges,
                },
            )
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}
