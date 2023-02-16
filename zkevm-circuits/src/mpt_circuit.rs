//! wrapping of mpt-circuit
use crate::{
    table::{MptTable, PoseidonTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};
use mpt_zktrie::hash::Hashable;
use mpt_zktrie::{operation::AccountOp, EthTrie, EthTrieCircuit, EthTrieConfig};

/// re-wrapping for mpt circuit
#[derive(Default, Clone, Debug)]
pub struct MptCircuit<F: Field>(pub(crate) EthTrieCircuit<F, false>);

/// Circuit configuration argumen ts
pub struct MptCircuitConfigArgs<F: Field> {
    /// PoseidonTable
    pub poseidon_table: PoseidonTable,
    /// MptTable
    pub mpt_table: MptTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

/// re-wrapping for mpt config
#[derive(Debug, Clone)]
pub struct MptCircuitConfig(pub(crate) EthTrieConfig);

impl<F: Field> SubCircuitConfig<F> for MptCircuitConfig {
    type ConfigArgs = MptCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            poseidon_table,
            mpt_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let conf = EthTrieConfig::configure_sub(
            meta,
            mpt_table.0,
            poseidon_table.0,
            challenges.evm_word(),
        );
        Self(conf)
    }
}

#[cfg(any(feature = "test", test))]
impl<F: Field + Hashable> SubCircuit<F> for MptCircuit<F> {
    type Config = MptCircuitConfig;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        let mut eth_trie: EthTrie<F> = Default::default();
        eth_trie.add_ops(
            block
                .mpt_updates
                .smt_traces
                .iter()
                .map(|tr| AccountOp::try_from(tr).unwrap()),
        );
        let (circuit, _) = eth_trie.to_circuits(
            (
                // notice we do not use the accompanied hash circuit so just assign any size
                100usize,
                Some(block.evm_circuit_pad_to),
            ),
            &block.mpt_updates.proof_types,
        );
        MptCircuit(circuit)
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let mut eth_trie: EthTrie<F> = Default::default();
        eth_trie.add_ops(
            block
                .mpt_updates
                .smt_traces
                .iter()
                .map(|tr| AccountOp::try_from(tr).unwrap()),
        );
        let (mpt_rows, _) = eth_trie.use_rows();
        (mpt_rows, block.circuits_params.max_rws.max(mpt_rows))
    }

    /// Make the assignments to the MptCircuit, notice it fill mpt table
    /// but not fill hash table
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.0.load_mpt_table(
            layouter,
            challenges.evm_word().inner,
            self.0.ops.as_slice(),
            self.0.mpt_table.iter().copied(),
            self.0.calcs,
        )?;
        config
            .0
            .synthesize_core(layouter, self.0.ops.iter(), self.0.calcs)?;
        Ok(())
    }

    /// powers of randomness for instance columns
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
}

#[cfg(any(feature = "test", test))]
impl<F: Field + Hashable> Circuit<F> for MptCircuit<F> {
    type Config = (MptCircuitConfig, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let mut out = Self::default();
        out.0.calcs = self.0.calcs;
        out
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let poseidon_table = PoseidonTable::dev_construct(meta);
        let mpt_table = MptTable::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);

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
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        config.0.dev_load_hash_table(
            &mut layouter,
            self.0.ops.iter().flat_map(|op| op.hash_traces()),
            self.0.calcs,
        )?;
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}
