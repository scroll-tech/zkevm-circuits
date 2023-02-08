//! wrapping of mpt-circuit
use crate::{
    bytecode_circuit::bytecode_unroller::{self, HASHBLOCK_BYTES_IN_FIELD},
    table::PoseidonTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use mpt_zktrie::hash::{Hashable, PoseidonHashChip, PoseidonHashConfig, PoseidonHashTable};

/// re-wrapping for mpt circuit
#[derive(Default, Clone, Debug)]
pub struct PoseidonCircuit<F: Field>(pub(crate) PoseidonHashTable<F>, usize);

/// Circuit configuration argumen ts
pub struct PoseidonCircuitConfigArgs {
    /// PoseidonTable
    pub poseidon_table: PoseidonTable,
}

/// re-wrapping for poseidon config
#[derive(Debug, Clone)]
pub struct PoseidonCircuitConfig<F: Field>(pub(crate) PoseidonHashConfig<F>);

impl<F: Field> SubCircuitConfig<F> for PoseidonCircuitConfig<F> {
    type ConfigArgs = PoseidonCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { poseidon_table }: Self::ConfigArgs,
    ) -> Self {
        let conf =
            PoseidonHashConfig::configure_sub(meta, poseidon_table.0, HASHBLOCK_BYTES_IN_FIELD);
        Self(conf)
    }
}

#[cfg(any(feature = "test", test))]
impl<F: Field> SubCircuit<F> for PoseidonCircuit<F> {
    type Config = PoseidonCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        let max_hashes = block.evm_circuit_pad_to / F::hash_block_size();
        #[allow(unused_mut)]
        let mut poseidon_table_data = PoseidonHashTable::default();
        // without any feature we just synthesis an empty poseidon circuit
        #[cfg(feature = "zktrie")]
        {
            use mpt_zktrie::{operation::AccountOp, EthTrie};
            let mut eth_trie: EthTrie<F> = Default::default();
            eth_trie.add_ops(
                block
                    .mpt_updates
                    .smt_traces
                    .iter()
                    .map(|tr| AccountOp::try_from(tr).unwrap()),
            );
            poseidon_table_data.constant_inputs_with_check(eth_trie.hash_traces());
        }
        #[cfg(feature = "poseidon-codehash")]
        {
            use bytecode_unroller::unroll_to_hash_input_default;
            for (_, bytecode) in &block.bytecodes {
                poseidon_table_data.stream_inputs(
                    &unroll_to_hash_input_default::<F>(bytecode.bytes.iter().copied()),
                    bytecode.bytes.len() as u64,
                    HASHBLOCK_BYTES_IN_FIELD,
                );
            }
        }

        Self(poseidon_table_data, max_hashes)
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let max_hashes = block.evm_circuit_pad_to / F::hash_block_size();
        let acc = 0;
        #[cfg(feature = "zktrie")]
        let acc = {
            let mut cnt = acc;
            use mpt_zktrie::{operation::AccountOp, EthTrie};
            let mut eth_trie: EthTrie<F> = Default::default();
            eth_trie.add_ops(
                block
                    .mpt_updates
                    .smt_traces
                    .iter()
                    .map(|tr| AccountOp::try_from(tr).unwrap()),
            );
            cnt += eth_trie.hash_traces().count();
            cnt
        };
        #[cfg(feature = "poseidon-codehash")]
        let acc = {
            let mut cnt = acc;
            use bytecode_unroller::unroll_to_hash_input_default;
            for (_, bytecode) in &block.bytecodes {
                cnt += unroll_to_hash_input_default::<F>(bytecode.bytes.iter().copied()).len();
            }
            cnt
        };
        (acc, max_hashes.max(acc))
    }

    /// Make the assignments to the MptCircuit, notice it fill mpt table
    /// but not fill hash table
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        // for single codehash we sitll use keccak256(nil)
        use crate::evm_circuit::util::rlc;
        use keccak256::EMPTY_HASH_LE;
        let empty_hash = challenges
            .evm_word()
            .map(|challenge| rlc::value(EMPTY_HASH_LE.as_ref(), challenge));

        let chip =
            PoseidonHashChip::<_, { bytecode_unroller::HASHBLOCK_BYTES_IN_FIELD }>::construct(
                config.0.clone(),
                &self.0,
                self.1,
                false,
                empty_hash.inner,
            );

        chip.load(layouter)
    }

    /// powers of randomness for instance columns
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
}

#[cfg(any(feature = "test", test))]
impl<F: Field + Hashable> Circuit<F> for PoseidonCircuit<F> {
    type Config = (PoseidonCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let mut out = Self::default();
        out.1 = self.1;
        out
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let poseidon_table = PoseidonTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let config =
            { PoseidonCircuitConfig::new(meta, PoseidonCircuitConfigArgs { poseidon_table }) };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}
