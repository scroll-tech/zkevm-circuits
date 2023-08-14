//! wrapping of mpt-circuit
use crate::{
    bytecode_circuit::bytecode_unroller::HASHBLOCK_BYTES_IN_FIELD,
    table::PoseidonTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{self},
};
//use bus_mapping::state_db::CodeDB;
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use hash_circuit::hash::{Hashable, PoseidonHashChip, PoseidonHashConfig, PoseidonHashTable};

/// re-wrapping for mpt circuit
#[derive(Default, Clone, Debug)]
pub struct PoseidonCircuit<F: Field>(pub(crate) PoseidonHashTable<F>, usize);

/// Circuit configuration argument ts
pub struct PoseidonCircuitConfigArgs {
    /// PoseidonTable
    pub poseidon_table: PoseidonTable,
}

/// re-wrapping for poseidon config
#[derive(Debug, Clone)]
pub struct PoseidonCircuitConfig<F: Field>(pub(crate) PoseidonHashConfig<F>);

const HASH_BLOCK_STEP_SIZE: usize = HASHBLOCK_BYTES_IN_FIELD * PoseidonTable::INPUT_WIDTH;

impl<F: Field> SubCircuitConfig<F> for PoseidonCircuitConfig<F> {
    type ConfigArgs = PoseidonCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { poseidon_table }: Self::ConfigArgs,
    ) -> Self {
        let poseidon_table = (
            poseidon_table.q_enable,
            [
                poseidon_table.hash_id,
                poseidon_table.input0,
                poseidon_table.input1,
                poseidon_table.control,
                poseidon_table.domain_spec,
                poseidon_table.heading_mark,
            ],
        );
        let conf = PoseidonHashConfig::configure_sub(meta, poseidon_table, HASH_BLOCK_STEP_SIZE);
        Self(conf)
    }
}

#[cfg(any(feature = "test", test))]
impl<F: Field> SubCircuit<F> for PoseidonCircuit<F> {
    type Config = PoseidonCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        let max_hashes = block.circuits_params.max_mpt_rows / F::hash_block_size();
        #[allow(unused_mut)]
        let mut poseidon_table_data: PoseidonHashTable<F> = PoseidonHashTable::default();
        // without any feature we just synthesis an empty poseidon circuit
        #[cfg(feature = "zktrie")]
        {
            let mpt_hashes = get_storage_poseidon_witness(block);
            if mpt_hashes.len() > max_hashes {
                log::error!(
                    "poseidon max_hashes: {:?} not enough. {:?} needed by zktrie proof",
                    max_hashes,
                    mpt_hashes.len()
                );
            }
            poseidon_table_data.fixed_inputs(&mpt_hashes);
        }
        #[cfg(feature = "poseidon-codehash")]
        {
            use crate::bytecode_circuit::bytecode_unroller::unroll_to_hash_input_default;
            for bytecode in block.bytecodes.values() {
                // must skip empty bytecode
                if !bytecode.bytes.is_empty() {
                    let unrolled_inputs =
                        unroll_to_hash_input_default::<F>(bytecode.bytes.iter().copied());
                    poseidon_table_data.stream_inputs(
                        &unrolled_inputs,
                        bytecode.bytes.len() as u64,
                        HASH_BLOCK_STEP_SIZE,
                    );
                }
            }
        }

        Self(poseidon_table_data, max_hashes)
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let mut path_hash_counter: std::collections::HashSet<[u8; 32]> = Default::default();
        let mut account_counter: std::collections::HashSet<[u8; 32]> = Default::default();
        let mut storage_counter: std::collections::HashSet<[u8; 32]> = Default::default();
        let mut key_counter: std::collections::HashSet<[u8; 32]> = Default::default();
        for smt_trace in &block.mpt_updates.smt_traces {
            // for a smt trace there are mutiple sources for hashes:
            // + account path, each layer (include the root) cost 1 hashes
            path_hash_counter.insert(smt_trace.account_path[0].root.0);
            for node in &smt_trace.account_path[0].path {
                path_hash_counter.insert(node.value.0);
            }
            for node in &smt_trace.account_path[1].path {
                path_hash_counter.insert(node.value.0);
            }

            // + the hashes required for leaf is dynamic and depended
            // on the type of mpt updates, here we suppose to count
            // all of the 4 hashes once
            if let Some(node) = smt_trace.account_path[0].leaf {
                account_counter.insert(node.value.0);
            }
            if let Some(node) = smt_trace.account_path[1].leaf {
                account_counter.insert(node.value.0);
            }

            // + and the address key
            key_counter.insert(smt_trace.account_key.0);

            // + state path, like account path
            if let Some(path) = &smt_trace.state_path[0] {
                for node in &path.path {
                    path_hash_counter.insert(node.value.0);
                }
            }

            if let Some(path) = &smt_trace.state_path[1] {
                for node in &path.path {
                    path_hash_counter.insert(node.value.0);
                }
            }

            // + state leaf
            if let Some(node) = smt_trace.state_path[0].as_ref().and_then(|pt| pt.leaf) {
                storage_counter.insert(node.value.0);
            }
            if let Some(node) = smt_trace.state_path[1].as_ref().and_then(|pt| pt.leaf) {
                storage_counter.insert(node.value.0);
            }

            // + the storage key
            if let Some(hash) = smt_trace.state_key {
                key_counter.insert(hash.0);
            }
        }

        let mut acc = path_hash_counter.len()
            + key_counter.len()
            + account_counter.len() * 4
            + storage_counter.len();

        for bytecode in block.bytecodes.values() {
            acc += bytecode.bytes.len() / HASH_BLOCK_STEP_SIZE + 1;
        }

        let acc = acc * F::hash_block_size();
        (acc, block.circuits_params.max_mpt_rows.max(acc))
    }

    /// Make the assignments to the MptCircuit, notice it fill mpt table
    /// but not fill hash table
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = PoseidonHashChip::<_, HASH_BLOCK_STEP_SIZE>::construct(
            config.0.clone(),
            &self.0,
            self.1,
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
        Self(Default::default(), self.1)
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let poseidon_table = PoseidonTable::construct(meta);

        let config =
            { PoseidonCircuitConfig::new(meta, PoseidonCircuitConfigArgs { poseidon_table }) };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[cfg(feature = "zktrie")]
fn get_storage_poseidon_witness<F: Field>(
    block: &crate::witness::Block<F>,
) -> Vec<([F; 2], F, Option<F>)> {
    use itertools::Itertools;
    use mpt_zktrie::mpt_circuits::{gadgets::mpt_update::hash_traces, types::Proof};
    hash_traces(
        &block
            .mpt_updates
            .proof_types
            .iter()
            .cloned()
            .zip_eq(block.mpt_updates.smt_traces.iter().cloned())
            .map(Proof::from)
            .collect_vec(),
    )
    .into_iter()
    .unique_by(|(inp, domain, hash)| {
        (
            inp.map(|f| f.to_bytes()),
            domain.to_bytes(),
            hash.to_bytes(),
        )
    })
    .map(|(inp, domain, hash)| (inp.map(F::from), domain.into(), Some(F::from(hash))))
    .collect()
}
