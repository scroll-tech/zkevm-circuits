//! Subcircuit implementation of `MultiBatch` public input hashes.

use std::marker::PhantomData;

use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, Expression},
};

use crate::{
    keccak_circuit::{KeccakCircuitConfig, KeccakCircuitConfigArgs},
    pi_agg_circuit::{LOG_DEGREE, MAX_TXS},
    table::KeccakTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
};

use super::multi_batch_circuit::{MultiBatchCircuit, MultiBatchCircuitConfig};

#[derive(Clone, Debug)]
pub struct MultiBatchCircuitConfigArgs<F: Field> {
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for MultiBatchCircuitConfig<F> {
    type ConfigArgs = MultiBatchCircuitConfigArgs<F>;

    /// Return a new MultiBatchCircuitConfig
    fn new(meta: &mut ConstraintSystem<F>, config_args: Self::ConfigArgs) -> Self {
        // Instance column stores the output of the hash
        let hash_digest_column = meta.instance_column();

        // hash configuration
        let keccak_circuit_config = {
            let keccak_table = KeccakTable::construct(meta);

            let keccak_circuit_config_args = KeccakCircuitConfigArgs {
                keccak_table,
                challenges: config_args.challenges,
            };

            KeccakCircuitConfig::new(meta, keccak_circuit_config_args)
        };

        let columns = keccak_circuit_config.cell_manager.columns();
        // The current code base is hardcoded for KeccakCircuit configured
        // with 300 rows and 87 columns per hash call.
        assert_eq!(
            columns.len(),
            87,
            "cell manager configuration does not match the hard coded setup"
        );

        // enabling equality for preimage and digest columns
        meta.enable_equality(columns[6].advice);
        // digest column
        meta.enable_equality(columns.last().unwrap().advice);
        // public input column
        meta.enable_equality(hash_digest_column);

        MultiBatchCircuitConfig {
            log_degree: LOG_DEGREE as usize,
            max_txs: MAX_TXS,
            hash_digest_column,
            keccak_circuit_config,
            _marker: PhantomData::default(),
        }
    }
}

impl<F: Field, const MAX_TXS: usize> SubCircuit<F> for MultiBatchCircuit<F, MAX_TXS> {
    type Config = MultiBatchCircuitConfig<F>;

    fn new_from_block(_block: &crate::witness::Block<F>) -> Self {
        // we cannot instantiate a new Self from a single block
        unimplemented!()
    }

    /// Return the minimum number of rows required to prove the block
    /// Row numbers without/with padding are both returned.
    fn min_num_rows_block(_block: &crate::witness::Block<F>) -> (usize, usize) {
        (1 << LOG_DEGREE, 1 << LOG_DEGREE)
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![self
            .hash_digest
            .0
            .iter()
            .map(|&x| F::from(x as u64))
            .collect()]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        // extract all the hashes and load them to the hash table
        let (preimages, _digests) = self.multi_batch_public_data.extract_hashes();

        config.keccak_circuit_config.load_aux_tables(layouter)?;

        let (_preimages, _digests) = config.assign(layouter, *challenges, &preimages)?;

        Ok(())
    }
}
