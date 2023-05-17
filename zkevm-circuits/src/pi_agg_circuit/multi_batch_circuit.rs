//! Circuit implementation of `MultiBatch` public input hashes.
//!
//!
//! IMPORTANT:
//!
//! The current implementation is KeccakCircuit parameter dependent.
//! The current code base is hardcoded for KeccakCircuit configured
//! with 300 rows and 83 columns per hash call.
//!
//! This is because we need to extract the preimage and digest cells,
//! and argue some relationship between those cells. If the cell manager
//! configuration is changed, the cells indices will be different,
//! and the relationship becomes unsatisfied.
//!
//! For now we stick to this hard coded design for simplicity.
//! A flexible design is a future work.

use super::{multi_batch::MultiBatchPublicData, LOG_DEGREE};
use crate::{
    keccak_circuit::{
        keccak_packed_multi::{get_num_rows_per_round, multi_keccak},
        param::NUM_ROUNDS,
        KeccakCircuitConfig, KeccakCircuitConfigArgs,
    },
    table::{KeccakTable, LookupTable},
    util::{Challenges, SubCircuitConfig},
};

use eth_types::{Field, H256};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use itertools::Itertools;
use std::marker::PhantomData;

/// Circuit inputs for MultiBatch
#[derive(Clone, Debug)]
pub struct MultiBatchCircuit<F: Field, const MAX_TXS: usize> {
    pub(crate) multi_batch_public_data: MultiBatchPublicData<MAX_TXS>,
    /// public input: the hash digest obtained via
    /// `MultiBatchPublicData::raw_public_input_bytes`
    pub(crate) hash_digest: H256,
    pub(crate) _marker: PhantomData<F>,
}

impl<F: Field, const MAX_TXS: usize> MultiBatchCircuit<F, MAX_TXS> {
    fn raw_public_input_bytes(&self) -> Vec<u8> {
        self.multi_batch_public_data.raw_public_input_hash_bytes()
    }
}

/// Config for MultiBatchCircuit
#[derive(Clone, Debug)]
pub struct MultiBatchCircuitConfig<F: Field> {
    /// Log of the degree of the circuit
    log_degree: usize,

    /// Max number of supported transactions
    max_txs: usize,

    /// Instance column stores the output of the hash
    /// i.e., hi(keccak(hash_preimage)), lo(keccak(hash_preimage))
    hash_digest_column: Column<Instance>,

    /// Challenges
    challenges: Challenges,

    /// Keccak circuit config
    keccak_circuit_config: KeccakCircuitConfig<F>,

    _marker: PhantomData<F>,
}

impl<F: Field> MultiBatchCircuitConfig<F> {
    /// Input the hash input bytes,
    /// assign the circuit for hash function,
    /// return cells for the hash inputs and digests.
    #[allow(clippy::type_complexity)]
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        challenges: Challenges<Value<F>>,
        preimages: &[Vec<u8>],
        num_chunks: usize,
    ) -> Result<
        (
            Vec<AssignedCell<F, F>>, // input cells
            Vec<AssignedCell<F, F>>, // digest cells
        ),
        Error,
    > {
        let mut is_first_time = true;
        let num_rows = 1 << 18;

        let witness = multi_keccak(preimages, challenges, capacity(num_rows))?;

        let preimage_indices = get_preimage_indices(preimages);
        let digest_indices = get_digest_indices(preimages.len());

        let mut inputs = vec![];
        let mut digests = vec![];

        layouter.assign_region(
            || "assign keccak rows",
            |mut region| {
                if is_first_time {
                    is_first_time = false;
                    let offset = witness.len() - 1;
                    self.keccak_circuit_config
                        .set_row(&mut region, offset, &witness[offset])?;
                    return Ok(());
                }
                // assign the hash cells
                let mut final_rpi_hash_inputs = vec![];
                let mut final_data_hash_inputs = vec![];
                let mut final_rpi_hash_inputs_reused = vec![];
                let mut final_data_hash_inputs_reused = vec![];
                let total_hash_ctr = 2 * num_chunks + 2;

                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row =
                        self.keccak_circuit_config
                            .set_row(&mut region, offset, keccak_row)?;

                    // we have k chunks, each chunk requires 2 hashes
                    // so the total input hashes prior to the final two is 2k
                    // extract the cells that are going to be reused as preimages
                    if offset <= 2 * num_chunks * 300 && digest_indices.contains(&offset) {
                        let current_hash_ctr = offset / 300;
                        // this hash occurred in the batch,
                        // we need to extract the digests
                        if current_hash_ctr % 2 == 0 {
                            // data hash
                            final_data_hash_inputs.push(row.last().unwrap().clone())
                        } else {
                            // rpi hash
                            final_rpi_hash_inputs.push(row.last().unwrap().clone())
                        }
                    }
                    // extract the cells that are the preimages
                    if offset <= (2 * num_chunks + 1) * 300
                        && offset > 2 * num_chunks * 300
                        && preimage_indices.contains(&offset)
                    {
                        // data hash
                        final_data_hash_inputs_reused.push(row[6].clone());
                    }
                    if offset <= total_hash_ctr * 300
                        && offset > (2 * num_chunks + 1) * 300
                        && preimage_indices.contains(&offset)
                    {
                        // rpi hash
                        final_rpi_hash_inputs_reused.push(row[6].clone());
                    }

                    // extract the returning cells
                    if preimage_indices.contains(&offset) {
                        inputs.push(row[6].clone());
                    }
                    if digest_indices.contains(&offset) {
                        digests.push(row.last().unwrap().clone());
                    }
                }
                // now we need to constrain that the hash digests are used as preimages
                {
                    assert_eq!(
                        final_data_hash_inputs.len(),
                        final_data_hash_inputs_reused.len(),
                        "final data hash's input length does not match"
                    );
                    let chunks = final_data_hash_inputs.len() / 8;
                    for i in 0..chunks {
                        for j in 0..8 {
                            {
                                let mut t1 = F::default();
                                let mut t2 = F::default();
                                final_data_hash_inputs[i * 8 + j].value().map(|f| t1 = *f);
                                final_data_hash_inputs_reused[(chunks - i - 1) * 8 + j]
                                    .value()
                                    .map(|f| t2 = *f);
                                assert_eq!(t1, t2)
                            }
                            // preimage and digest has different endianness
                            // (great design decision btw /s)
                            region.constrain_equal(
                                final_data_hash_inputs[i * 8 + j].cell(),
                                final_data_hash_inputs_reused[(chunks - i - 1) * 8 + j].cell(),
                            )?;
                        }
                    }
                }
                {
                    assert_eq!(
                        final_rpi_hash_inputs.len(),
                        final_rpi_hash_inputs_reused.len(),
                        "final data hash's input length does not match"
                    );
                    let chunks = final_rpi_hash_inputs.len() / 8;
                    for i in 0..chunks {
                        for j in 0..8 {
                            {
                                let mut t1 = F::default();
                                let mut t2 = F::default();
                                final_rpi_hash_inputs[i * 8 + j].value().map(|f| t1 = *f);
                                final_rpi_hash_inputs_reused[(chunks - i - 1) * 8 + j]
                                    .value()
                                    .map(|f| t2 = *f);
                                assert_eq!(t1, t2)
                            }
                            // preimage and digest has different endianness
                            // (great design decision btw /s)
                            region.constrain_equal(
                                final_rpi_hash_inputs[i * 8 + j].cell(),
                                final_rpi_hash_inputs_reused[(chunks - i - 1) * 8 + j].cell(),
                            )?;
                        }
                    }
                }
                self.keccak_circuit_config
                    .keccak_table
                    .annotate_columns_in_region(&mut region);
                self.keccak_circuit_config.annotate_circuit(&mut region);
                Ok(())
            },
        )?;
        Ok((inputs, digests))
    }
}

impl<F: Field, const MAX_TXS: usize> Circuit<F> for MultiBatchCircuit<F, MAX_TXS> {
    type FloorPlanner = SimpleFloorPlanner;

    type Config = MultiBatchCircuitConfig<F>;

    fn without_witnesses(&self) -> Self {
        Self {
            multi_batch_public_data: MultiBatchPublicData::default(),
            hash_digest: H256([0u8; 32]), //(F::default(), F::default()),
            _marker: PhantomData::default(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // Instance column stores the output of the hash
        // i.e., hi(keccak(hash_preimage)), lo(keccak(hash_preimage))
        let hash_digest_column = meta.instance_column();

        let challenges = Challenges::construct(meta);
        let challenges_exprs = challenges.exprs(meta);

        // hash configuration
        let keccak_circuit_config = {
            let keccak_table = KeccakTable::construct(meta);

            let keccak_circuit_config_args = KeccakCircuitConfigArgs {
                keccak_table,
                challenges: challenges_exprs,
            };

            KeccakCircuitConfig::new(meta, keccak_circuit_config_args)
        };

        let columns = keccak_circuit_config.cell_manager.columns();

        // enabling equality for preimage and digest columns
        meta.enable_equality(columns[6].advice);
        // digest column
        meta.enable_equality(columns.last().unwrap().advice);

        MultiBatchCircuitConfig {
            log_degree: LOG_DEGREE as usize,
            max_txs: MAX_TXS,
            hash_digest_column,
            challenges,
            keccak_circuit_config,
            _marker: PhantomData::default(),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = config.challenges.values(&layouter);

        //==============================================================
        // extract all the hashes and load them to the hash table
        //==============================================================
        let (preimages, _digests) = self.multi_batch_public_data.extract_hashes();

        // for i in 0..4 {
        //     println!("{}-th hash", i);
        //     println!("preimage: {:02x?}", preimages[i]);
        //     println!(
        //         "preimage rlc: {:02x?}",
        //         data_to_rlc(preimages[i].as_ref(), &challenges)
        //     );
        //     println!("digest: {:02x?}", digests[i]);
        //     println!(
        //         "digest rlc: {:02x?}\n\n",
        //         data_to_rlc(digests[i].as_ref(), &challenges)
        //     );
        // }

        config
            .keccak_circuit_config
            .load_aux_tables(&mut layouter)?;

        let (_preimages, _digests) = config.assign(
            &mut layouter,
            challenges,
            &preimages,
            self.multi_batch_public_data.public_data_chunks.len(),
        )?;

        // Following code are used for debugging
        //
        // // assert the inputs are correct
        // {
        //     for (i, preimage) in preimages.iter().enumerate() {
        //         for (j, chunk) in preimage.iter().chunks(8).into_iter().enumerate() {
        //             for (k, &byte) in chunk.enumerate() {
        //                 let index = i * 300 + j * 12 + k + 12;
        //                 println!("index: {}", index);
        //                 println!("input byte:  {:?}", F::from(byte as u64));
        //                 println!("keccak byte: {:?}\n", witness[index].cell_values[6]);
        //                 assert_eq!(F::from(byte as u64), witness[index].cell_values[6]);
        //             }
        //         }
        //     }
        // }

        // // assert the outputs are correct
        // {
        //     for (i, &digest) in digests.iter().enumerate() {
        //         let preimage_bytes: [u8; 32] = digest.try_into().unwrap();
        //         for (j, chunk) in preimage_bytes.iter().chunks(8).into_iter().enumerate() {
        //             for (k, &byte) in chunk.enumerate() {
        //                 let index = i * 300 + (3 - j) * 12 + k + 252;
        //                 println!("index: {}", index);
        //                 println!("digest byte:  {:?}", F::from(byte as u64));
        //                 println!("keccak byte: {:?}\n", witness[index].cell_values.last());
        //                 assert_eq!(
        //                     F::from(byte as u64),
        //                     *witness[index].cell_values.last().unwrap()
        //                 );
        //             }
        //         }
        //     }
        // }

        Ok(())
    }
}

// compute an RLC of the hash digest in the clear
fn data_to_rlc<F: Field>(digest: &[u8], challenges: &Challenges<Value<F>>) -> Value<F> {
    digest.iter().fold(Value::known(F::zero()), |acc, byte| {
        acc.zip(challenges.evm_word())
            .and_then(|(acc, rand)| Value::known(acc * rand + F::from(*byte as u64)))
    })
}

fn capacity(num_rows: usize) -> Option<usize> {
    if num_rows > 0 {
        // Subtract two for unusable rows
        Some(num_rows / ((NUM_ROUNDS + 1) * get_num_rows_per_round()) - 2)
    } else {
        None
    }
}

/// Return the indices of the rows that contain the input preimages
fn get_preimage_indices(preimages: &[Vec<u8>]) -> Vec<usize> {
    let mut res = vec![];
    for (i, preimage) in preimages.iter().enumerate() {
        for (j, chunk) in preimage.iter().chunks(8).into_iter().enumerate() {
            for (k, _) in chunk.enumerate() {
                res.push(i * 300 + j * 12 + k + 12)
            }
        }
    }
    res
}

/// Return the indices of the rows that contain the output digest
fn get_digest_indices(digest_len: usize) -> Vec<usize> {
    let mut res = vec![];
    for i in 0..digest_len {
        for j in 0..4 {
            for k in 0..8 {
                res.push(i * 300 + (3 - j) * 12 + k + 252)
            }
        }
    }
    res
}
