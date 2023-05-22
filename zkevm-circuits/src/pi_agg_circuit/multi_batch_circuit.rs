//! Circuit implementation of `MultiBatch` public input hashes.
//!
//!
//! IMPORTANT:
//!
//! The current implementation is KeccakCircuit parameter dependent.
//! The current code base is hardcoded for KeccakCircuit configured
//! with 300 rows and 87 columns per hash call. The 7-th column is used
//! for hash preimages and the 87-th column is for hash digest.
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
use std::{marker::PhantomData, vec};

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

    /// Instance column stores the aggregated rpi hash digest
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
    ) -> Result<
        (
            Vec<Vec<AssignedCell<F, F>>>, // input cells
            Vec<Vec<AssignedCell<F, F>>>, // digest cells
        ),
        Error,
    > {
        let mut is_first_time = true;
        let num_rows = 1 << 18;

        let witness = multi_keccak(preimages, challenges, capacity(num_rows))?;

        // extract the indices of the rows for which the preimage and the digest cells lie in
        let (preimage_indices, digest_indices) = get_indices(preimages);

        log::info!("preimage indices: {:?}", preimage_indices);
        log::info!("digest indices:   {:?}", digest_indices);

        let mut hash_input_cells = vec![];
        let mut hash_output_cells = vec![];

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
                // ====================================================
                // Step 1. Extract the hash cells
                // ====================================================
                let mut current_hash_input_cells = vec![];
                let mut current_hash_output_cells = vec![];

                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row =
                        self.keccak_circuit_config
                            .set_row(&mut region, offset, keccak_row)?;

                    if preimage_indices.contains(&offset) {
                        current_hash_input_cells.push(row[6].clone());
                    }
                    if digest_indices.contains(&offset) {
                        current_hash_output_cells.push(row.last().unwrap().clone());
                    }

                    // we reset the current hash when it is finalized
                    // note that length == 0 indicate that the hash is a padding
                    // so we simply skip it
                    if keccak_row.is_final && keccak_row.length != 0 {
                        hash_input_cells.push(current_hash_input_cells);
                        hash_output_cells.push(current_hash_output_cells);
                        current_hash_input_cells = vec![];
                        current_hash_output_cells = vec![];
                    }
                }

                // sanity: we have same number of hash input and output
                let hash_num = hash_input_cells.len();
                assert!(hash_num % 2 == 0);
                assert_eq!(hash_num, hash_output_cells.len());

                // ====================================================
                // Step 2. Constraint the hash digest is reused later for hash preimages
                // ====================================================
                {
                    // 2.1 assert the data hash's input is well-formed
                    {
                        let mut final_data_hash_inputs = vec![];
                        for i in 0..hash_num / 2 - 1 {
                            final_data_hash_inputs
                                .extend_from_slice(hash_output_cells[i * 2].as_ref());
                        }
                        assert_eq!(
                            final_data_hash_inputs.len(),
                            hash_input_cells[hash_num - 2].len()
                        );
                        let chunks = final_data_hash_inputs.len() / 8;
                        for i in 0..chunks {
                            for j in 0..8 {
                                // sanity: the values in cells match
                                assert_equal(
                                    &final_data_hash_inputs[i * 8 + j],
                                    &hash_input_cells[hash_num - 2][(chunks - i - 1) * 8 + j],
                                );
                                // preimage and digest has different endianness
                                // (great design decision btw /s)
                                region.constrain_equal(
                                    final_data_hash_inputs[i * 8 + j].cell(),
                                    hash_input_cells[hash_num - 2][(chunks - i - 1) * 8 + j].cell(),
                                )?;
                            }
                        }
                    }

                    // 2.2 assert the rpi hash's input is well-formed
                    {
                        let mut final_rpi_hash_inputs = vec![];
                        for i in 0..hash_num / 2 - 1 {
                            final_rpi_hash_inputs
                                .extend_from_slice(hash_output_cells[i * 2 + 1].as_ref());
                        }
                        assert_eq!(
                            final_rpi_hash_inputs.len(),
                            hash_input_cells[hash_num - 1].len()
                        );
                        let chunks = final_rpi_hash_inputs.len() / 8;
                        for i in 0..chunks {
                            for j in 0..8 {
                                // sanity: the values in cells match
                                assert_equal(
                                    &final_rpi_hash_inputs[i * 8 + j],
                                    &hash_input_cells[hash_num - 1][(chunks - i - 1) * 8 + j],
                                );
                                // preimage and digest has different endianness
                                // (great design decision btw /s)
                                region.constrain_equal(
                                    final_rpi_hash_inputs[i * 8 + j].cell(),
                                    hash_input_cells[hash_num - 1][(chunks - i - 1) * 8 + j].cell(),
                                )?;
                            }
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

        // ====================================================
        // Step 3. Constraint the final hash output matches the raw public input
        // ====================================================
        {
            let final_digest_cells = hash_output_cells.last().unwrap();
            for i in 0..4 {
                for j in 0..8 {
                    // digest in circuit has a different endianness
                    layouter.constrain_instance(
                        final_digest_cells[(3 - i) * 8 + j].cell(),
                        self.hash_digest_column,
                        i * 8 + j,
                    )?;
                }
            }
        }

        // debugging info
        //
        // print!("input: ");
        // for e in hash_input_cells.iter() {
        //     print!("{} ", e.len());
        // }
        // println!();
        //
        // print!("digests: ");
        // for e in hash_output_cells.iter() {
        //     print!("{} ", e.len());
        // }
        // println!();

        Ok((hash_input_cells, hash_output_cells))
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

        config
            .keccak_circuit_config
            .load_aux_tables(&mut layouter)?;

        let (_preimages, _digests) = config.assign(&mut layouter, challenges, &preimages)?;

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

fn capacity(num_rows: usize) -> Option<usize> {
    if num_rows > 0 {
        // Subtract two for unusable rows
        Some(num_rows / ((NUM_ROUNDS + 1) * get_num_rows_per_round()) - 2)
    } else {
        None
    }
}

/// Return
/// - the indices of the rows that contain the input preimages
/// - the indices of the rows that contain the output digest
/// - number of rounds that used for all but last two hashes
fn get_indices(preimages: &[Vec<u8>]) -> (Vec<usize>, Vec<usize>) {
    let mut preimage_indices = vec![];
    let mut digest_indices = vec![];
    let mut round_ctr = 0;

    for preimage in preimages.iter() {
        let num_rounds = 1 + preimage.len() / 136;
        for (i, round) in preimage.chunks(136).enumerate() {
            // indices for preimegas
            for (j, _chunk) in round.chunks(8).into_iter().enumerate() {
                for k in 0..8 {
                    preimage_indices.push(round_ctr * 300 + j * 12 + k + 12)
                }
            }
            // indices for digests
            if i == num_rounds - 1 {
                for j in 0..4 {
                    for k in 0..8 {
                        digest_indices.push(round_ctr * 300 + (3 - j) * 12 + k + 252)
                    }
                }
            }
            round_ctr += 1;
        }
    }
    (preimage_indices, digest_indices)
}

#[inline]
// assert two cells have same value
// (NOT constraining equality in circuit)
fn assert_equal<F: Field>(a: &AssignedCell<F, F>, b: &AssignedCell<F, F>) {
    let mut t1 = F::default();
    let mut t2 = F::default();
    a.value().map(|f| t1 = *f);
    b.value().map(|f| t2 = *f);
    assert_eq!(t1, t2)
}
