use ark_std::{end_timer, start_timer};
use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Column, ConstraintSystem, Error, Expression, Instance},
};
use zkevm_circuits::{
    keccak_circuit::{
        keccak_packed_multi::multi_keccak, KeccakCircuitConfig, KeccakCircuitConfigArgs,
    },
    table::{KeccakTable, LookupTable},
    util::{Challenges, SubCircuitConfig},
};

use crate::{
    util::{assert_equal, capacity, get_indices},
    LOG_DEGREE,
};

/// Config for BatchCircuit
#[derive(Clone, Debug)]
pub struct BatchCircuitConfig<F: Field> {
    /// Instance column stores the aggregated rpi hash digest
    pub(crate) hash_digest_column: Column<Instance>,

    /// Keccak circuit config
    pub(crate) keccak_circuit_config: KeccakCircuitConfig<F>,
}

/// Auxiliary arguments for BatchCircuit's Config
#[derive(Clone, Debug)]
pub struct BatchCircuitConfigArgs<F: Field> {
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for BatchCircuitConfig<F> {
    type ConfigArgs = BatchCircuitConfigArgs<F>;

    /// Return a new BatchCircuitConfig
    fn new(meta: &mut ConstraintSystem<F>, config_args: Self::ConfigArgs) -> Self {
        // hash configuration
        let keccak_circuit_config = {
            let keccak_table = KeccakTable::construct(meta);

            let keccak_circuit_config_args = KeccakCircuitConfigArgs {
                keccak_table,
                challenges: config_args.challenges,
            };

            KeccakCircuitConfig::new(meta, keccak_circuit_config_args)
        };

        // The current code base is hardcoded for KeccakCircuit configured
        // with 300 rows and 87 columns per hash call.
        let columns = keccak_circuit_config.cell_manager.columns();

        assert_eq!(
            columns.len(),
            87,
            "cell manager configuration does not match the hard coded setup"
        );

        // enabling equality for preimage and digest columns
        meta.enable_equality(columns[6].advice);
        // digest column
        meta.enable_equality(columns.last().unwrap().advice);

        // Instance column stores the output of the hash
        let hash_digest_column = meta.instance_column();
        // public input column
        meta.enable_equality(hash_digest_column);

        BatchCircuitConfig {
            hash_digest_column,
            keccak_circuit_config,
        }
    }
}

impl<F: Field> BatchCircuitConfig<F> {
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
        let num_rows = 1 << LOG_DEGREE;

        let timer = start_timer!(|| ("multi keccak").to_string());
        let witness = multi_keccak(preimages, challenges, capacity(num_rows))?;
        end_timer!(timer);

        // extract the indices of the rows for which the preimage and the digest cells lie in
        let (preimage_indices, digest_indices) = get_indices(preimages);
        let mut preimage_indices_iter = preimage_indices.iter();
        let mut digest_indices_iter = digest_indices.iter();

        let mut hash_input_cells = vec![];
        let mut hash_output_cells = vec![];

        let mut cur_preimage_index = preimage_indices_iter.next();
        let mut cur_digest_index = digest_indices_iter.next();

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

                let timer = start_timer!(|| "assign row");
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row =
                        self.keccak_circuit_config
                            .set_row(&mut region, offset, keccak_row)?;

                    if cur_preimage_index.is_some() && *cur_preimage_index.unwrap() == offset {
                        current_hash_input_cells.push(row[6].clone());
                        cur_preimage_index = preimage_indices_iter.next();
                    }
                    if cur_digest_index.is_some() && *cur_digest_index.unwrap() == offset {
                        current_hash_output_cells.push(row.last().unwrap().clone());
                        cur_digest_index = digest_indices_iter.next();
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
                end_timer!(timer);

                // sanity: we have same number of hash input and output
                let hash_num = hash_input_cells.len();
                let num_chunks = hash_num - 2;
                assert!(hash_num == preimages.len());
                assert_eq!(hash_num, hash_output_cells.len());

                // ====================================================
                // Step 2. Constraint the relations between hash preimages and digests
                // ====================================================
                //
                // 2.1 batch_data_hash digest is reused for public input hash
                //
                // public input hash is build as
                //  keccak(
                //      chain_id ||
                //      chunk[0].prev_state_root ||
                //      chunk[k-1].post_state_root ||
                //      chunk[k-1].withdraw_root ||
                //      batch_data_hash )
                for i in 0..4 {
                    for j in 0..8 {
                        // sanity check
                        assert_equal(
                            &hash_input_cells[0][i * 8 + j + 100],
                            &hash_output_cells[1][(3 - i) * 8 + j],
                        );
                        region.constrain_equal(
                            // preimage and digest has different endianness
                            hash_input_cells[0][i * 8 + j + 100].cell(),
                            hash_output_cells[1][(3 - i) * 8 + j].cell(),
                        )?;
                    }
                }

                // 2.2 batch_pi_hash used same roots as chunk_pi_hash
                //
                // batch_pi_hash =
                //   keccak(
                //      chain_id ||
                //      chunk[0].prev_state_root ||
                //      chunk[k-1].post_state_root ||
                //      chunk[k-1].withdraw_root ||
                //      batchData_hash )
                //
                // chunk[i].piHash =
                //   keccak(
                //        chain id ||
                //        chunk[i].prevStateRoot || chunk[i].postStateRoot || chunk[i].withdrawRoot
                // ||        chunk[i].datahash)
                for i in 0..32 {
                    // 2.2.1 chunk[0].prev_state_root
                    // sanity check
                    assert_equal(&hash_input_cells[0][i + 4], &hash_input_cells[2][i + 4]);
                    region.constrain_equal(
                        hash_input_cells[0][i + 4].cell(),
                        hash_input_cells[2][i + 4].cell(),
                    )?;
                    // 2.2.2 chunk[k-1].post_state_root
                    // sanity check
                    assert_equal(
                        &hash_input_cells[0][i + 36],
                        &hash_input_cells[hash_num - 1][i + 36],
                    );
                    region.constrain_equal(
                        hash_input_cells[0][i + 36].cell(),
                        hash_input_cells[hash_num - 1][i + 36].cell(),
                    )?;
                    // 2.2.3 chunk[k-1].withdraw_root
                    assert_equal(
                        &hash_input_cells[0][i + 68],
                        &hash_input_cells[hash_num - 1][i + 68],
                    );
                    region.constrain_equal(
                        hash_input_cells[0][i + 68].cell(),
                        hash_input_cells[hash_num - 1][i + 68].cell(),
                    )?;
                }

                // 2.3 same dataHash is used for batchDataHash and chunk[i].piHash
                //
                // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
                //
                // chunk[i].piHash =
                //     keccak(
                //        &chain id ||
                //        chunk[i].prevStateRoot || chunk[i].postStateRoot || chunk[i].withdrawRoot
                // ||        chunk[i].datahash)
                for (i, chunk) in hash_input_cells[1].chunks(32).enumerate().take(num_chunks) {
                    for (j, cell) in chunk.iter().enumerate() {
                        // sanity check
                        assert_equal(cell, &hash_input_cells[2 + i][j + 100]);
                        region.constrain_equal(
                            cell.cell(),
                            hash_input_cells[2 + i][j + 100].cell(),
                        )?;
                    }
                }

                // 2.4  chunks are continuous: they are linked via the state roots
                for i in 0..num_chunks - 1 {
                    for j in 0..32 {
                        // sanity check
                        assert_equal(
                            &hash_input_cells[i + 3][4 + j],
                            &hash_input_cells[i + 2][36 + j],
                        );
                        region.constrain_equal(
                            // chunk[i+1].prevStateRoot
                            hash_input_cells[i + 3][4 + j].cell(),
                            // chunk[i].postStateRoot
                            hash_input_cells[i + 2][36 + j].cell(),
                        )?;
                    }
                }

                // 2.5 assert hashes uses a same chain id
                for i in 0..num_chunks {
                    for j in 0..4 {
                        // sanity check
                        assert_equal(&hash_input_cells[0][j], &hash_input_cells[i + 2][j]);
                        region.constrain_equal(
                            // chunk[i+1].prevStateRoot
                            hash_input_cells[0][j].cell(),
                            // chunk[i].postStateRoot
                            hash_input_cells[i + 2][j].cell(),
                        )?;
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
        // Step 3. Constraint the hash data matches the raw public input
        // ====================================================
        {
            for i in 0..32 {
                // first_chunk_prev_state_root
                layouter.constrain_instance(
                    hash_input_cells[2][4 + i].cell(),
                    self.hash_digest_column,
                    i,
                )?;
                // last_chunk_post_state_root
                layouter.constrain_instance(
                    hash_input_cells.last().unwrap()[36 + i].cell(),
                    self.hash_digest_column,
                    i + 32,
                )?;
                // last_chunk_withdraw_root
                layouter.constrain_instance(
                    hash_input_cells.last().unwrap()[68 + i].cell(),
                    self.hash_digest_column,
                    i + 64,
                )?;
            }
            // batch_public_input_hash
            for i in 0..4 {
                for j in 0..8 {
                    // digest in circuit has a different endianness
                    layouter.constrain_instance(
                        hash_output_cells[0][(3 - i) * 8 + j].cell(),
                        self.hash_digest_column,
                        i * 8 + j + 96,
                    )?;
                }
            }
            // last 4 inputs are the chain id
            for i in 0..4 {
                layouter.constrain_instance(
                    hash_input_cells[0][i].cell(),
                    self.hash_digest_column,
                    128 + i,
                )?;
            }
        }

        Ok((hash_input_cells, hash_output_cells))
    }
}
