use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Column, ConstraintSystem, Error, Expression, Instance},
};
use zkevm_circuits::{
    keccak_circuit::{
        keccak_packed_multi::multi_keccak, KeccakCircuitConfig, KeccakCircuitConfigArgs,
    },
    table::KeccakTable,
    util::{Challenges, SubCircuitConfig},
};

use crate::{
    util::{capacity, get_indices},
    CHAIN_ID_LEN, LOG_DEGREE,
};

/// Config for MockChunkCircuit
#[derive(Clone, Debug)]
pub struct MockChunkCircuitConfig {
    /// Instance column stores the aggregated rpi hash digest
    pub(crate) hash_digest_column: Column<Instance>,

    /// Keccak circuit config
    pub(crate) keccak_circuit_config: KeccakCircuitConfig<Fr>,
}
/// Auxiliary arguments for BatchCircuit's Config
#[derive(Clone, Debug)]
pub struct MockChunkCircuitConfigArgs {
    pub challenges: Challenges<Expression<Fr>>,
}

impl SubCircuitConfig<Fr> for MockChunkCircuitConfig {
    type ConfigArgs = MockChunkCircuitConfigArgs;

    /// Return a new BatchCircuitConfig
    fn new(meta: &mut ConstraintSystem<Fr>, config_args: Self::ConfigArgs) -> Self {
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

        MockChunkCircuitConfig {
            hash_digest_column,
            keccak_circuit_config,
        }
    }
}

impl MockChunkCircuitConfig {
    /// Input the hash input bytes,
    /// assign the circuit for hash function,
    /// return cells for the hash inputs and digests.
    #[allow(clippy::type_complexity)]
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        challenges: Challenges<Value<Fr>>,
        preimages: &[u8],
    ) -> Result<
        Vec<AssignedCell<Fr, Fr>>, // digest cells
        Error,
    > {
        let mut is_first_time = true;
        let num_rows = 1 << LOG_DEGREE;

        let timer = start_timer!(|| ("multi keccak").to_string());
        let witness = multi_keccak(&[preimages.to_vec()], challenges, capacity(num_rows))?;
        end_timer!(timer);

        // extract the indices of the rows for which the preimage and the digest cells lie in
        let (preimage_indices, digest_indices) = get_indices(&[preimages.to_vec()]);
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
                let timer = start_timer!(|| "assign row");
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row =
                        self.keccak_circuit_config
                            .set_row(&mut region, offset, keccak_row)?;

                    if cur_preimage_index.is_some() && *cur_preimage_index.unwrap() == offset {
                        hash_input_cells.push(row[6].clone());
                        cur_preimage_index = preimage_indices_iter.next();
                    }

                    if cur_digest_index.is_some() && *cur_digest_index.unwrap() == offset {
                        hash_output_cells.push(row.last().unwrap().clone());
                        cur_digest_index = digest_indices_iter.next();
                    }
                }
                end_timer!(timer);

                // sanity: hash output is 32 cells
                assert_eq!(32, hash_output_cells.len());

                Ok(())
            },
        )?;

        // ====================================================
        // Step 2. check the cells match the public input
        // ====================================================
        // chunk's data hash
        for i in 0..32 {
            layouter.constrain_instance(
                hash_input_cells[i + 96 + CHAIN_ID_LEN].cell(),
                self.hash_digest_column,
                i + CHAIN_ID_LEN,
            )?;
        }
        // chunk's public_input_hash
        for i in 0..4 {
            for j in 0..8 {
                // digest in circuit has a different endianness
                layouter.constrain_instance(
                    hash_output_cells[(3 - i) * 8 + j].cell(),
                    self.hash_digest_column,
                    i * 8 + j + 32 + CHAIN_ID_LEN,
                )?;
            }
        }
        // chain id
        for i in 0..CHAIN_ID_LEN {
            layouter.constrain_instance(hash_input_cells[i].cell(), self.hash_digest_column, i)?;
        }

        Ok(hash_output_cells)
    }
}
