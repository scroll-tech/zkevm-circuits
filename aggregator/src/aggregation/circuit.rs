use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::commitment::ParamsKZG,
    },
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::{
        halo2::{
            halo2_ecc::halo2_base::{
                self, gates::GateInstructions, AssignedValue, Context, ContextParams, QuantumCell,
            },
            Halo2Loader,
        },
        native::NativeLoader,
    },
    pcs::kzg::{Bdfg21, Kzg, KzgAccumulator, KzgSuccinctVerifyingKey},
    util::arithmetic::fe_to_limbs,
};
use snark_verifier_sdk::{
    aggregate, flatten_accumulator, gen_dummy_snark, types::Svk, CircuitExt, Snark, SnarkWitness,
};
use zkevm_circuits::util::Challenges;

use crate::{
    aggregation::{config::AggregationConfig, util::is_smaller_than},
    assigned_cell_to_value,
    constants::{ACC_LEN, BITS, DIGEST_LEN, LIMBS},
    core::{assert_hash_relations, assign_batch_hashes, extract_accumulators_and_proof},
    param::ConfigParams,
    BatchHash, ChunkHash, MAX_AGG_SNARKS,
};

/// Aggregation circuit that does not re-expose any public inputs from aggregated snarks
#[derive(Clone)]
pub struct AggregationCircuit {
    pub(crate) svk: KzgSuccinctVerifyingKey<G1Affine>,
    // the input snarks for the aggregation circuit
    // it is padded already so it will have a fixed length of MAX_AGG_SNARKS
    pub(crate) snarks_with_padding: Vec<SnarkWitness>,
    // the public instance for this circuit consists of
    // - an accumulator (12 elements)
    // - the batch's public_input_hash (32 elements)
    // - the number of snarks that is aggregated (1 element)
    pub(crate) flattened_instances: Vec<Fr>,
    // accumulation scheme proof, private input
    pub(crate) as_proof: Value<Vec<u8>>,
    // batch hash circuit for which the snarks are generated
    pub(crate) batch_hash: BatchHash,
}

impl AggregationCircuit {
    /// Build a new aggregation circuit for a list of __compressed__ snarks.
    /// Requires the chunk hashes that are used for the __fresh__ snark
    pub fn new<SnarkCircuit: CircuitExt<Fr>>(
        params: &ParamsKZG<Bn256>,
        snarks_without_padding: &[Snark],
        rng: impl Rng + Send,
        chunk_hashes: &[ChunkHash],
    ) -> Self {
        let timer = start_timer!(|| "generate aggregation circuit");
        // sanity: for each chunk we have a snark
        let snarks_len = snarks_without_padding.len();
        assert_eq!(
            snarks_len,
            chunk_hashes.len(),
            "num of snarks ({}) does not match number of chunks ({})",
            snarks_len,
            chunk_hashes.len(),
        );
        assert!(
            snarks_len <= MAX_AGG_SNARKS,
            "input #snarks ({}) exceed maximum allowed ({})",
            snarks_len,
            MAX_AGG_SNARKS
        );

        // sanity check: snarks's public input matches chunk_hashes
        for (chunk, snark) in chunk_hashes.iter().zip(snarks_without_padding.iter()) {
            let chunk_hash_bytes = chunk.public_input_hash();
            let snark_hash_bytes = &snark.instances[0];

            assert_eq!(snark_hash_bytes.len(), ACC_LEN + DIGEST_LEN);

            for i in 0..32 {
                // for each snark,
                //  first 12 elements are accumulator
                //  next 32 elements are public_input_hash
                //  accumulator + public_input_hash = snark public input
                assert_eq!(
                    Fr::from(chunk_hash_bytes.as_bytes()[i] as u64),
                    snark_hash_bytes[i + ACC_LEN]
                );
            }
        }

        // pad the input snarks with dummy snarks
        let dummy_snarks = if snarks_len < MAX_AGG_SNARKS {
            let mut params = params.clone();
            params.downsize(9);
            let dummy_snark = gen_dummy_snark::<SnarkCircuit, Kzg<Bn256, Bdfg21>>(
                &params,
                None,
                vec![ACC_LEN + DIGEST_LEN],
            );
            vec![dummy_snark; MAX_AGG_SNARKS - snarks_len]
        } else {
            vec![]
        };
        let snarks_with_padding = [snarks_without_padding, dummy_snarks.as_ref()].concat();

        // extract the accumulators and proofs
        let svk = params.get_g()[0].into();

        // this aggregates MULTIPLE snarks
        //  (instead of ONE as in proof compression)
        let (accumulator, as_proof) =
            extract_accumulators_and_proof(params, &snarks_with_padding, rng).unwrap();
        let KzgAccumulator::<G1Affine, NativeLoader> { lhs, rhs } = accumulator;
        let acc_instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<Fq, Fr, LIMBS, BITS>)
            .concat();

        // extract batch's public input hash
        let batch_hash = BatchHash::construct(chunk_hashes);
        let public_input_hash = &batch_hash.instances_exclude_acc()[0];

        // the public instance for this circuit consists of
        // - an accumulator (12 elements)
        // - the batch's public_input_hash (32 elements)
        // - the number of snarks that is aggregated (1 element)
        let flattened_instances: Vec<Fr> = [
            acc_instances.as_slice(),
            public_input_hash.as_slice(),
            &[Fr::from(snarks_len as u64)],
        ]
        .concat();

        log::trace!("flattened instances during construction");
        for (i, e) in flattened_instances.iter().enumerate() {
            log::trace!("{}-th: {:?}", i, e);
        }
        end_timer!(timer);
        Self {
            svk,
            snarks_with_padding: snarks_with_padding.iter().cloned().map_into().collect(),
            flattened_instances,
            as_proof: Value::known(as_proof),
            batch_hash,
        }
    }

    pub fn succinct_verifying_key(&self) -> &Svk {
        &self.svk
    }

    pub fn snarks_without_padding(&self) -> &[SnarkWitness] {
        &self.snarks_with_padding[0..self.batch_hash.number_of_valid_chunks]
    }

    pub fn snarks_with_padding(&self) -> &[SnarkWitness] {
        &self.snarks_with_padding
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}

impl Circuit<Fr> for AggregationCircuit {
    type Config = (AggregationConfig, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let params = ConfigParams::aggregation_param();
        let challenges = Challenges::construct(meta);
        let config = AggregationConfig::configure(meta, &params, challenges);
        log::info!(
            "aggregation circuit configured with k = {} and {:?} advice columns",
            params.degree,
            params.num_advice
        );
        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (config, challenge) = config;

        let witness_time = start_timer!(|| "synthesize | Aggregation Circuit");
        config
            .range()
            .load_lookup_table(&mut layouter)
            .expect("load range lookup table");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        // This circuit takes 3 steps
        // - 1. use aggregation circuit to aggregate the multiple snarks into a single one;
        //   re-export all the public input of the snarks, denoted by the accumulator
        //   [acc_instances] and the chunk's public hash [snarks_instances]
        // - 2. use public input aggregation circuit to aggregate the chunks; expose the instance
        //   denoted by [batch_instances]
        // - 3. assert [snarks_instances] are private inputs used for [batch_instances]

        // ==============================================
        // Step 1: snark aggregation circuit
        // ==============================================
        // stores accumulators for all snarks, including the padded ones
        let mut accumulator_instances: Vec<AssignedValue<Fr>> = vec![];
        // stores public inputs for all snarks, including the padded ones
        let mut snark_inputs: Vec<AssignedValue<Fr>> = vec![];

        layouter.assign_region(
            || "aggregation",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: config.flex_gate().max_rows,
                        num_context_ids: 1,
                        fixed_columns: config.flex_gate().constants.clone(),
                    },
                );

                let ecc_chip = config.ecc_chip();
                let loader = Halo2Loader::new(ecc_chip, ctx);

                //
                // extract the assigned values for
                // - instances which are the public inputs of each chunk (prefixed with 12 instances
                //   from previous accumulators)
                // - new accumulator to be verified on chain
                //
                let (assigned_aggregation_instances, acc) = aggregate::<Kzg<Bn256, Bdfg21>>(
                    &self.svk,
                    &loader,
                    &self.snarks_with_padding,
                    self.as_proof(),
                );
                log::trace!("aggregation circuit during assigning");
                for (i, e) in assigned_aggregation_instances[0].iter().enumerate() {
                    log::trace!("{}-th instance: {:?}", i, e.value)
                }

                // extract the following cells for later constraints
                // - the accumulators
                // - the public inputs from each snark
                accumulator_instances.extend(flatten_accumulator(acc).iter().copied());
                // the snark is not a fresh one, assigned_instances already contains an
                // accumulator so we want to skip the first 12 elements from the public input
                snark_inputs.extend(
                    assigned_aggregation_instances
                        .iter()
                        .flat_map(|instance_column| instance_column.iter().skip(ACC_LEN)),
                );

                config.range().finalize(&mut loader.ctx_mut());

                loader.ctx_mut().print_stats(&["Range"]);

                Ok(())
            },
        )?;

        log::trace!("instance outside aggregation function");
        for (i, e) in snark_inputs.iter().enumerate() {
            log::trace!("{}-th instance: {:?}", i, e.value)
        }
        // assert the accumulator in aggregation instance matches public input
        for (i, v) in accumulator_instances.iter().enumerate() {
            layouter.constrain_instance(v.cell(), config.instance, i)?;
        }

        // ==============================================
        // step 2: public input aggregation circuit
        // ==============================================
        // extract all the hashes and load them to the hash table
        let challenges = challenge.values(&layouter);

        let timer = start_timer!(|| ("extract hash").to_string());
        // orders:
        // - batch_public_input_hash
        // - chunk\[i\].piHash for i in \[0, MAX_AGG_SNARKS)
        // - batch_data_hash_preimage
        let preimages = self.batch_hash.extract_hash_preimages();
        assert_eq!(
            preimages.len(),
            MAX_AGG_SNARKS + 2,
            "error extracting preimages"
        );
        end_timer!(timer);

        log::trace!("hash preimages");
        for (i, e) in preimages.iter().enumerate() {
            log::trace!("{}-th hash preimage {:02x?}", i, e)
        }

        let timer = start_timer!(|| ("load aux table").to_string());
        config
            .keccak_circuit_config
            .load_aux_tables(&mut layouter)?;
        end_timer!(timer);

        let timer = start_timer!(|| ("assign cells").to_string());
        let (hash_preimage_cells, hash_digest_cells, hash_data_rlc_cells) = assign_batch_hashes(
            &config.keccak_circuit_config,
            &mut layouter,
            challenges,
            &preimages,
        )
        .unwrap();
        end_timer!(timer);

        log::trace!("hash input");
        for v in hash_preimage_cells.iter() {
            for (i, c) in v.iter().enumerate() {
                log::trace!("{}-th {:?}", i, c.value())
            }
        }
        log::trace!("hash output");
        for v in hash_digest_cells.iter() {
            for (i, c) in v.iter().enumerate() {
                log::trace!("{}-th {:?}", i, c.value())
            }
        }

        // ==============================================
        // step 3: aggregation circuit and public input aggregation circuit
        // share common inputs
        // ==============================================
        // aggregation circuit's public input:
        // - for each chunk:
        //      - data hash
        //      - public input hash
        // Those are used as private inputs to the public input aggregation circuit

        assert_hash_relations(
            &config,
            &mut layouter,
            &snark_inputs,
            &hash_preimage_cells,
            &hash_digest_cells,
            &hash_data_rlc_cells,
            self.flattened_instances.last().unwrap(),
        )?;

        // // stores assigned_num_snark_without_padding cell
        // let mut assigned_num_snarks = vec![];
        // layouter.assign_region(
        //     || "glue circuits",
        //     |region| {
        //         if first_pass {
        //             first_pass = false;
        //             return Ok(());
        //         }

        //         // last element within flattened instance encodes the number of snarks
        //         // (this will be be checked against aggregation circuit's public inputs later)
        //         let num_snarks_without_padding =
        //             Value::known(*self.flattened_instances.last().unwrap());

        //         let mut ctx = Context::new(
        //             region,
        //             ContextParams {
        //                 max_rows: config.flex_gate().max_rows,
        //                 num_context_ids: 1,
        //                 fixed_columns: config.flex_gate().constants.clone(),
        //             },
        //         );

        //         let flex_gate = &config.base_field_config.range.gate;

        //         // =================================================
        //         // step 3.1. before processing, we need to convert halo2proof's AssignedCells to
        //         // halo2-lib's AssignedValues.
        //         // =================================================
        //         //
        //         // Note that this is a bit overkill since not all cells in halo2proof's
        //         // hash_input_cells and hash_output_cells needs to be extracted for
        //         // halo2-lib. A future optimization may cherry pick the right cells
        //         // for conversion.
        //         //
        //         let hash_input_cells = assigned_cell_to_value!(hash_input_cells, ctx, flex_gate);
        //         let hash_output_cells = assigned_cell_to_value!(hash_output_cells, ctx,
        // flex_gate);

        //         // =================================================
        //         // step 3.2
        //         // the actual circuit logics
        //         // =================================================
        //         let assigned_num_snark_without_padding =
        //             flex_gate.load_witness(&mut ctx, num_snarks_without_padding);
        //         let mut current_snark_indexer = flex_gate.load_constant(&mut ctx, Fr::zero());
        //         assigned_num_snarks.push(assigned_num_snark_without_padding);
        //         let one = flex_gate.load_constant(&mut ctx, Fr::one());
        //         let mut data_hash_inputs = vec![];

        //         for chunk_idx in 0..MAX_AGG_SNARKS {
        //             // this loop is invariant w.r.t. num_snark_without_padding
        //             // it firstly derive a boolean cell to check whether the snark is a dummy one
        //             // and use this boolean cell to override equality checks if the snark is
        // dummy

        //             let is_padding = is_smaller_than(
        //                 &flex_gate,
        //                 &mut ctx,
        //                 &current_snark_indexer,
        //                 &assigned_num_snark_without_padding,
        //             );
        //             let is_not_padding = flex_gate.not(&mut ctx,
        // QuantumCell::Existing(is_padding));

        //             // step 3.2.1, data hash
        //             // - batch_data_hash := keccak(chunk_0.data_hash || ... ||
        // chunk_k-1.data_hash)             // where batch_data_hash is the second hash for
        // pi aggregation             for i in 0..32 {
        //                 // let byte_is_equal = flex_gate.is_equal(
        //                 //     &mut ctx,
        //                 //     // the first 32 inputs for the snark
        //                 //     QuantumCell::Existing(snark_inputs[64 * chunk_idx + i]),
        //                 //     QuantumCell::Existing(hash_input_cells[1][chunk_idx * 32 + i]),
        //                 // );
        //                 let consolidated_result = flex_gate.mul(
        //                     &mut ctx,
        //                     QuantumCell::Existing(snark_inputs[64 * chunk_idx + i]),
        //                     QuantumCell::Existing(is_not_padding),
        //                 );
        //                 data_hash_inputs.push(consolidated_result);

        //                 // flex_gate.assert_equal(
        //                 //     &mut ctx,
        //                 //     QuantumCell::Existing(enforced_result),
        //                 //     QuantumCell::Existing(one),
        //                 // );
        //             }
        //             // step 3.2.2, public input hash
        //             // the public input hash for the i-th snark is the (i+2)-th hash
        //             for i in 0..4 {
        //                 for j in 0..8 {
        //                     let byte_is_equal = flex_gate.is_equal(
        //                         &mut ctx,
        //                         // the first 32 inputs for the snark
        //                         QuantumCell::Existing(
        //                             snark_inputs[64 * chunk_idx + i * 8 + j + 32],
        //                         ),
        //                         QuantumCell::Existing(
        //                             hash_output_cells[chunk_idx + 2][(3 - i) * 8 + j],
        //                         ),
        //                     );
        //                     let enforced_result = flex_gate.or(
        //                         &mut ctx,
        //                         QuantumCell::Existing(byte_is_equal),
        //                         QuantumCell::Existing(is_padding),
        //                     );
        //                     flex_gate.assert_equal(
        //                         &mut ctx,
        //                         QuantumCell::Existing(enforced_result),
        //                         QuantumCell::Existing(one),
        //                     );
        //                 }
        //             }
        //             // increment the current indexer by 1
        //             current_snark_indexer = flex_gate.add(
        //                 &mut ctx,
        //                 QuantumCell::Existing(current_snark_indexer),
        //                 QuantumCell::Existing(one),
        //             );
        //         }

        //         Ok(())
        //     },
        // )?;

        // ====================================================
        // Last step: public inputs
        // - Constrain the hash data matches the public input hash
        // - Constrain the number of snarks matches public input
        // ====================================================
        let acc_len = 12;
        {
            // Constrain the hash data matches the public input hash
            for i in 0..4 {
                for j in 0..8 {
                    // digest in circuit has a different endianness
                    layouter.constrain_instance(
                        hash_digest_cells[0][(3 - i) * 8 + j].cell(),
                        config.instance,
                        i * 8 + j + acc_len,
                    )?;
                }
            }
            // // Constrain the number of snarks matches public input
            // layouter.constrain_instance(
            //     assigned_num_snarks[0].cell(),
            //     config.instance,
            //     DIGEST_LEN + acc_len,
            // )?;
        }

        end_timer!(witness_time);
        Ok(())
    }
}
