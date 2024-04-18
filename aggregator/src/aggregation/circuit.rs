use crate::blob::BlobData;
use ark_std::{end_timer, start_timer};
use halo2_base::{Context, ContextParams};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{Circuit, ConstraintSystem, Error, Selector},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use rand::Rng;
#[cfg(not(feature = "disable_proof_aggregation"))]
use std::rc::Rc;
use std::{env, fs::File};

#[cfg(not(feature = "disable_proof_aggregation"))]
use snark_verifier::loader::halo2::halo2_ecc::halo2_base;
use snark_verifier::pcs::kzg::KzgSuccinctVerifyingKey;
#[cfg(not(feature = "disable_proof_aggregation"))]
use snark_verifier::{
    loader::halo2::{halo2_ecc::halo2_base::AssignedValue, Halo2Loader},
    pcs::kzg::{Bdfg21, Kzg},
};
#[cfg(not(feature = "disable_proof_aggregation"))]
use snark_verifier_sdk::{aggregate, flatten_accumulator};
use snark_verifier_sdk::{CircuitExt, Snark, SnarkWitness};
use zkevm_circuits::util::Challenges;

use crate::{
    batch::BatchHash,
    constants::{ACC_LEN, DIGEST_LEN, MAX_AGG_SNARKS},
    core::{assign_batch_hashes, extract_proof_and_instances_with_pairing_check},
    util::parse_hash_digest_cells,
    AssignedBarycentricEvaluationConfig, ConfigParams,
};

use super::AggregationConfig;

/// Aggregation circuit that does not re-expose any public inputs from aggregated snarks
#[derive(Clone)]
pub struct AggregationCircuit {
    pub svk: KzgSuccinctVerifyingKey<G1Affine>,
    // the input snarks for the aggregation circuit
    // it is padded already so it will have a fixed length of MAX_AGG_SNARKS
    pub snarks_with_padding: Vec<SnarkWitness>,
    // the public instance for this circuit consists of
    // - an accumulator (12 elements)
    // - the batch's public_input_hash (32 elements)
    pub flattened_instances: Vec<Fr>,
    // accumulation scheme proof, private input
    pub as_proof: Value<Vec<u8>>,
    // batch hash circuit for which the snarks are generated
    // the chunks in this batch are also padded already
    pub batch_hash: BatchHash,
}

impl AggregationCircuit {
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks_with_padding: &[Snark],
        rng: impl Rng + Send,
        batch_hash: BatchHash,
    ) -> Result<Self, snark_verifier::Error> {
        let timer = start_timer!(|| "generate aggregation circuit");

        // sanity check: snarks's public input matches chunk_hashes
        for (chunk, snark) in batch_hash
            .chunks_with_padding
            .iter()
            .zip(snarks_with_padding.iter())
        {
            let chunk_hash_bytes = chunk.public_input_hash();
            let snark_hash_bytes = &snark.instances[0];

            assert_eq!(snark_hash_bytes.len(), ACC_LEN + DIGEST_LEN);

            for i in 0..DIGEST_LEN {
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

        // extract the accumulators and proofs
        let svk = params.get_g()[0].into();

        // this aggregates MULTIPLE snarks
        //  (instead of ONE as in proof compression)
        let (as_proof, acc_instances) =
            extract_proof_and_instances_with_pairing_check(params, snarks_with_padding, rng)?;

        // extract batch's public input hash
        let public_input_hash = &batch_hash.instances_exclude_acc()[0];

        // the public instance for this circuit consists of
        // - an accumulator (12 elements)
        // - the batch's public_input_hash (32 elements)
        let flattened_instances: Vec<Fr> =
            [acc_instances.as_slice(), public_input_hash.as_slice()].concat();

        end_timer!(timer);
        Ok(Self {
            svk,
            snarks_with_padding: snarks_with_padding.iter().cloned().map_into().collect(),
            flattened_instances,
            as_proof: Value::known(as_proof),
            batch_hash,
        })
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
        let params = env::var("AGGREGATION_CONFIG").map_or_else(
            |_| ConfigParams::aggregation_param(),
            |path| {
                serde_json::from_reader(
                    File::open(path.as_str()).unwrap_or_else(|_| panic!("{path:?} does not exist")),
                )
                .unwrap()
            },
        );

        let challenges = Challenges::construct(meta);
        let config = AggregationConfig::configure(meta, &params, challenges);
        log::info!(
            "aggregation circuit configured with k = {} and {:?} advice columns",
            params.degree,
            params.num_advice
        );
        (config, challenges)
    }

    #[allow(clippy::type_complexity)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (config, challenge) = config;

        let witness_time = start_timer!(|| "synthesize | Aggregation Circuit");

        let timer = start_timer!(|| "aggregation");

        // load lookup table in range config
        config
            .range()
            .load_lookup_table(&mut layouter)
            .expect("load range lookup table");
        // ==============================================
        // Step 1: snark aggregation circuit
        // ==============================================
        #[cfg(feature = "disable_proof_aggregation")]
        let barycentric = {
            let mut first_pass = halo2_base::SKIP_FIRST_PASS;
            layouter.assign_region(
                || "barycentric evaluation",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(AssignedBarycentricEvaluationConfig::default());
                    }

                    let mut ctx = Context::new(
                        region,
                        ContextParams {
                            max_rows: config.flex_gate().max_rows,
                            num_context_ids: 1,
                            fixed_columns: config.flex_gate().constants.clone(),
                        },
                    );

                    let barycentric = config.barycentric.assign(
                        &mut ctx,
                        &self.batch_hash.blob.coefficients,
                        self.batch_hash.blob.challenge_digest,
                        self.batch_hash.blob.evaluation,
                    );

                    config.barycentric.scalar.range.finalize(&mut ctx);
                    ctx.print_stats(&["barycentric evaluation"]);

                    Ok(barycentric)
                },
            )?
        };

        #[cfg(not(feature = "disable_proof_aggregation"))]
        let (accumulator_instances, snark_inputs, barycentric) = {
            let mut first_pass = halo2_base::SKIP_FIRST_PASS;

            let (accumulator_instances, snark_inputs, barycentric) = layouter.assign_region(
                || "aggregation",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok((
                            vec![],
                            vec![],
                            AssignedBarycentricEvaluationConfig::default(),
                        ));
                    }

                    // stores accumulators for all snarks, including the padded ones
                    let mut accumulator_instances: Vec<AssignedValue<Fr>> = vec![];
                    // stores public inputs for all snarks, including the padded ones
                    let mut snark_inputs: Vec<AssignedValue<Fr>> = vec![];
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
                    // - instances which are the public inputs of each chunk (prefixed with 12
                    //   instances from previous accumulators)
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
                    // accumulator so we want to skip the first 12 elements from the public
                    // input
                    snark_inputs.extend(
                        assigned_aggregation_instances
                            .iter()
                            .flat_map(|instance_column| instance_column.iter().skip(ACC_LEN)),
                    );

                    loader.ctx_mut().print_stats(&["snark aggregation"]);

                    let mut ctx = Rc::into_inner(loader).unwrap().into_ctx();
                    let barycentric = config.barycentric.assign(
                        &mut ctx,
                        &self.batch_hash.blob.coefficients,
                        self.batch_hash.blob.challenge_digest,
                        self.batch_hash.blob.evaluation,
                    );

                    ctx.print_stats(&["barycentric"]);

                    config.range().finalize(&mut ctx);

                    Ok((accumulator_instances, snark_inputs, barycentric))
                },
            )?;

            assert_eq!(snark_inputs.len(), MAX_AGG_SNARKS * DIGEST_LEN);
            (accumulator_instances, snark_inputs, barycentric)
        };
        end_timer!(timer);
        // ==============================================
        // step 2: public input aggregation circuit
        // ==============================================
        // extract all the hashes and load them to the hash table
        let challenges = challenge.values(&layouter);

        let timer = start_timer!(|| "load aux table");

        let assigned_batch_hash = {
            config
                .keccak_circuit_config
                .load_aux_tables(&mut layouter)?;
            end_timer!(timer);

            let timer = start_timer!(|| "extract hash");
            // orders:
            // - batch_public_input_hash
            // - chunk\[i\].piHash for i in \[0, MAX_AGG_SNARKS)
            // - batch_data_hash_preimage
            // - preimage for blob metadata
            // - preimage of chunk data digest (only for valid chunks)
            // - preimage of challenge digest
            let preimages = self.batch_hash.extract_hash_preimages();
            assert_eq!(
                preimages.len(),
                4 + MAX_AGG_SNARKS + self.batch_hash.number_of_valid_chunks,
                "error extracting preimages"
            );
            end_timer!(timer);

            let timer = start_timer!(|| ("assign hash cells").to_string());
            let chunks_are_valid = self
                .batch_hash
                .chunks_with_padding
                .iter()
                .map(|chunk| !chunk.is_padding)
                .collect::<Vec<_>>();
            let assigned_batch_hash = assign_batch_hashes(
                &config,
                &mut layouter,
                challenges,
                &chunks_are_valid,
                &preimages,
            )
            .map_err(|_e| Error::ConstraintSystemFailure)?;

            end_timer!(timer);

            assigned_batch_hash
        };
        // digests
        let (batch_pi_hash_digest, chunk_pi_hash_digests, _potential_batch_data_hash_digest) =
            parse_hash_digest_cells(&assigned_batch_hash.hash_output);

        // ==============================================
        // step 3: assert public inputs to the snarks are correct
        // ==============================================
        for (i, chunk) in chunk_pi_hash_digests.iter().enumerate() {
            let hash = self.batch_hash.chunks_with_padding[i].public_input_hash();
            for j in 0..4 {
                for k in 0..8 {
                    log::trace!(
                        "pi {:02x} {:?}",
                        hash[j * 8 + k],
                        chunk[8 * (3 - j) + k].value()
                    );
                }
            }
        }

        #[cfg(not(feature = "disable_proof_aggregation"))]
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        #[cfg(not(feature = "disable_proof_aggregation"))]
        layouter.assign_region(
            || "pi checks",
            |mut region| -> Result<(), Error> {
                if first_pass {
                    // this region only use copy constraints and do not affect the shape of the
                    // layouter
                    first_pass = false;
                    return Ok(());
                }

                for i in 0..MAX_AGG_SNARKS {
                    for j in 0..4 {
                        for k in 0..8 {
                            let mut t1 = Fr::default();
                            let mut t2 = Fr::default();
                            chunk_pi_hash_digests[i][j * 8 + k].value().map(|x| t1 = *x);
                            snark_inputs[i * DIGEST_LEN + (3 - j) * 8 + k]
                                .value()
                                .map(|x| t2 = *x);
                            log::trace!(
                                "{}-th snark: {:?} {:?}",
                                i,
                                chunk_pi_hash_digests[i][j * 8 + k].value(),
                                snark_inputs[i * DIGEST_LEN + (3 - j) * 8 + k].value()
                            );

                            region.constrain_equal(
                                // in the keccak table, the input and output data have different
                                // endianess
                                chunk_pi_hash_digests[i][j * 8 + k].cell(),
                                snark_inputs[i * DIGEST_LEN + (3 - j) * 8 + k].cell(),
                            )?;
                        }
                    }
                }

                Ok(())
            },
        )?;

        // ==============================================
        // step 4: assert public inputs to the aggregator circuit are correct
        // ==============================================
        // accumulator
        #[cfg(not(feature = "disable_proof_aggregation"))]
        {
            assert!(accumulator_instances.len() == ACC_LEN);
            for (i, v) in accumulator_instances.iter().enumerate() {
                layouter.constrain_instance(v.cell(), config.instance, i)?;
            }
        }

        // public input hash
        for i in 0..4 {
            for j in 0..8 {
                log::trace!(
                    "pi (circuit vs real): {:?} {:?}",
                    batch_pi_hash_digest[i * 8 + j].value(),
                    self.instances()[0][(3 - i) * 8 + j + ACC_LEN]
                );

                layouter.constrain_instance(
                    batch_pi_hash_digest[i * 8 + j].cell(),
                    config.instance,
                    (3 - i) * 8 + j + ACC_LEN,
                )?;
            }
        }

        // blob data config
        {
            let barycentric_assignments = &barycentric.barycentric_assignments;
            let challenge_le = &barycentric.z_le;
            let evaluation_le = &barycentric.y_le;

            let blob_data = BlobData::from(&self.batch_hash);
            let blob_data_exports = config.blob_data_config.assign(
                &mut layouter,
                challenges,
                &config.rlc_config,
                &assigned_batch_hash.chunks_are_padding,
                &blob_data,
                barycentric_assignments,
            )?;

            layouter.assign_region(
                || "blob checks",
                |mut region| -> Result<(), Error> {
                    region.constrain_equal(
                        assigned_batch_hash.num_valid_snarks.cell(),
                        blob_data_exports.num_valid_chunks.cell(),
                    )?;

                    for (chunk_data_digest, expected_chunk_data_digest) in blob_data_exports
                        .chunk_data_digests
                        .iter()
                        .zip_eq(assigned_batch_hash.blob.chunk_tx_data_digests.iter())
                    {
                        for (c, ec) in chunk_data_digest
                            .iter()
                            .zip_eq(expected_chunk_data_digest.iter())
                        {
                            region.constrain_equal(c.cell(), ec.cell())?;
                        }
                    }

                    for (c, ec) in evaluation_le
                        .iter()
                        .zip_eq(assigned_batch_hash.blob.y.iter().rev())
                    {
                        region.constrain_equal(c.cell(), ec.cell())?;
                    }

                    for (c, ec) in challenge_le
                        .iter()
                        .zip_eq(assigned_batch_hash.blob.z.iter().rev())
                    {
                        region.constrain_equal(c.cell(), ec.cell())?;
                    }

                    for (c, ec) in blob_data_exports
                        .versioned_hash
                        .iter()
                        .zip_eq(assigned_batch_hash.blob.versioned_hash.iter())
                    {
                        region.constrain_equal(c.cell(), ec.cell())?;
                    }

                    Ok(())
                },
            )?;
        }

        end_timer!(witness_time);

        Ok(())
    }
}

impl CircuitExt<Fr> for AggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        // 12 elements from accumulator
        // 32 elements from batch's public_input_hash
        vec![ACC_LEN + DIGEST_LEN]
    }

    // 12 elements from accumulator
    // 32 elements from batch's public_input_hash
    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.flattened_instances.clone()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        // the accumulator are the first 12 cells in the instance
        Some((0..ACC_LEN).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        // - advice columns from flex gate
        // - selectors from RLC gate
        config.0.flex_gate().basic_gates[0]
            .iter()
            .map(|gate| gate.q_enable)
            .chain(
                [
                    config.0.rlc_config.selector,
                    config.0.rlc_config.enable_challenge1,
                    config.0.rlc_config.enable_challenge2,
                    config.0.blob_data_config.data_selector,
                    config.0.blob_data_config.hash_selector,
                ]
                .iter()
                .cloned(),
            )
            .collect()
    }
}
