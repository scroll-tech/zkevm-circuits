use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{Circuit, ConstraintSystem, Error, Selector},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::halo2::{
        halo2_ecc::{
            ecc::EccChip,
            fields::fp::FpConfig,
            halo2_base::{Context, ContextParams},
        },
        Halo2Loader,
    },
    pcs::kzg::KzgSuccinctVerifyingKey,
};
use snark_verifier_sdk::{
    aggregate, flatten_accumulator, types::KzgBDFG, CircuitExt, Snark, SnarkWitness,
};
use std::{env, fs::File, rc::Rc};
use zkevm_circuits::util::Challenges;

use crate::{
    aggregation::{decoder::WORKED_EXAMPLE, witgen::process},
    batch::BatchInfo,
    blob::BatchData,
    constants::{ACC_LEN, DIGEST_LEN},
    core::{assign_batch_hashes, extract_proof_and_instances_with_pairing_check},
    util::parse_hash_digest_cells,
    witgen::{zstd_encode, MultiBlockProcessResult},
    AssignedBarycentricEvaluationConfig, BatchCircuitConfig, ConfigParams, LOG_DEGREE, PI_CHAIN_ID,
    PI_CURRENT_BATCH_HASH, PI_CURRENT_STATE_ROOT, PI_CURRENT_WITHDRAW_ROOT, PI_PARENT_BATCH_HASH,
    PI_PARENT_STATE_ROOT,
};

/// The circuit is designed to handle various validity checks. Consequently, its configuration encapsulates
/// multiple inner configurations that independently verify different requirements. Once witness values
/// are assigned to all the member circuits/tables, relevant exported cells are connected to establish
/// constrained links between certain components.
///
/// A batch is essentially a collection of chunks, where each chunk has been pre-validated, and the proof
/// SNARK configures the batch circuit.
///
/// Our goal is to make the batch data available on the settlement layer by submitting it via an EIP-4844
/// blob-carrying transaction. However, the data within the blob sidecar is a zstd-compressed version of
/// the batch data, combined with some metadata.
///
/// The blob’s bytes are assigned as witness to the `BlobDataConfig`, while the batch’s metadata and
/// the raw batch data (a list of RLP-encoded L2 transactions) are assigned as witness to the `BatchDataConfig`.
///
/// Using the `DecoderConfig`, the following constraints are established:
/// - `blob_data::rlc == decoder::encoded_rlc`
/// - `batch_data::rlc == decoder::decoded_rlc`
///
/// This essentially ensures that the blob represents a zstd-compressed version of the batch.
///
/// It is important to note that the blob bytes are received as private witnesses, and the blob sidecar
/// is not accessible to the Ethereum execution client. Therefore, an additional consistency check is required
/// to ensure that the blob bytes provided as private witnesses are indeed the same as those attached on-chain.
///
/// This is achieved by:
/// - Calling the point-evaluation precompile on-chain, which verifies the KZG opening proof for the blob
/// polynomial at a random point `z` (with the evaluation result `y`)
/// - Including `z` and the evaluation result `y` as public inputs to the batch circuit
/// - Evaluating the blob polynomial in-circuit at point `z`, constructed using the batch data itself
/// , as a Fiat-Shamir challenge.
///
/// The in-circuit evaluation of the blob polynomial is performed using the `BarycentricConfig`.
///
/// Finally, additional checks are performed to verify the correctness of the chunk SNARKs provided to
/// the batch circuit for aggregation. Since the chunks must be ‘continuous,’ the post and pre-roots
/// of the chunks are connected. We support aggregating up to a specified maximum number of SNARKs.
/// However, to avoid dynamic configurations, the batch circuit mandates that exactly this upper bound
/// is used. If there are fewer meaningful SNARKs, the last meaningful SNARK is repeated to pad the input.
#[derive(Clone)]
pub struct BatchCircuit<const N_SNARKS: usize> {
    pub svk: KzgSuccinctVerifyingKey<G1Affine>,
    // the input snarks for the aggregation circuit
    // it is padded already so it will have a fixed length of N_SNARKS
    pub snarks_with_padding: Vec<SnarkWitness>,
    // The public instance for this circuit consists of
    // - accumulator (12 elements)
    // - parent_state_root (2 elements, split hi_lo)
    // - parent_batch_hash (2 elements)
    // - state_root (2 elements)
    // - batch_hash (2 elements)
    // - chain id (1 element)
    // - withdraw_root (2 elements)
    pub flattened_instances: Vec<Fr>,
    // accumulation scheme proof, private input
    pub as_proof: Value<Vec<u8>>,
    // batch hash circuit for which the snarks are generated
    // the chunks in this batch are also padded already
    pub batch_info: BatchInfo<N_SNARKS>,
}

impl<const N_SNARKS: usize> BatchCircuit<N_SNARKS> {
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks_with_padding: &[Snark],
        rng: impl Rng + Send,
        batch_info: BatchInfo<N_SNARKS>,
    ) -> Result<Self, snark_verifier::Error> {
        let timer = start_timer!(|| "generate aggregation circuit");

        // sanity check: snarks's public input matches chunk_hashes
        for (chunk, snark) in batch_info
            .padded_chunks
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
        let (as_proof, accumulator_instances) =
            extract_proof_and_instances_with_pairing_check(params, snarks_with_padding, rng)?;

        // The public instance for this circuit consists of
        // - an accumulator (12 elements)
        // - parent_state_root (2 elements, split hi_lo)
        // - parent_batch_hash (2 elements)
        // - state_root (2 elements)
        // - batch_hash (2 elements)
        // - chain id (1 element)
        // - withdraw_root (2 elements)
        let flattened_instances: Vec<Fr> = [
            accumulator_instances.as_slice(),
            batch_info.instances_exclude_acc::<Fr>()[0].as_slice(),
        ]
        .concat();

        end_timer!(timer);

        Ok(Self {
            svk,
            snarks_with_padding: snarks_with_padding.iter().cloned().map_into().collect(),
            flattened_instances,
            as_proof: Value::known(as_proof),
            batch_info,
        })
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}

impl<const N_SNARKS: usize> Circuit<Fr> for BatchCircuit<N_SNARKS> {
    type Config = (BatchCircuitConfig<N_SNARKS>, Challenges);

    type FloorPlanner = SimpleFloorPlanner;

    type Params = ();

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

        let challenges = Challenges::construct_p1(meta);
        let config = BatchCircuitConfig::configure(meta, &params, challenges);
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
        let (accumulator_instances, snark_inputs, barycentric) = {
            use halo2_proofs::halo2curves::bn256::Fq;
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

                    let ctx = Context::new(
                        region,
                        ContextParams {
                            max_rows: config.flex_gate().max_rows,
                            num_context_ids: 1,
                            fixed_columns: config.flex_gate().constants.clone(),
                        },
                    );

                    let ecc_chip = config.ecc_chip();
                    let loader: Rc<Halo2Loader<G1Affine, EccChip<Fr, FpConfig<Fr, Fq>>>> =
                        Halo2Loader::new(ecc_chip, ctx);

                    // Extract the assigned values for
                    // - instances which are the public inputs of each chunk (prefixed with 12
                    //   instances from previous accumulators)
                    // - new accumulator
                    log::debug!("aggregation: chunk aggregation");
                    let (assigned_aggregation_instances, acc) = aggregate::<KzgBDFG>(
                        &self.svk,
                        &loader,
                        &self.snarks_with_padding,
                        self.as_proof(),
                    );
                    for (i, e) in assigned_aggregation_instances[0].iter().enumerate() {
                        log::trace!("{}-th instance: {:?}", i, e.value)
                    }

                    // extract the following cells for later constraints
                    // - the accumulators
                    // - the public inputs from each snark
                    let accumulator_instances = flatten_accumulator(acc);
                    // the snark is not a fresh one, assigned_instances already contains an
                    // accumulator so we want to skip the first 12 elements from the public
                    // input
                    let snark_inputs = assigned_aggregation_instances
                        .iter()
                        .flat_map(|instance_column| instance_column.iter().skip(ACC_LEN))
                        .copied()
                        .collect_vec();

                    loader
                        .ctx_mut()
                        .print_stats(&["snark aggregation [chunks -> batch]"]);

                    let mut ctx = Rc::into_inner(loader).unwrap().into_ctx();
                    log::debug!("batching: assigning barycentric");
                    let barycentric = config.barycentric.assign(
                        &mut ctx,
                        &self.batch_info.point_evaluation_assignments.coefficients,
                        self.batch_info
                            .point_evaluation_assignments
                            .challenge_digest,
                        self.batch_info.point_evaluation_assignments.evaluation,
                    );

                    ctx.print_stats(&["barycentric"]);

                    config.range().finalize(&mut ctx);

                    Ok((accumulator_instances, snark_inputs, barycentric))
                },
            )?;

            (accumulator_instances, snark_inputs, barycentric)
        };
        end_timer!(timer);

        assert!(accumulator_instances.len() == ACC_LEN);
        for (i, v) in accumulator_instances.iter().enumerate() {
            layouter.constrain_instance(v.cell(), config.instance, i)?;
        }

        // ==============================================
        // step 2: public input batch circuit
        // ==============================================
        // extract all the hashes and load them to the hash table
        let challenges = challenge.values(&layouter);

        let timer = start_timer!(|| "load aux table");

        let assigned_batch_hash = {
            config.keccak.load_aux_tables(&mut layouter)?;
            end_timer!(timer);

            let timer = start_timer!(|| "extract hash");
            // orders:
            // - batch_hash
            // - chunk\[i\].piHash for i in \[0, N_SNARKS)
            // - batch_data_hash_preimage
            // - preimage for blob metadata
            // - preimage of chunk data digest (only for valid chunks)
            // - preimage of challenge digest
            let preimages = self.batch_info.extract_hash_preimages();
            assert_eq!(
                preimages.len(),
                4 + N_SNARKS + self.batch_info.num_valid_chunks,
                "error extracting preimages"
            );
            end_timer!(timer);

            let timer = start_timer!(|| ("assign hash cells").to_string());
            let chunks_are_valid = self
                .batch_info
                .padded_chunks
                .iter()
                .map(|chunk| !chunk.is_padding)
                .collect::<Vec<_>>();
            let assigned_batch_hash = assign_batch_hashes::<N_SNARKS>(
                &config.keccak,
                &config.rlc,
                &mut layouter,
                challenges,
                &chunks_are_valid,
                self.batch_info.num_valid_chunks,
                &preimages,
            )
            .map_err(|e| {
                log::error!("assign_batch_hashes err {:#?}", e);
                Error::ConstraintSystemFailure
            })?;

            end_timer!(timer);

            assigned_batch_hash
        };

        // Extract digests
        let (_batch_hash_digest, chunk_pi_hash_digests, _potential_batch_data_hash_digest) =
            parse_hash_digest_cells::<N_SNARKS>(&assigned_batch_hash.hash_output);

        // ========================================================================
        // step 2.a: check accumulator including public inputs to the snarks
        // ========================================================================
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        layouter.assign_region(
            || "BatchCircuit: Chunk PI",
            |mut region| -> Result<(), Error> {
                if first_pass {
                    // this region only use copy constraints and do not affect the shape of the
                    // layouter
                    first_pass = false;
                    return Ok(());
                }

                for i in 0..N_SNARKS {
                    for j in 0..DIGEST_LEN {
                        let mut t1 = Fr::default();
                        let mut t2 = Fr::default();
                        chunk_pi_hash_digests[i][j].value().map(|x| t1 = *x);
                        snark_inputs[i * DIGEST_LEN + j].value().map(|x| t2 = *x);
                        log::trace!(
                            "{}-th snark: {:?} {:?}",
                            i,
                            chunk_pi_hash_digests[i][j].value(),
                            snark_inputs[i * DIGEST_LEN + j].value()
                        );

                        region.constrain_equal(
                            chunk_pi_hash_digests[i][j].cell(),
                            snark_inputs[i * DIGEST_LEN + j].cell(),
                        )?;
                    }
                }

                Ok(())
            },
        )?;

        // ========================================================================
        // step 2.b: constrain extracted public input cells against actual instance
        // ========================================================================
        let public_input_cells = assigned_batch_hash.public_input_cells;
        let instance_offsets: Vec<usize> = vec![
            PI_PARENT_BATCH_HASH,
            PI_PARENT_BATCH_HASH + 1,
            PI_CURRENT_BATCH_HASH,
            PI_CURRENT_BATCH_HASH + 1,
            PI_PARENT_STATE_ROOT,
            PI_PARENT_STATE_ROOT + 1,
            PI_CURRENT_STATE_ROOT,
            PI_CURRENT_STATE_ROOT + 1,
            PI_CURRENT_WITHDRAW_ROOT,
            PI_CURRENT_WITHDRAW_ROOT + 1,
            PI_CHAIN_ID,
        ];
        for (c, instance_offset) in public_input_cells
            .as_vec()
            .iter()
            .zip_eq(instance_offsets.into_iter())
        {
            layouter.constrain_instance(c.cell(), config.instance, instance_offset)?;
        }

        // blob data config
        {
            let barycentric_assignments = &barycentric.barycentric_assignments;
            let challenge_le = &barycentric.z_le;
            let evaluation_le = &barycentric.y_le;

            let batch_data = BatchData::from(&self.batch_info);

            let blob_data_exports = config.blob_data.assign(
                &mut layouter,
                challenges,
                &config.rlc,
                &self.batch_info.blob_bytes,
                barycentric_assignments,
            )?;

            let batch_data_exports = config.batch_data.assign(
                &mut layouter,
                challenges,
                &config.rlc,
                &assigned_batch_hash.chunks_are_padding,
                &batch_data,
                self.batch_info.versioned_hash,
                barycentric_assignments,
            )?;

            // conditionally encode those bytes. By default we use a worked example.
            let raw_bytes = if blob_data_exports.enable_encoding_bool {
                batch_data.get_batch_data_bytes()
            } else {
                WORKED_EXAMPLE.as_bytes().to_vec()
            };
            let encoded_bytes = zstd_encode(&raw_bytes);

            let MultiBlockProcessResult {
                witness_rows,
                literal_bytes: decoded_literals,
                fse_aux_tables,
                block_info_arr,
                sequence_info_arr,
                address_table_rows: address_table_arr,
                sequence_exec_results,
            } = process(&encoded_bytes, challenges.keccak_input());

            // sanity check
            let (recovered_bytes, sequence_exec_info_arr) = sequence_exec_results.into_iter().fold(
                (Vec::new(), Vec::new()),
                |(mut out_byte, mut out_exec), res| {
                    out_byte.extend(res.recovered_bytes);
                    out_exec.push(res.exec_trace);
                    (out_byte, out_exec)
                },
            );
            if blob_data_exports.enable_encoding_bool {
                assert_eq!(
                    raw_bytes, recovered_bytes,
                    "original and recovered bytes mismatch"
                );
            }

            let decoder_exports = config.decoder.assign(
                &mut layouter,
                &raw_bytes,
                &encoded_bytes,
                witness_rows,
                decoded_literals,
                fse_aux_tables,
                block_info_arr,
                sequence_info_arr,
                address_table_arr,
                sequence_exec_info_arr,
                &challenges,
                LOG_DEGREE, // TODO: configure k for batch circuit instead of hard-coded here.
            )?;

            layouter.assign_region(
                || "consistency checks",
                |mut region| -> Result<(), Error> {
                    // Initialise the RLC config for basic arithmetic/conditional checks.
                    config.rlc.init(&mut region)?;
                    let mut rlc_config_offset = 0;

                    region.constrain_equal(
                        assigned_batch_hash.num_valid_snarks.cell(),
                        batch_data_exports.num_valid_chunks.cell(),
                    )?;

                    for (chunk_data_digest, expected_chunk_data_digest) in batch_data_exports
                        .chunk_data_digests
                        .iter()
                        .zip_eq(assigned_batch_hash.blob.chunk_tx_data_digests.iter())
                    {
                        for (c, ec) in chunk_data_digest
                            .iter()
                            .zip_eq(expected_chunk_data_digest.iter())
                        {
                            log::trace!("blob chunk tx: {:?} {:?}", c.value(), ec.value());
                            region.constrain_equal(c.cell(), ec.cell())?;
                        }
                    }

                    for (c, ec) in evaluation_le
                        .iter()
                        .zip_eq(assigned_batch_hash.blob.y.iter().rev())
                    {
                        log::trace!("blob y: {:?} {:?}", c.value(), ec.value());
                        region.constrain_equal(c.cell(), ec.cell())?;
                    }

                    for (c, ec) in challenge_le
                        .iter()
                        .zip_eq(assigned_batch_hash.blob.z.iter().rev())
                    {
                        log::trace!("blob z: {:?} {:?}", c.value(), ec.value());
                        region.constrain_equal(c.cell(), ec.cell())?;
                    }

                    for (c, ec) in batch_data_exports
                        .versioned_hash
                        .iter()
                        .zip_eq(assigned_batch_hash.blob.versioned_hash.iter())
                    {
                        log::trace!("blob version hash: {:?} {:?}", c.value(), ec.value());
                        region.constrain_equal(c.cell(), ec.cell())?;
                    }

                    // do we encode batch data to blob? or not.
                    let enable_encoding = blob_data_exports.enable_encoding.clone();
                    let disable_encoding =
                        config
                            .rlc
                            .not(&mut region, &enable_encoding, &mut rlc_config_offset)?;

                    // equate rlc (from blob data) with decoder's encoded_rlc
                    let (conditional_blob_rlc, conditional_encoded_rlc) = (
                        config.rlc.mul(
                            &mut region,
                            &blob_data_exports.bytes_rlc,
                            &enable_encoding,
                            &mut rlc_config_offset,
                        )?,
                        config.rlc.mul(
                            &mut region,
                            &decoder_exports.encoded_rlc,
                            &enable_encoding,
                            &mut rlc_config_offset,
                        )?,
                    );
                    region.constrain_equal(
                        conditional_blob_rlc.cell(),
                        conditional_encoded_rlc.cell(),
                    )?;

                    // equate len(blob_bytes) with decoder's encoded_len
                    let (conditional_blob_len, conditional_encoded_len) = (
                        config.rlc.mul(
                            &mut region,
                            &blob_data_exports.cooked_len,
                            &enable_encoding,
                            &mut rlc_config_offset,
                        )?,
                        config.rlc.mul(
                            &mut region,
                            &decoder_exports.encoded_len,
                            &enable_encoding,
                            &mut rlc_config_offset,
                        )?,
                    );
                    region.constrain_equal(
                        conditional_blob_len.cell(),
                        conditional_encoded_len.cell(),
                    )?;

                    // equate rlc (from batch data) with decoder's decoded_rlc
                    let (conditional_batch_rlc, conditional_decoded_rlc) = (
                        config.rlc.mul(
                            &mut region,
                            &batch_data_exports.bytes_rlc,
                            &enable_encoding,
                            &mut rlc_config_offset,
                        )?,
                        config.rlc.mul(
                            &mut region,
                            &decoder_exports.decoded_rlc,
                            &enable_encoding,
                            &mut rlc_config_offset,
                        )?,
                    );
                    region.constrain_equal(
                        conditional_batch_rlc.cell(),
                        conditional_decoded_rlc.cell(),
                    )?;

                    // equate len(batch_data) with decoder's decoded_len
                    let (conditional_batch_len, conditional_decoded_len) = (
                        config.rlc.mul(
                            &mut region,
                            &batch_data_exports.batch_data_len,
                            &enable_encoding,
                            &mut rlc_config_offset,
                        )?,
                        config.rlc.mul(
                            &mut region,
                            &decoder_exports.decoded_len,
                            &enable_encoding,
                            &mut rlc_config_offset,
                        )?,
                    );
                    region.constrain_equal(
                        conditional_batch_len.cell(),
                        conditional_decoded_len.cell(),
                    )?;

                    // if we do not enable encoding, then blob == batch (rlc).
                    let (conditional_blob_rlc, conditional_batch_rlc) = (
                        config.rlc.mul(
                            &mut region,
                            &blob_data_exports.bytes_rlc,
                            &disable_encoding,
                            &mut rlc_config_offset,
                        )?,
                        config.rlc.mul(
                            &mut region,
                            &batch_data_exports.bytes_rlc,
                            &disable_encoding,
                            &mut rlc_config_offset,
                        )?,
                    );
                    region.constrain_equal(
                        conditional_blob_rlc.cell(),
                        conditional_batch_rlc.cell(),
                    )?;

                    // if we do not enable encoding, then blob == batch (len).
                    let (conditional_blob_len, conditional_batch_len) = (
                        config.rlc.mul(
                            &mut region,
                            &blob_data_exports.bytes_len,
                            &disable_encoding,
                            &mut rlc_config_offset,
                        )?,
                        config.rlc.mul(
                            &mut region,
                            &batch_data_exports.batch_data_len,
                            &disable_encoding,
                            &mut rlc_config_offset,
                        )?,
                    );
                    region.constrain_equal(
                        conditional_blob_len.cell(),
                        conditional_batch_len.cell(),
                    )?;

                    Ok(())
                },
            )?;
        }

        end_timer!(witness_time);

        Ok(())
    }
}

impl<const N_SNARKS: usize> CircuitExt<Fr> for BatchCircuit<N_SNARKS> {
    fn num_instance(&self) -> Vec<usize> {
        // - 12 elements from accumulator
        // - parent_state_root (2 elements, split hi_lo)
        // - parent_batch_hash (2 elements)
        // - state_root (2 elements)
        // - batch_hash (2 elements)
        // - chain id (1 element)
        // - withdraw_root (2 elements)
        vec![ACC_LEN + 11]
    }

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
                    config.0.rlc.selector,
                    config.0.rlc.lookup_gate_selector,
                    config.0.rlc.enable_challenge1,
                    config.0.rlc.enable_challenge2,
                    config.0.batch_data.data_selector,
                    config.0.batch_data.hash_selector,
                ]
                .iter()
                .cloned(),
            )
            .collect()
    }
}
