use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::{Circuit, ConstraintSystem, Error, Selector},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::{
        halo2::{
            halo2_ecc::halo2_base::{self, AssignedValue, Context, ContextParams},
            Halo2Loader,
        },
        native::NativeLoader,
    },
    pcs::kzg::{Bdfg21, Kzg, KzgAccumulator, KzgSuccinctVerifyingKey},
    util::arithmetic::fe_to_limbs,
};
use snark_verifier_sdk::{aggregate, flatten_accumulator, CircuitExt, Snark, SnarkWitness};
use zkevm_circuits::util::Challenges;

use crate::{
    batch::BatchHash,
    constants::{ACC_LEN, BITS, DIGEST_LEN, LIMBS, MAX_AGG_SNARKS},
    core::{assign_batch_hashes, extract_accumulators_and_proof},
    util::parse_hash_digest_cells,
    ConfigParams,
};

use super::AggregationConfig;

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
    // the chunks in this batch are also padded already
    pub(crate) batch_hash: BatchHash,
}

impl AggregationCircuit {
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks_with_padding: &[Snark],
        rng: impl Rng + Send,
        batch_hash: BatchHash,
    ) -> Self {
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
        let public_input_hash = &batch_hash.instances_exclude_acc()[0];

        // the public instance for this circuit consists of
        // - an accumulator (12 elements)
        // - the batch's public_input_hash (32 elements)
        // - the number of snarks that is aggregated (1 element)
        let flattened_instances: Vec<Fr> = [
            acc_instances.as_slice(),
            public_input_hash.as_slice(),
            &[Fr::from(batch_hash.number_of_valid_chunks as u64)],
        ]
        .concat();

        end_timer!(timer);
        Self {
            svk,
            snarks_with_padding: snarks_with_padding.iter().cloned().map_into().collect(),
            flattened_instances,
            as_proof: Value::known(as_proof),
            batch_hash,
        }
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

        let timer = start_timer!(|| "aggregation");
        #[cfg(feature = "wip")]
        {
            // ==============================================
            // Step 1: snark aggregation circuit
            // ==============================================
            config
                .range()
                .load_lookup_table(&mut layouter)
                .expect("load range lookup table");

            let mut first_pass = halo2_base::SKIP_FIRST_PASS;

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

            assert_eq!(snark_inputs.len(), MAX_AGG_SNARKS * DIGEST_LEN);
        }
        end_timer!(timer);
        // ==============================================
        // step 2: public input aggregation circuit
        // ==============================================
        // extract all the hashes and load them to the hash table
        let challenges = challenge.values(&layouter);

        let timer = start_timer!(|| "load aux table");
        config
            .keccak_circuit_config
            .load_aux_tables(&mut layouter)?;
        end_timer!(timer);

        let timer = start_timer!(|| "extract hash");
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

        let timer = start_timer!(|| ("assign hash cells").to_string());
        let (_hash_preimage_cells, hash_digest_cells, data_rlc_cells) = assign_batch_hashes(
            &config,
            &mut layouter,
            challenges,
            &preimages,
            self.batch_hash.number_of_valid_chunks,
        )
        .unwrap();

        // digests
        let (batch_pi_hash_digest, chunk_pi_hash_digests, _potential_batch_data_hash_digest) =
            parse_hash_digest_cells(&hash_digest_cells);
        end_timer!(timer);

        #[cfg(feature = "wip")]
        {
            // ==============================================
            // step 3: assert public inputs to the snarks are correct
            // ==============================================

            layouter.assign_region(
                || "aggregation",
                |mut region| {
                    for i in 0..MAX_AGG_SNARKS {
                        for j in 0..4 {
                            for k in 0..8 {
                                let mut t1 = Fr::default();
                                let mut t2 = Fr::default();
                                chunk_pi_hash_digests[i][j * 8 + k].value().map(|x| t1 = *x);
                                snark_inputs[i * DIGEST_LEN + (3 - j) * 8 + k]
                                    .value()
                                    .map(|x| t2 = *x);
                                assert_eq!(t1, t2);

                                region.constrain_equal(
                                    chunk_pi_hash_digests[i][j * 8 + k].cell(),
                                    snark_inputs[i * DIGEST_LEN + (3 - j) * 8 + k].cell(),
                                )?;
                            }
                        }
                    }

                    Ok(())
                },
            )?;
        }

        // ==============================================
        // step 4: assert public inputs to the aggregator circuit are correct
        // ==============================================
        // accumulator
        #[cfg(feature = "wip")]
        {
            assert!(accumulator_instances.len() == ACC_LEN);
            for (i, v) in accumulator_instances.iter().enumerate() {
                layouter.constrain_instance(v.cell(), config.instance, i)?;
            }
        }
        // public input hash

        println!("hash digest");
        for (i, e) in batch_pi_hash_digest.iter().enumerate() {
            println!("{}: {:?}", i, e.value())
        }
        println!();
        println!("instance");
        for (i, e) in self.instances()[0].iter().enumerate() {
            println!("{}: {:?}", i, e)
        }

        for i in 0..4 {
            for j in 0..8 {
                layouter.constrain_instance(
                    batch_pi_hash_digest[i * 8 + j].cell(),
                    config.instance,
                    (3 - i) * 8 + j + ACC_LEN,
                )?;
            }
        }

        end_timer!(witness_time);
        Ok(())
    }
}

impl CircuitExt<Fr> for AggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        // 12 elements from accumulator
        // 32 elements from batch's public_input_hash
        // 1 element for # of valid chunks
        vec![ACC_LEN + DIGEST_LEN]
    }

    // 12 elements from accumulator
    // 32 elements from batch's public_input_hash
    // 1 element for # of valid chunks
    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.flattened_instances.clone()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        // the accumulator are the first 12 cells in the instance
        Some((0..ACC_LEN).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        // - advice columns from flex gate
        // - selector from RLC gate
        config.0.flex_gate().basic_gates[0]
            .iter()
            .map(|gate| gate.q_enable)
            .into_iter()
            .chain([config.0.rlc_config.selector].iter().cloned())
            .collect()
    }
}
