use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::halo2::{
        halo2_ecc::halo2_base::{self, AssignedValue, Context, ContextParams},
        Halo2Loader,
    },
    pcs::kzg::{Bdfg21, Kzg, KzgAccumulator, KzgSuccinctVerifyingKey},
    util::arithmetic::fe_to_limbs,
};
use snark_verifier_sdk::{
    halo2::aggregation::{aggregate, flatten_accumulator, Svk},
    CircuitExt, NativeLoader, Snark, SnarkWitness,
};
use zkevm_circuits::util::Challenges;

use crate::{
    core::{assign_batch_hashes, extract_accumulators_and_proof},
    param::{ConfigParams, BITS, LIMBS},
    proof_aggregation::config::AggregationConfig,
    BatchHashCircuit, ChunkHash,
};

/// Aggregation circuit that does not re-expose any public inputs from aggregated snarks
#[derive(Clone)]
pub struct AggregationCircuit {
    pub(crate) svk: KzgSuccinctVerifyingKey<G1Affine>,
    pub(crate) snarks: Vec<SnarkWitness>,
    // the public instance for this circuit consists of
    // - an accumulator (12 elements)
    // - batch hash circuit's public inputs, 132 elements
    pub(crate) flattened_instances: Vec<Fr>,
    // accumulation scheme proof, private input
    pub(crate) as_proof: Value<Vec<u8>>,
    // batch hash circuit for which the snarks are generated
    pub(crate) batch_hash_circuit: BatchHashCircuit<Fr>,
}

impl AggregationCircuit {
    /// Build a new aggregation circuit for a list of __compressed__ snarks.
    /// Requires the chunk hashes that are used for the __fresh__ snark
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: &[Snark],
        rng: impl Rng + Send,
        chunk_hashes: &[ChunkHash],
    ) -> Self {
        // sanity: for each chunk we have a snark
        assert_eq!(
            snarks.len(),
            chunk_hashes.len(),
            "num of snarks ({}) does not match number of chunks ({})",
            snarks.len(),
            chunk_hashes.len(),
        );
        // sanity check: snarks's public input matches chunk_hashes
        for (chunk, snark) in chunk_hashes.iter().zip(snarks.iter()) {
            let chunk_hash_bytes = chunk.public_input_hash();
            let snark_hash_bytes = &snark.instances[0];

            for i in 0..32 {
                // wenqing: for each snark, 
                //  first 12 elements are accumulator
                //  next 32 elements are data hash (44=12+32)
                //  next 32 elements are public_input_hash
                //  data hash + public_input_hash = snark public input
                assert_eq!(
                    Fr::from(chunk.data_hash.as_bytes()[i] as u64),
                    snark_hash_bytes[i + 12]
                );

                assert_eq!(
                    Fr::from(chunk_hash_bytes[i] as u64),
                    snark_hash_bytes[i + 44]
                );
            }
        }

        // extract the accumulators and proofs
        let svk = params.get_g()[0].into();

        // wenqing: this aggregates MULTIPLE snarks 
        //  (instead of ONE as in proof compression)
        let (accumulator, as_proof) = extract_accumulators_and_proof(params, snarks, rng);
        let KzgAccumulator::<G1Affine, NativeLoader> { lhs, rhs } = accumulator;
        let acc_instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<Fq, Fr, LIMBS, BITS>)
            .concat();

        // extract the pi aggregation circuit's instances
        let batch_hash_circuit = BatchHashCircuit::construct(chunk_hashes);
        let pi_aggregation_instances = &batch_hash_circuit.instances()[0];

        let flattened_instances: Vec<Fr> = [
            acc_instances.as_slice(),
            pi_aggregation_instances.as_slice(),
        ]
        .concat();

        log::trace!("flattened instances during construction");
        for (i, e) in flattened_instances.iter().enumerate() {
            log::trace!("{}-th: {:?}", i, e);
        }

        Self {
            svk,
            snarks: snarks.iter().cloned().map_into().collect(),
            flattened_instances,
            as_proof: Value::known(as_proof),
            batch_hash_circuit,
        }
    }

    pub fn succinct_verifying_key(&self) -> &Svk {
        &self.svk
    }

    pub fn snarks(&self) -> &[SnarkWitness] {
        &self.snarks
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
            "aggregation circuit configured with k = {}  and {:?} advice columns",
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
        //   re-export all the public input of the snarks, denoted by [snarks_instances], and the
        //   accumulator [acc_instances]
        // - 2. use public input aggregation circuit to aggregate the chunks; expose the instance
        //   denoted by [pi_agg_instances]
        // - 3. assert [snarks_instances] are private inputs used for public input aggregation
        //   circuit

        // ==============================================
        // Step 1: aggregation circuit
        // ==============================================
        let mut accumulator_instances: Vec<AssignedValue<Fr>> = vec![];
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
                        max_rows: config.gate().max_rows,
                        num_context_ids: 1,
                        fixed_columns: config.gate().constants.clone(),
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
                    &self.snarks,
                    self.as_proof(),
                );
                log::trace!("aggregation circuit during assigning");
                for (i, e) in assigned_aggregation_instances[0].iter().enumerate() {
                    log::trace!("{}-th instance: {:?}", i, e.value)
                }

                // extract the following cells for later constraints
                // - the accumulators
                // - the public input from snark
                accumulator_instances.extend(flatten_accumulator(acc).iter().copied());
                // - the snark is not a fresh one, assigned_instances already contains an
                //   accumulator so we want to skip the first 12 elements from the public input
                snark_inputs.extend(
                    assigned_aggregation_instances
                        .iter()
                        .flat_map(|instance_column| instance_column.iter().skip(12)),
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
        // assert the accumulator in aggregation instance matchs public input
        for (i, v) in accumulator_instances.iter().enumerate() {
            layouter.constrain_instance(v.cell(), config.instance, i)?;
        }

        // ==============================================
        // step 2: public input aggregation circuit
        // ==============================================
        // extract all the hashes and load them to the hash table
        let challenges = challenge.values(&layouter);

        let timer = start_timer!(|| ("extract hash").to_string());
        let preimages = self.batch_hash_circuit.extract_hash_preimages();
        end_timer!(timer);

        let timer = start_timer!(|| ("load aux table").to_string());
        config
            .keccak_circuit_config
            .load_aux_tables(&mut layouter)?;
        end_timer!(timer);

        let timer = start_timer!(|| ("assign cells").to_string());
        let (hash_input_cells, hash_output_cells) = assign_batch_hashes(
            &config.keccak_circuit_config,
            &mut layouter,
            challenges,
            &preimages,
        )?;
        end_timer!(timer);

        log::trace!("hash input");
        for v in hash_input_cells.iter() {
            for (i, c) in v.iter().enumerate() {
                log::trace!("{}-th {:?}", i, c.value())
            }
        }
        log::trace!("hash output");
        for v in hash_output_cells.iter() {
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
        layouter.assign_region(
            || "glue circuits",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                for chunk_idx in 0..self.snarks.len() {
                    // step 3.1, data hash
                    // - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
                    // where batch_data_hash is the second hash for pi aggregation
                    for i in 0..32 {
                        region.constrain_equal(
                            // the first 32 inputs for the snark
                            snark_inputs[64 * chunk_idx + i].cell(),
                            hash_input_cells[1][chunk_idx * 32 + i].cell(),
                        )?;
                    }
                    // step 3.2, public input hash
                    // the public input hash for the i-th snark is the (i+2)-th hash
                    for i in 0..4 {
                        for j in 0..8 {
                            region.constrain_equal(
                                // the second 32 inputs for the snark
                                snark_inputs[64 * chunk_idx + i * 8 + j + 32].cell(),
                                hash_output_cells[chunk_idx + 2][(3 - i) * 8 + j].cell(),
                            )?;
                        }
                    }
                }

                Ok(())
            },
        )?;

        // ====================================================
        // Last step: Constraint the hash data matches the raw public input
        // ====================================================
        let acc_len = 12;
        {
            for i in 0..32 {
                // first_chunk_prev_state_root
                layouter.constrain_instance(
                    hash_input_cells[2][4 + i].cell(),
                    config.instance,
                    i + acc_len,
                )?;
                // last_chunk_post_state_root
                layouter.constrain_instance(
                    hash_input_cells.last().unwrap()[36 + i].cell(),
                    config.instance,
                    i + 32 + acc_len,
                )?;
                // last_chunk_withdraw_root
                layouter.constrain_instance(
                    hash_input_cells.last().unwrap()[68 + i].cell(),
                    config.instance,
                    i + 64 + acc_len,
                )?;
            }
            // batch_public_input_hash
            for i in 0..4 {
                for j in 0..8 {
                    // digest in circuit has a different endianness
                    // wenqing: 96 is the byte position for batch data hash
                    layouter.constrain_instance(
                        hash_output_cells[0][(3 - i) * 8 + j].cell(),
                        config.instance,
                        i * 8 + j + 96 + acc_len,
                    )?;
                }
            }
            // last 4 inputs are the chain id
            // wenqing: chain_id is put at last for instance
            for i in 0..4 {
                layouter.constrain_instance(
                    hash_input_cells[0][i].cell(),
                    config.instance,
                    128 + acc_len + i,
                )?;
            }
        }

        end_timer!(witness_time);
        Ok(())
    }
}
