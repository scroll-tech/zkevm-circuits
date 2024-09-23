//! Circuit implementation for compression circuit.

use crate::params::ConfigParams;
use ark_std::{end_timer, start_timer};
use ce_snark_verifier::halo2_base::gates::circuit::{BaseConfig, CircuitBuilderStage};
use ce_snark_verifier_sdk::{
    gen_pk,
    halo2::aggregation::{AggregationCircuit, AggregationConfigParams, VerifierUniversality},
    CircuitExt as CeCircuitExt, SHPLONK,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, Selector},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use halo2curves::{
    bn256::{Bn256, Fr},
    pairing::Engine,
};
use rand::Rng;
use snark_verifier::{
    loader::native::NativeLoader, pcs::kzg::KzgAccumulator, verifier::PlonkVerifier,
};
use snark_verifier_sdk::{
    types::{PoseidonTranscript, Shplonk, POSEIDON_SPEC},
    CircuitExt,
};
use std::fs::File;

/// Input a proof, this compression circuit generates a new proof that may have smaller size.
///
/// It re-exposes same public inputs from the input snark.
/// All this circuit does is to reduce the proof size.
#[derive(Clone, Debug)]
pub struct CompressionCircuit(AggregationCircuit);

impl Circuit<Fr> for CompressionCircuit {
    type Params = (); // TODO: use BaseCircuitParams?
    type Config = BaseConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self(self.0.without_witnesses())
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        AggregationCircuit::configure_with_params(meta, load_params())
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let witness_time = start_timer!(|| "synthesize | compression Circuit");
        let result = self.0.synthesize(config, layouter);
        end_timer!(witness_time);
        result
    }
}

impl CircuitExt<Fr> for CompressionCircuit {
    fn num_instance(&self) -> Vec<usize> {
        self.0.num_instance()
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        self.0.instances()
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        AggregationCircuit::accumulator_indices()
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        AggregationCircuit::selectors(config)
    }
}

impl CeCircuitExt<Fr> for CompressionCircuit {
    fn num_instance(&self) -> Vec<usize> {
        self.0.num_instance()
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        self.0.instances()
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        AggregationCircuit::accumulator_indices()
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        AggregationCircuit::selectors(config)
    }
}

impl CompressionCircuit {
    /// Build a new circuit from a snark, with a flag whether this snark has been compressed before
    pub fn new(
        degree: u32,
        params: &ParamsKZG<Bn256>,
        snark: snark_verifier_sdk::Snark,
        has_accumulator: bool,
        rng: impl Rng + Send,
    ) -> Result<Self, ce_snark_verifier::Error> {
        // compression_debug
        // verify_snark_accumulator_pairing(&snark, params)
        //     .expect("Compression circuit accumulator pre-check should not fail.");
        Self::new_from_ce_snark(degree, params, to_ce_snark(&snark), has_accumulator, rng)
    }

    pub fn new_from_ce_snark(
        degree: u32,
        params: &ParamsKZG<Bn256>,
        snark: ce_snark_verifier_sdk::Snark,
        has_accumulator: bool,
        _rng: impl Rng + Send, // TODO: hook this up to the rng in AggregationCircuit? is that even needed?
    ) -> Result<Self, ce_snark_verifier::Error> {
        println!("");
        println!("");
        println!("");
        println!("=> Constructing compression circuit");

        // compression_debug
        // let mut inner = AggregationCircuit::new::<SHPLONK>(
        //     CircuitBuilderStage::Mock,
        //     load_params(),
        //     params,
        //     [snark],
        //     VerifierUniversality::None,
        // );
        // inner.expose_previous_instances(has_accumulator);
        // Ok(Self(inner))

        let lookup_bits = degree as usize - 1;
        let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            AggregationConfigParams { degree, lookup_bits, ..Default::default() },
            &params,
            [snark.clone()],
            VerifierUniversality::Full,
        );
        println!("=> After AggregationCircuit::new::<SHPLONK>");

        let agg_config = agg_circuit.calculate_params(Some(10));

        println!("=> After agg_config");
        println!("=> agg_config: {:?}", agg_config);

        let _pk = gen_pk(&params, &agg_circuit, None);
        let break_points = agg_circuit.break_points();
        drop(agg_circuit);
    
        let mut inner = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            agg_config,
            &params,
            [snark],
            VerifierUniversality::Full,
        )
        .use_break_points(break_points);
        inner.expose_previous_instances(has_accumulator);

        Ok(Self(inner))

        // let _proof = gen_evm_proof_shplonk(&params, &pk, agg_circuit, instances.clone());

        // let _deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
        //     &params,
        //     pk.get_vk(),
        //     num_instances,
        //     Some(Path::new("examples/StandardPlonkVerifier.sol")),
        // );
    }
}

pub(crate) fn verify_snark_accumulator_pairing<'a>(
    snark: &'a snark_verifier_sdk::Snark,
    params: &ParamsKZG<Bn256>,
) -> Result<&'a snark_verifier_sdk::Snark, snark_verifier::Error> {
    let svk = params.get_g()[0].into();
    let mut transcript_read =
        PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&[], POSEIDON_SPEC.clone());

    transcript_read.new_stream(snark.proof.as_slice());

    let proof = Shplonk::read_proof(
        &svk,
        &snark.protocol,
        &snark.instances,
        &mut transcript_read,
    );

    for (idx, acc) in Shplonk::succinct_verify(&svk, &snark.protocol, &snark.instances, &proof)
        .into_iter()
        .enumerate()
    {
        let KzgAccumulator { lhs, rhs } = acc;
        let left = Bn256::pairing(&lhs, &params.g2());
        let right = Bn256::pairing(&rhs, &params.s_g2());

        log::trace!("compression circuit accumulator pre-check: left {:?}", left);
        log::trace!(
            "compression circuit accumulator pre-check: right {:?}",
            right
        );

        if left != right {
            return Err(snark_verifier::Error::AssertionFailure(format!(
                "accumulator check failed in compression circuit construction {left:?} {right:?}, {idx:?}",
            )));
        }
    }

    Ok(snark)
}

fn load_params() -> AggregationConfigParams {
    let path = std::env::var("COMPRESSION_CONFIG")
        .unwrap_or_else(|_| "configs/compression_wide.config".to_owned());
    let params: ConfigParams = serde_json::from_reader(
        File::open(path.as_str()).unwrap_or_else(|_| panic!("{path:?} does not exist")),
    )
    .unwrap_or_else(|_| ConfigParams::default_compress_wide_param());

    log::info!(
        "compression circuit configured with k = {} and {:?} advice columns",
        params.degree,
        params.num_advice
    );

    AggregationConfigParams {
        degree: params.degree,
        num_advice: *params.num_advice.first().unwrap(),
        num_lookup_advice: *params.num_lookup_advice.first().unwrap(),
        num_fixed: params.num_fixed,
        lookup_bits: params.lookup_bits,
    }
}

pub fn to_ce_snark(snark: &snark_verifier_sdk::Snark) -> ce_snark_verifier_sdk::Snark {
    let s = serde_json::to_string(&snark).unwrap();
    let mut inner_deserializer = serde_json::Deserializer::from_str(&s);
    inner_deserializer.disable_recursion_limit();

    let deserializer = serde_stacker::Deserializer::new(&mut inner_deserializer);
    serde::Deserialize::deserialize(deserializer).unwrap()
}
