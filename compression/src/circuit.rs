//! Circuit implementation for compression circuit.

use crate::params::ConfigParams;
use ark_std::{end_timer, start_timer};
use ce_snark_verifier::halo2_base::gates::circuit::{
    builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig, CircuitBuilderStage,
};
use ce_snark_verifier_sdk::{
    halo2::aggregation::{AggregationCircuit, AggregationConfigParams, VerifierUniversality},
    CircuitExt as CeCircuitExt, SHPLONK,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, Selector},
    poly::kzg::commitment::ParamsKZG,
};
use halo2curves::bn256::{Bn256, Fr};
use rand::Rng;
use snark_verifier_sdk::CircuitExt;
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
        AggregationCircuit::configure_with_params(meta, load_params().into())
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
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
        params: &ParamsKZG<Bn256>,
        snark: snark_verifier_sdk::Snark,
        has_accumulator: bool,
        rng: impl Rng + Send,
    ) -> Result<Self, ce_snark_verifier::Error> {
        Self::new_from_ce_snark(params, convert(&snark), has_accumulator, rng)
    }

    pub fn new_from_ce_snark(
        params: &ParamsKZG<Bn256>,
        snark: ce_snark_verifier_sdk::Snark,
        has_accumulator: bool,
        _rng: impl Rng + Send, // TODO: hook this up to the rng in AggregationCircuit? is that even needed?
    ) -> Result<Self, ce_snark_verifier::Error> {
        let mut inner = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            load_params(),
            params,
            [snark],
            VerifierUniversality::None,
        );
        inner.expose_previous_instances(has_accumulator);

        Ok(Self(inner))
    }
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

fn convert(snark: &snark_verifier_sdk::Snark) -> ce_snark_verifier_sdk::Snark {
    serde_json::from_str(&serde_json::to_string(&snark).unwrap()).unwrap()
}
