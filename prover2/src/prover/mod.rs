use aggregator::MAX_AGG_SNARKS;
use halo2_proofs::{halo2curves::bn256::Fr, plonk::Circuit};
use snark_verifier_sdk::{CircuitExt, Snark};
use tracing::instrument;

use crate::{
    types::{ProverType, ProverTypeBatch, ProverTypeBundle, ProverTypeChunk},
    Proof, ProofLayer, ProverConfig, ProverError,
};

pub mod config;
pub mod params;

/// Convenience type for chunk prover.
pub type ChunkProver = Prover<ProverTypeChunk>;

/// Convenience type for batch prover.
pub type BatchProver = Prover<ProverTypeBatch<MAX_AGG_SNARKS>>;

/// Convenience type for bundle prover.
pub type BundleProver = Prover<ProverTypeBundle>;

/// A generic prover that is capable of generating proofs for given tasks.
#[derive(Debug)]
pub struct Prover<T> {
    /// Config for the prover.
    pub config: ProverConfig<T>,
}

impl<T> Prover<T> {
    /// Construct a new prover.
    pub fn new(config: ProverConfig<T>) -> Self {
        Self { config }
    }
}

impl<Type: ProverType> Prover<Type> {
    /// Generate a proof for the given task.
    #[instrument(name = "Prover::gen_proof", skip(self))]
    pub fn gen_proof(&mut self, task: Type::Task) -> Result<Proof, ProverError> {
        // Generate SNARKs for all the layers at which the prover operates. We start from the base
        // layer, i.e. the innermost layer and compress SNARKs until we have the SNARK of the
        // outermost layer for this prover.
        let base_layer = Type::base_layer()?;
        let base_circuit = Type::build_base(task);
        let mut snark = self.gen_snark(base_layer, &base_circuit)?;

        for layer in Type::compression_layers() {
            let kzg_params = self.config.kzg_params(layer)?;
            let compression_circuit = Type::build_compression(kzg_params, snark, layer);
            snark = self.gen_snark(layer, &compression_circuit)?;
        }

        unimplemented!()
    }

    /// Generate a SNARK for the given circuit.
    fn gen_snark<C>(&mut self, _layer: ProofLayer, _circuit: &C) -> Result<Snark, ProverError>
    where
        C: Circuit<Fr> + CircuitExt<Fr>,
    {
        unimplemented!()
    }
}
