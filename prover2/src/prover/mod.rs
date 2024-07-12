use aggregator::MAX_AGG_SNARKS;
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::{CircuitExt, Snark};
use tracing::instrument;

use crate::{
    types::{ProverType, ProverTypeBatch, ProverTypeBundle, ProverTypeChunk},
    util::{gen_rng, read_json, write_json},
    Proof, ProofLayer, ProverConfig, ProverError, ProvingTask,
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
    pub fn gen_proof(
        &mut self,
        task: Type::Task,
    ) -> Result<Proof<Type::ProofAuxData>, ProverError> {
        // Early return if the proof for the given task is already available in cache.
        let id = task.id();
        let path_proof = self.config.path_proof(&id);
        if let Some(path) = &path_proof {
            if let Ok(proof) = read_json(path) {
                return Ok(proof);
            }
        }

        // Generate SNARKs for all the layers at which the prover operates.
        //
        // We start from the base layer, i.e. the innermost layer for the prover.
        let base_layer = Type::base_layer()?;
        let (base_circuit, aux_data) = Type::build_base(task);
        let mut snark = self.gen_snark(&id, base_layer, base_circuit)?;

        // The base layer's SNARK is compressed for every layer of compression.
        for layer in Type::compression_layers() {
            let kzg_params = self.config.kzg_params(layer)?;
            let compression_circuit = Type::build_compression(kzg_params, snark, layer);
            snark = self.gen_snark(&id, layer, compression_circuit)?;
        }

        // We have the final compressed SNARK for the proof generation process under the prover.
        let outermost_layer = Type::outermost_layer()?;
        let pk = self.config.proving_key(outermost_layer)?;
        let proof = Proof::new(outermost_layer, snark, pk, aux_data)?;

        // Dump the proof if caching is enabled.
        if let Some(path) = &path_proof {
            write_json(path, &proof)?;
        }

        Ok(proof)
    }

    /// Generate a SNARK for the given circuit.
    fn gen_snark<C>(
        &mut self,
        id: &str,
        layer: ProofLayer,
        circuit: C,
    ) -> Result<Snark, ProverError>
    where
        C: CircuitExt<Fr>,
    {
        let path = self.config.path_snark(id, layer);
        let (kzg_params, pk) = self.config.gen_proving_key(layer, &circuit)?;
        let mut rng = gen_rng();

        snark_verifier_sdk::gen_snark_shplonk(kzg_params, pk, circuit, &mut rng, path)
            .map_err(|e| ProverError::GenSnark(id.into(), layer, e))
    }
}
