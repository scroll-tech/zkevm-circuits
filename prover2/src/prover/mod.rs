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
pub type ChunkProver = Prover<ProverTypeChunk, false>;

/// Convenience type for batch prover.
pub type BatchProver = Prover<ProverTypeBatch<MAX_AGG_SNARKS>, false>;

/// Convenience type for bundle prover. Since bundling of batches is also the final layer, we wish
/// to verify the proof in EVM.
pub type BundleProver = Prover<ProverTypeBundle, true>;

/// A generic prover that is capable of generating proofs for given tasks.
#[derive(Debug)]
pub struct Prover<T, const EVM_VERIFY: bool> {
    /// Config for the prover.
    pub config: ProverConfig<T>,
}

impl<T, const EVM_VERIFY: bool> Prover<T, EVM_VERIFY> {
    /// Construct a new prover.
    pub fn new(config: ProverConfig<T>) -> Self {
        Self { config }
    }
}

impl<Type: ProverType, const EVM_VERIFY: bool> Prover<Type, EVM_VERIFY> {
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

        let proof = if EVM_VERIFY {
            self.gen_proof_evm(task)?
        } else {
            self.gen_proof_halo2(task)?
        };

        // Dump the proof if caching is enabled.
        if let Some(path) = &path_proof {
            write_json(path, &proof)?;
        }

        Ok(proof)
    }

    /// Generate a halo2 proof for the given task. The poseidon hash function is used for
    /// fiat-shamir transform on the transcript.
    #[instrument(name = "Prover::gen_proof_halo2", skip(self))]
    fn gen_proof_halo2(
        &mut self,
        task: Type::Task,
    ) -> Result<Proof<Type::ProofAuxData>, ProverError> {
        let id = task.id();

        // Generate SNARKs for all the layers at which the prover operates.
        //
        // We start from the base layer, i.e. the innermost layer for the prover.
        let (mut snark, aux_data) = self.gen_base_snark(task)?;

        // The base layer's SNARK is compressed for every layer of compression.
        for layer in Type::compression_layers() {
            let kzg_params = self.config.kzg_params(layer)?;
            let compression_circuit = Type::build_compression(kzg_params, snark, layer);
            snark = self.gen_halo2_snark(&id, layer, compression_circuit)?;
        }

        // We have the final compressed SNARK for the proof generation process under the prover.
        let outermost_layer = Type::outermost_layer()?;
        let pk = self.config.proving_key(outermost_layer)?;
        let proof = Proof::new_from_snark(outermost_layer, snark, pk, aux_data)?;

        Ok(proof)
    }

    /// Generate an EVM-verifiable proof for the given task. The Keccak256 hash function is used
    /// for fiat-shamir transform on the transcript.
    #[instrument(name = "Prover::gen_proof_evm", skip(self))]
    fn gen_proof_evm(
        &mut self,
        task: Type::Task,
    ) -> Result<Proof<Type::ProofAuxData>, ProverError> {
        let id = task.id();

        // Generate SNARKs for all the layers at which the prover operates.
        //
        // We start from the base layer, i.e. the innermost layer for the prover.
        let (mut snark, aux_data) = self.gen_base_snark(task)?;

        // The base layer's SNARK is compressed for every layer of compression, except the last
        // (final) layer. The final layer of compression is supposed to be EVM-verifiable.
        for &layer in Type::compression_layers().iter().rev().skip(1).rev() {
            let kzg_params = self.config.kzg_params(layer)?;
            let compression_circuit = Type::build_compression(kzg_params, snark, layer);
            snark = self.gen_halo2_snark(&id, layer, compression_circuit)?;
        }

        // We have the final compressed SNARK for the proof generation process under the prover.
        let outermost_layer = Type::outermost_layer()?;
        let kzg_params = self.config.kzg_params(outermost_layer)?;
        let compression_circuit = Type::build_compression(kzg_params, snark, outermost_layer);
        let instances = compression_circuit.instances();
        let (kzg_params, pk) = self
            .config
            .gen_proving_key(outermost_layer, &compression_circuit)?;
        let mut rng = gen_rng();
        let raw_proof = snark_verifier_sdk::gen_evm_proof_shplonk(
            kzg_params,
            pk,
            compression_circuit,
            instances.clone(),
            &mut rng,
        );

        let proof = Proof::new_from_raw(outermost_layer, &instances[0], &raw_proof, pk, aux_data);

        Ok(proof)
    }

    /// Generates a SNARK for the base circuit of a prover. THe base circuit is generally a circuit
    /// with larger number of advice columns while being of lower degree. The SNARK of the base
    /// circuit is then compressed using the compression layer to produce a proof that's cheaper to
    /// verify.
    #[instrument(name = "Prover::gen_base_snark", skip(self))]
    fn gen_base_snark(
        &mut self,
        task: Type::Task,
    ) -> Result<(Snark, Type::ProofAuxData), ProverError> {
        let id = task.id();

        // Generate SNARKs for all the layers at which the prover operates.
        //
        // We start from the base layer, i.e. the innermost layer for the prover.
        let base_layer = Type::base_layer()?;
        let (base_circuit, aux_data) = Type::build_base(task);

        Ok((
            self.gen_halo2_snark(&id, base_layer, base_circuit)?,
            aux_data,
        ))
    }

    /// Generate a SNARK for the given circuit.
    fn gen_halo2_snark<C>(
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
