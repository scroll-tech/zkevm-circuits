use std::{collections::BTreeMap, path::PathBuf};

use aggregator::ChunkInfo;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use snark_verifier_sdk::Snark;

use crate::{
    common,
    config::LayerId,
    consts::CHUNK_VK_FILENAME,
    proof::compare_chunk_info,
    types::ChunkProvingTask,
    utils::try_read,
    zkevm::{
        circuit::{calculate_row_usage_of_witness_block, chunk_trace_to_witness_block},
        ChunkProverError, ChunkVerifier, RowUsage,
    },
    ChunkKind, ChunkProofV2, ChunkProofV2Metadata, ProverError,
};

/// Prover responsible for generating [`chunk proofs`][ChunkProof].
#[derive(Debug)]
pub struct Prover<'params> {
    /// Encapsulates the common prover.
    pub prover_impl: common::Prover<'params>,
    /// The chunk proof verifier.
    ///
    /// The verifier is optional in dev-scenarios where the verifier is generated on-the-fly. For
    /// production environments, we already have the verifying key available.
    verifier: Option<ChunkVerifier<'params>>,
    /// The [`VerifyingKey`][halo2_proofs::plonk::VerifyingKey] in its raw bytes form, as read from
    /// disk. For the same reasons as the [Self::verifier] field, this too is optional.
    raw_vk: Option<Vec<u8>>,
}

impl<'params> Prover<'params> {
    /// Construct a chunk prover given a map of degree to KZG setup params and a path to a
    /// directory to find stored assets.
    pub fn from_params_and_assets(
        params_map: &'params BTreeMap<u32, ParamsKZG<Bn256>>,
        assets_dir: &str,
    ) -> Self {
        // Try to read the verifying key from disk, but don't panic if not found.
        let path = PathBuf::from(assets_dir).join(CHUNK_VK_FILENAME.clone());
        let raw_vk = try_read(&path);

        // Build the inner prover.
        let prover_impl = common::Prover::from_params_map(params_map);

        // Build an optional verifier if the verifying key has been located on disk.
        let verifier = if raw_vk.is_none() {
            log::warn!(
                "ChunkProver setup without verifying key (dev mode): {} doesn't exist in {}",
                *CHUNK_VK_FILENAME,
                assets_dir
            );
            None
        } else {
            Some(super::verifier::Verifier::from_params_and_assets(
                prover_impl.params_map,
                assets_dir,
            ))
        };

        Self {
            prover_impl,
            verifier,
            raw_vk,
        }
    }

    /// Returns the optional [`VerifyingKey`][halo2_proofs::plonk::VerifyingKey] in its raw form.
    pub fn get_vk(&self) -> Option<Vec<u8>> {
        self.prover_impl
            .raw_vk(LayerId::Layer2.id())
            .or_else(|| self.raw_vk.clone())
    }

    /// Generate a proof for a chunk via the halo2-route, i.e. the inner SNARK is generated using the
    /// halo2-based [`SuperCircuit`][zkevm_circuits::super_circuit::SuperCircuit].
    pub fn gen_halo2_chunk_proof(
        &mut self,
        chunk: ChunkProvingTask,
        chunk_id: Option<&str>,
        inner_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<ChunkProofV2, ProverError> {
        // Panic if the chunk is empty, i.e. no traces were found.
        assert!(!chunk.is_empty());

        // The chunk identifier is either the specified identifier or we calculate it on-the-fly.
        let chunk_id = chunk_id.map_or_else(|| chunk.identifier(), |name| name.to_string());

        // Try to locate a cached chunk proof for the same identifier.
        if let Some(dir) = output_dir.as_ref() {
            if let Ok(chunk_proof) = ChunkProofV2::from_json(dir, &chunk_id) {
                return Ok(chunk_proof);
            }
        }

        // Generate the proof if proof was not found in cache.
        //
        // Construct the chunk as witness and check circuit capacity for the halo2-based super
        // circuit.
        let witness_block = chunk_trace_to_witness_block(chunk.block_traces)?;
        let sub_circuit_row_usages = calculate_row_usage_of_witness_block(&witness_block)?;
        let row_usage = RowUsage::from_row_usage_details(sub_circuit_row_usages.clone());

        // If the circuit-capacity checker (ccc) overflows, early-return with appropriate
        // error.
        if !row_usage.is_ok {
            return Err(ChunkProverError::CircuitCapacityOverflow(row_usage).into());
        }

        // Build the chunk information required by the inner circuit for SNARK generation.
        let chunk_info_reconstructed = ChunkInfo::from_witness_block(&witness_block, false);

        // Sanity check: if chunk information was already provided, make sure it exactly
        // matches the chunk information reconstructed from the block traces of the chunk.
        if let Some(chunk_info_provided) = chunk.chunk_info.as_ref() {
            compare_chunk_info(
                &format!("gen_halo2_chunk_proof {chunk_id:?}"),
                &chunk_info_reconstructed,
                chunk_info_provided,
            )
            .map_err(ChunkProverError::Custom)?;
        }

        // Generate the final Layer-2 SNARK.
        let snark = self
            .prover_impl
            .load_or_gen_final_chunk_snark(&chunk_id, &witness_block, inner_id, output_dir)
            .map_err(|e| ChunkProverError::Custom(e.to_string()))?;

        // Sanity check on the verifying key used at Layer-2.
        self.check_vk()?;

        // Construct the chunk proof.
        let chunk_proof_metadata = ChunkProofV2Metadata::new(
            &snark,
            ChunkKind::Halo2,
            chunk_info_reconstructed,
            Some(row_usage),
        )?;
        let chunk_proof = ChunkProofV2::new(
            snark,
            self.prover_impl.pk(LayerId::Layer2.id()),
            chunk_proof_metadata,
        )?;

        // If the output directory was provided, write the proof to disk.
        if let Some(output_dir) = output_dir {
            chunk_proof.dump(output_dir, &chunk_id)?;
        }

        // If the verifier was set, i.e. production environments, we also do a sanity verification
        // of the proof that was generated above.
        if let Some(verifier) = &self.verifier {
            verifier.verify_chunk_proof(&chunk_proof)?;
        }

        Ok(chunk_proof)
    }

    /// Generates a chunk proof by compressing the provided SNARK. The generated proof uses the
    /// [`CompressionCircuit`][aggregator::CompressionCircuit] to compress the supplied
    /// [`SNARK`][snark_verifier_sdk::Snark] only once using thin-compression parameters.
    ///
    /// The [`ChunkProof`] represents the Layer-2 proof in Scroll's proving pipeline and the
    /// generated SNARK can then be used as inputs to the [`BatchCircuit`][aggregator::BatchCircuit].
    ///
    /// This method should be used iff the input SNARK was generated from a halo2-backend for Sp1.
    /// In order to construct a chunk proof via the halo2-based
    /// [`SuperCircuit`][zkevm_circuits::super_circuit::SuperCircuit], please use [`gen_chunk_proof`][Self::gen_chunk_proof].
    pub fn gen_sp1_chunk_proof(
        &mut self,
        inner_snark: Snark,
        chunk: ChunkProvingTask,
        chunk_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<ChunkProofV2, ProverError> {
        // Panic if the chunk is empty, i.e. no traces were found.
        assert!(!chunk.is_empty());

        // The chunk identifier is either the specified identifier or we calculate it on-the-fly.
        let chunk_id = chunk_id.map_or_else(|| chunk.identifier(), |name| name.to_string());

        // Generate a Layer-2 compression SNARK for the provided inner SNARK.
        let snark = self
            .prover_impl
            .load_or_gen_comp_snark(
                &chunk_id,
                LayerId::Layer2.id(),
                true,
                LayerId::Layer2.degree(),
                inner_snark,
                output_dir,
            )
            .map_err(|e| ChunkProverError::Custom(e.to_string()))?;

        // Sanity check on the verifying key used at Layer-2.
        self.check_vk()?;

        // We reconstruct some metadata to be attached with the chunk proof.
        let chunk_info = chunk.chunk_info.unwrap_or({
            let witness_block = chunk_trace_to_witness_block(chunk.block_traces)?;
            ChunkInfo::from_witness_block(&witness_block, false)
        });

        // Construct a chunk proof.
        //
        // Note that the `row_usage` has been set to an empty vector, because in the sp1-route we
        // don't have the notion of rows being allocated to sub-circuits, as in the case of the
        // halo2-route.
        let chunk_proof_metadata =
            ChunkProofV2Metadata::new(&snark, ChunkKind::Sp1, chunk_info, None)?;
        let chunk_proof = ChunkProofV2::new(
            snark,
            self.prover_impl.pk(LayerId::Layer2.id()),
            chunk_proof_metadata,
        )?;

        // If the output directory was provided, write the proof to disk.
        if let Some(output_dir) = output_dir {
            chunk_proof.dump(output_dir, &chunk_id)?;
        }

        // If the verifier was set, i.e. production environments, we also do a sanity verification
        // of the proof that was generated above.
        if let Some(verifier) = &self.verifier {
            verifier.verify_chunk_proof(&chunk_proof)?;
        }

        Ok(chunk_proof)
    }

    /// Sanity check for the [`VerifyinKey`][halo2_proofs::plonk::VerifyingKey] used to generate
    /// Layer-2 SNARK that is wrapped inside the [`ChunkProof`]. The prover generated VK is
    /// expected to match the VK used to initialise the prover.
    fn check_vk(&self) -> Result<(), ChunkProverError> {
        if let Some(expected_vk) = self.raw_vk.as_ref() {
            let base64_exp_vk = base64::encode(expected_vk);
            if let Some(generated_vk) = self.prover_impl.raw_vk(LayerId::Layer2.id()).as_ref() {
                let base64_gen_vk = base64::encode(generated_vk);
                if generated_vk.ne(expected_vk) {
                    log::error!(
                        "ChunkProver: VK mismatch! found={}, expected={}",
                        base64_gen_vk,
                        base64_exp_vk,
                    );
                    return Err(ChunkProverError::VerifyingKeyMismatch(
                        base64_gen_vk,
                        base64_exp_vk,
                    ));
                }
            } else {
                return Err(ChunkProverError::VerifyingKeyNotFound(base64_exp_vk));
            }
        }

        Ok(())
    }
}
