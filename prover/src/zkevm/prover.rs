use std::collections::BTreeMap;

use crate::{
    common,
    config::LayerId,
    consts::CHUNK_VK_FILENAME,
    io::try_to_read,
    proof::compare_chunk_info,
    types::ChunkProvingTask,
    zkevm::{
        circuit::{calculate_row_usage_of_witness_block, chunk_trace_to_witness_block},
        ChunkProverError, RowUsage,
    },
    ChunkProof,
};
use aggregator::ChunkInfo;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};

#[derive(Debug)]
pub struct Prover<'params> {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub prover_impl: common::Prover<'params>,
    verifier: Option<super::verifier::Verifier<'params>>,
    raw_vk: Option<Vec<u8>>,
}

impl<'params> Prover<'params> {
    pub fn from_params_and_assets(
        params_map: &'params BTreeMap<u32, ParamsKZG<Bn256>>,
        assets_dir: &str,
    ) -> Self {
        let prover_impl = common::Prover::from_params_map(params_map);

        let raw_vk = try_to_read(assets_dir, &CHUNK_VK_FILENAME);
        let verifier = if raw_vk.is_none() {
            log::warn!(
                "zkevm-prover: {} doesn't exist in {}",
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
            raw_vk,
            verifier,
        }
    }

    pub fn get_vk(&self) -> Option<Vec<u8>> {
        self.prover_impl
            .raw_vk(LayerId::Layer2.id())
            .or_else(|| self.raw_vk.clone())
    }

    /// Generate proof for a chunk. This method usually takes ~10minutes.
    /// Meaning of each parameter:
    ///   output_dir:
    ///     If `output_dir` is not none, the dir will be used to save/load proof or intermediate results.
    ///     If proof or intermediate results can be loaded from `output_dir`,
    ///     then they will not be computed again.
    ///     If `output_dir` is not none, computed intermediate results and proof will be written
    ///     into this dir.
    ///   chunk_identifier:
    ///     used to distinguish different chunk files located in output_dir.
    ///     If it is not set, default value(first block number of this chuk) will be used.
    ///   id:
    ///     TODO(zzhang). clean this. I think it can only be None or Some(0)...
    pub fn gen_chunk_proof(
        &mut self,
        chunk: ChunkProvingTask,
        chunk_id: Option<&str>,
        inner_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<ChunkProof, ChunkProverError> {
        assert!(!chunk.is_empty());

        let chunk_id = chunk_id.map_or_else(|| chunk.identifier(), |name| name.to_string());

        let cached_proof =
            output_dir.and_then(|dir| ChunkProof::from_json_file(dir, &chunk_id).ok());

        let chunk_proof = cached_proof.unwrap_or({
            let witness_block = chunk_trace_to_witness_block(chunk.block_traces)?;
            log::info!("Got witness block");

            let sub_circuit_row_usages = calculate_row_usage_of_witness_block(&witness_block)?;
            let row_usage = RowUsage::from_row_usage_details(sub_circuit_row_usages.clone());
            if !row_usage.is_ok {
                return Err(ChunkProverError::CircuitCapacityOverflow(row_usage));
            }

            let chunk_info = ChunkInfo::from_witness_block(&witness_block, false);
            if let Some(chunk_info_input) = chunk.chunk_info.as_ref() {
                compare_chunk_info(
                    &format!("gen_chunk_proof {chunk_id:?}"),
                    &chunk_info,
                    chunk_info_input,
                )?;
            }
            let snark = self
                .prover_impl
                .load_or_gen_final_chunk_snark(&chunk_id, &witness_block, inner_id, output_dir)
                .map_err(|e| ChunkProverError::Custom(e.to_string()))?;

            self.check_vk();

            let result = ChunkProof::new(
                snark,
                self.prover_impl.pk(LayerId::Layer2.id()),
                chunk_info,
                chunk.chunk_kind,
                sub_circuit_row_usages,
            );

            if let (Some(output_dir), Ok(proof)) = (output_dir, &result) {
                proof
                    .dump(output_dir, &chunk_id)
                    .map_err(|e| ChunkProverError::Custom(e.to_string()))?;
            }

            result.map_err(|e| ChunkProverError::Custom(e.to_string()))?
        });

        if let Some(verifier) = &self.verifier {
            if !verifier.verify_chunk_proof(chunk_proof.clone()) {
                return Err(String::from("chunk proof verification failed").into());
            }
            log::info!("chunk proof verified OK");
        }

        Ok(chunk_proof)
    }

    /// Check vk generated is same with vk loaded from assets
    fn check_vk(&self) {
        if self.raw_vk.is_some() {
            let gen_vk = self
                .prover_impl
                .raw_vk(LayerId::Layer2.id())
                .unwrap_or_default();
            if gen_vk.is_empty() {
                log::warn!("no gen_vk found, skip check_vk");
                return;
            }
            let init_vk = self.raw_vk.clone().unwrap_or_default();
            if gen_vk != init_vk {
                log::error!(
                    "zkevm-prover: generated VK is different with init one - gen_vk = {}, init_vk = {}",
                    base64::encode(gen_vk),
                    base64::encode(init_vk),
                );
            }
        }
    }
}
