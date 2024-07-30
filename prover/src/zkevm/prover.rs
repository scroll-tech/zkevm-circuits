use crate::{
    common,
    config::{LayerId, ZKEVM_DEGREES},
    consts::CHUNK_VK_FILENAME,
    io::try_to_read,
    proof::compare_chunk_info,
    types::ChunkProvingTask,
    utils::chunk_trace_to_witness_block,
    zkevm::circuit::calculate_row_usage_of_witness_block,
    ChunkProof,
};
use aggregator::ChunkInfo;
use anyhow::Result;

#[derive(Debug)]
pub struct Prover {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub prover_impl: common::Prover,
    verifier: Option<super::verifier::Verifier>,
    raw_vk: Option<Vec<u8>>,
}

impl Prover {
    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let prover_impl = common::Prover::from_params_dir(params_dir, &ZKEVM_DEGREES);

        let raw_vk = try_to_read(assets_dir, &CHUNK_VK_FILENAME);
        let verifier = if raw_vk.is_none() {
            log::warn!(
                "zkevm-prover: {} doesn't exist in {}",
                *CHUNK_VK_FILENAME,
                assets_dir
            );
            None
        } else {
            Some(super::verifier::Verifier::from_dirs(params_dir, assets_dir))
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
        chunk_identifier: Option<&str>,
        inner_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<ChunkProof> {
        assert!(!chunk.is_empty());

        let chunk_identifier =
            chunk_identifier.map_or_else(|| chunk.identifier(), |name| name.to_string());

        let chunk_proof = match output_dir
            .and_then(|output_dir| ChunkProof::from_json_file(output_dir, &chunk_identifier).ok())
        {
            Some(proof) => Ok(proof),
            None => {
                let witness_block = chunk_trace_to_witness_block(chunk.block_traces)?;
                let row_usage = calculate_row_usage_of_witness_block(&witness_block)?;
                log::info!("Got witness block");

                let chunk_info = ChunkInfo::from_witness_block(&witness_block, false);
                if let Some(chunk_info_input) = chunk.chunk_info.as_ref() {
                    compare_chunk_info(
                        &format!("gen_chunk_proof {chunk_identifier:?}"),
                        &chunk_info,
                        chunk_info_input,
                    )?;
                }
                let snark = self.prover_impl.load_or_gen_final_chunk_snark(
                    &chunk_identifier,
                    &witness_block,
                    inner_id,
                    output_dir,
                )?;

                self.check_vk();

                let result = ChunkProof::new(
                    snark,
                    self.prover_impl.pk(LayerId::Layer2.id()),
                    chunk_info,
                    row_usage,
                );

                if let (Some(output_dir), Ok(proof)) = (output_dir, &result) {
                    proof.dump(output_dir, &chunk_identifier)?;
                }

                result
            }
        }?;

        if let Some(verifier) = &self.verifier {
            if !verifier.verify_chunk_proof(chunk_proof.clone()) {
                anyhow::bail!("chunk prover cannot generate valid proof");
            }
            log::info!("verify_chunk_proof done");
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
