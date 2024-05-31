use crate::{
    common,
    config::{LayerId, ZKEVM_DEGREES},
    consts::CHUNK_VK_FILENAME,
    io::try_to_read,
    types::ChunkProvingTask,
    utils::chunk_trace_to_witness_block,
    ChunkProof,
};
use aggregator::ChunkHash;
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

    pub fn gen_chunk_proof(
        &mut self,
        chunk: ChunkProvingTask,
        name: Option<&str>,
        inner_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<ChunkProof> {
        assert!(!chunk.is_empty());

        let chunk_identifier = name.map_or_else(|| chunk.identifier(), |name| name.to_string());

        let chunk_proof = match output_dir
            .and_then(|output_dir| ChunkProof::from_json_file(output_dir, &chunk_identifier).ok())
        {
            Some(proof) => Ok(proof),
            None => {
                let witness_block = chunk_trace_to_witness_block(chunk.block_traces)?;
                log::info!("Got witness block");

                let snark = self.prover_impl.load_or_gen_final_chunk_snark(
                    &chunk_identifier,
                    &witness_block,
                    inner_id,
                    output_dir,
                )?;

                self.check_vk();

                let chunk_hash = ChunkHash::from_witness_block(&witness_block, false);

                let result = ChunkProof::new(
                    snark,
                    self.prover_impl.pk(LayerId::Layer2.id()),
                    Some(chunk_hash),
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
        }

        Ok(chunk_proof)
    }

    /// Check vk generated is same with vk loaded from assets
    fn check_vk(&self) {
        if self.raw_vk.is_some() {
            // Check VK is same with the init one, and take (clear) init VK.
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
