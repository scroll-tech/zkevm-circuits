use crate::{
    common,
    config::{LayerId, ZKEVM_DEGREES},
    consts::CHUNK_VK_FILENAME,
    io::try_to_read,
    utils::chunk_trace_to_witness_block,
    ChunkProof,
};
use aggregator::ChunkHash;
use anyhow::Result;
use eth_types::l2_types::BlockTrace;

#[derive(Debug)]
pub struct Prover {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Prover,
    raw_vk: Option<Vec<u8>>,
}

impl Prover {
    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let inner = common::Prover::from_params_dir(params_dir, &ZKEVM_DEGREES);

        let raw_vk = try_to_read(assets_dir, &CHUNK_VK_FILENAME);
        if raw_vk.is_none() {
            log::warn!(
                "zkevm-prover: {} doesn't exist in {}",
                *CHUNK_VK_FILENAME,
                assets_dir
            );
        }

        Self { inner, raw_vk }
    }

    pub fn get_vk(&self) -> Option<Vec<u8>> {
        self.inner
            .raw_vk(LayerId::Layer2.id())
            .or_else(|| self.raw_vk.clone())
    }

    pub fn gen_chunk_proof(
        &mut self,
        chunk_trace: Vec<BlockTrace>,
        name: Option<&str>,
        inner_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<ChunkProof> {
        assert!(!chunk_trace.is_empty());

        let witness_block = chunk_trace_to_witness_block(chunk_trace)?;
        log::info!("Got witness block");

        let name = name.map_or_else(
            || {
                witness_block
                    .context
                    .ctxs
                    .first_key_value()
                    .map_or(0.into(), |(_, ctx)| ctx.number)
                    .low_u64()
                    .to_string()
            },
            |name| name.to_string(),
        );

        let snark = self.inner.load_or_gen_final_chunk_snark(
            &name,
            &witness_block,
            inner_id,
            output_dir,
        )?;

        self.check_and_clear_raw_vk();

        match output_dir.and_then(|output_dir| ChunkProof::from_json_file(output_dir, &name).ok()) {
            Some(proof) => Ok(proof),
            None => {
                let chunk_hash = ChunkHash::from_witness_block(&witness_block, false);

                let result =
                    ChunkProof::new(snark, self.inner.pk(LayerId::Layer2.id()), Some(chunk_hash));

                if let (Some(output_dir), Ok(proof)) = (output_dir, &result) {
                    proof.dump(output_dir, &name)?;
                }

                result
            }
        }
    }

    fn check_and_clear_raw_vk(&mut self) {
        if self.raw_vk.is_some() {
            // Check VK is same with the init one, and take (clear) init VK.
            let gen_vk = self.inner.raw_vk(LayerId::Layer2.id()).unwrap_or_default();
            let init_vk = self.raw_vk.take().unwrap_or_default();

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
