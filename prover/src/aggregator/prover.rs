use crate::{
    common,
    config::{LayerId, AGG_DEGREES},
    consts::{AGG_KECCAK_ROW, AGG_VK_FILENAME, CHUNK_PROTOCOL_FILENAME},
    io::{force_to_read, try_to_read},
    BatchProof, BatchProvingTask, ChunkProof,
};
use aggregator::{ChunkInfo, MAX_AGG_SNARKS};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use snark_verifier_sdk::Snark;
use std::{env, iter::repeat};

#[derive(Debug)]
pub struct Prover {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub prover_impl: common::Prover,
    pub chunk_protocol: Vec<u8>,
    raw_vk: Option<Vec<u8>>,
}

impl Prover {
    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        log::debug!("set env KECCAK_ROWS={}", AGG_KECCAK_ROW.to_string());
        env::set_var("KECCAK_ROWS", AGG_KECCAK_ROW.to_string());

        let prover_impl = common::Prover::from_params_dir(params_dir, &AGG_DEGREES);
        let chunk_protocol = force_to_read(assets_dir, &CHUNK_PROTOCOL_FILENAME);

        let raw_vk = try_to_read(assets_dir, &AGG_VK_FILENAME);
        if raw_vk.is_none() {
            log::warn!(
                "agg-prover: {} doesn't exist in {}",
                *AGG_VK_FILENAME,
                assets_dir
            );
        }

        Self {
            prover_impl,
            chunk_protocol,
            raw_vk,
        }
    }

    // Return true if chunk proofs are valid (same protocol), false otherwise.
    pub fn check_protocol_of_chunks(&self, chunk_proofs: &[ChunkProof]) -> bool {
        chunk_proofs.iter().enumerate().all(|(i, proof)| {
            let result = proof.protocol == self.chunk_protocol;
            if !result {
                log::error!(
                    "Non-match protocol of chunk-proof index-{}: expected = {:x}, actual = {:x}",
                    i,
                    Sha256::digest(&self.chunk_protocol),
                    Sha256::digest(&proof.protocol),
                );
            }

            result
        })
    }

    pub fn get_vk(&self) -> Option<Vec<u8>> {
        self.prover_impl
            .raw_vk(LayerId::Layer4.id())
            .or_else(|| self.raw_vk.clone())
    }

    // Return the EVM proof for verification.
    pub fn gen_agg_evm_proof(
        &mut self,
        batch: BatchProvingTask,
        name: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<BatchProof> {
        let name = name.map_or_else(|| batch.identifier(), |name| name.to_string());

        let layer3_snark = self.load_or_gen_last_agg_snark(&name, batch, output_dir)?;

        // Load or generate final compression thin EVM proof (layer-4).
        let evm_proof = self.prover_impl.load_or_gen_comp_evm_proof(
            &name,
            LayerId::Layer4.id(),
            true,
            LayerId::Layer4.degree(),
            layer3_snark,
            output_dir,
        )?;
        log::info!("Got final compression thin EVM proof (layer-4): {name}");

        self.check_vk();

        let batch_proof = BatchProof::from(evm_proof.proof);
        if let Some(output_dir) = output_dir {
            batch_proof.dump(output_dir, "agg")?;
        }

        Ok(batch_proof)
    }

    // Generate layer3 snark.
    // Then it could be used to generate a layer4 proof.
    pub fn load_or_gen_last_agg_snark(
        &mut self,
        name: &str,
        batch: BatchProvingTask,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let real_chunk_count = batch.chunk_proofs.len();
        assert!((1..=MAX_AGG_SNARKS).contains(&real_chunk_count));

        if !self.check_protocol_of_chunks(&batch.chunk_proofs) {
            bail!("non-match-chunk-protocol: {name}");
        }
        let mut chunk_hashes: Vec<_> = batch
            .chunk_proofs
            .iter()
            .map(|p| p.chunk_info.clone())
            .collect();
        let mut layer2_snarks: Vec<_> = batch
            .chunk_proofs
            .into_iter()
            .map(|p| p.to_snark())
            .collect();

        if real_chunk_count < MAX_AGG_SNARKS {
            let padding_snark = layer2_snarks.last().unwrap().clone();
            let mut padding_chunk_hash = chunk_hashes.last().unwrap().clone();
            padding_chunk_hash.is_padding = true;

            // Extend to MAX_AGG_SNARKS for both chunk hashes and layer-2 snarks.
            chunk_hashes.extend(repeat(padding_chunk_hash).take(MAX_AGG_SNARKS - real_chunk_count));
            layer2_snarks.extend(repeat(padding_snark).take(MAX_AGG_SNARKS - real_chunk_count));
        }

        // Load or generate aggregation snark (layer-3).
        let layer3_snark = self.prover_impl.load_or_gen_agg_snark(
            name,
            LayerId::Layer3.id(),
            LayerId::Layer3.degree(),
            &chunk_hashes,
            &layer2_snarks,
            output_dir,
        )?;
        log::info!("Got aggregation snark (layer-3): {name}");

        Ok(layer3_snark)
    }

    /// Check vk generated is same with vk loaded from assets
    fn check_vk(&self) {
        if self.raw_vk.is_some() {
            let gen_vk = self
                .prover_impl
                .raw_vk(LayerId::Layer4.id())
                .unwrap_or_default();
            if gen_vk.is_empty() {
                log::warn!("no gen_vk found, skip check_vk");
                return;
            }
            let init_vk = self.raw_vk.clone().unwrap_or_default();
            if gen_vk != init_vk {
                log::error!(
                    "agg-prover: generated VK is different with init one - gen_vk = {}, init_vk = {}",
                    base64::encode(gen_vk),
                    base64::encode(init_vk),
                );
            }
        }
    }
}

pub fn check_chunk_hashes(
    name: &str,
    chunk_hashes_proofs: &[(ChunkInfo, ChunkProof)],
) -> Result<()> {
    for (idx, (in_arg, chunk_proof)) in chunk_hashes_proofs.iter().enumerate() {
        let in_proof = &chunk_proof.chunk_info;
        crate::proof::compare_chunk_info(&format!("{name} chunk num {idx}"), in_arg, in_proof)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::H256;

    #[test]
    fn test_check_chunk_hashes() {
        let chunk_hashes_proofs = vec![
            (ChunkInfo::default(), ChunkProof::default()),
            (
                ChunkInfo {
                    chain_id: 1,
                    prev_state_root: H256::zero(),
                    data_hash: [100; 32].into(),
                    ..Default::default()
                },
                ChunkProof {
                    chunk_info: ChunkInfo {
                        chain_id: 1,
                        prev_state_root: [0; 32].into(),
                        data_hash: [100; 32].into(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                ChunkInfo {
                    post_state_root: H256::zero(),
                    ..Default::default()
                },
                ChunkProof {
                    chunk_info: ChunkInfo {
                        post_state_root: [1; 32].into(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
        ];

        let result = check_chunk_hashes("test-batch", &chunk_hashes_proofs);
        assert_eq!(
            result.unwrap_err().downcast_ref::<String>().unwrap(),
            "test-batch chunk num 2 chunk different post_state_root: 0x0000…0000 != 0x0101…0101"
        );
    }
}
