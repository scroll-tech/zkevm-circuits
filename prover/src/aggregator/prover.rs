use std::{env, iter::repeat};

use aggregator::{BatchHash, BatchHeader, ChunkInfo, MAX_AGG_SNARKS};
use anyhow::{bail, Result};
use eth_types::H256;
use sha2::{Digest, Sha256};
use snark_verifier_sdk::Snark;

use crate::{
    common,
    config::{LayerId, AGG_DEGREES},
    consts::{BATCH_KECCAK_ROW, BATCH_VK_FILENAME, BUNDLE_VK_FILENAME, CHUNK_PROTOCOL_FILENAME},
    io::{force_to_read, try_to_read},
    proof::BundleProof,
    types::BundleProvingTask,
    BatchProof, BatchProvingTask, ChunkProof,
};

#[derive(Debug)]
pub struct Prover {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub prover_impl: common::Prover,
    pub chunk_protocol: Vec<u8>,
    raw_vk_batch: Option<Vec<u8>>,
    raw_vk_bundle: Option<Vec<u8>>,
}

impl Prover {
    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        log::debug!("set env KECCAK_ROWS={}", BATCH_KECCAK_ROW.to_string());
        env::set_var("KECCAK_ROWS", BATCH_KECCAK_ROW.to_string());

        let prover_impl = common::Prover::from_params_dir(params_dir, &AGG_DEGREES);
        let chunk_protocol = force_to_read(assets_dir, &CHUNK_PROTOCOL_FILENAME);

        let raw_vk_batch = try_to_read(assets_dir, &BATCH_VK_FILENAME);
        let raw_vk_bundle = try_to_read(assets_dir, &BUNDLE_VK_FILENAME);
        if raw_vk_batch.is_none() {
            log::warn!(
                "batch-prover: {} doesn't exist in {}",
                *BATCH_VK_FILENAME,
                assets_dir
            );
        }
        if raw_vk_bundle.is_none() {
            log::warn!(
                "batch-prover: {} doesn't exist in {}",
                *BUNDLE_VK_FILENAME,
                assets_dir
            );
        }

        Self {
            prover_impl,
            chunk_protocol,
            raw_vk_batch,
            raw_vk_bundle,
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

    pub fn get_batch_vk(&self) -> Option<Vec<u8>> {
        self.prover_impl
            .raw_vk(LayerId::Layer4.id())
            .or_else(|| self.raw_vk_batch.clone())
    }

    pub fn get_bundle_vk(&self) -> Option<Vec<u8>> {
        self.prover_impl
            .raw_vk(LayerId::Layer6.id())
            .or_else(|| self.raw_vk_bundle.clone())
    }

    // Return the EVM proof for verification.
    pub fn gen_batch_proof(
        &mut self,
        batch: BatchProvingTask,
        name: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<BatchProof> {
        let name = name.map_or_else(|| batch.identifier(), |name| name.to_string());

        let (layer3_snark, batch_hash) =
            self.load_or_gen_last_agg_snark::<MAX_AGG_SNARKS>(&name, batch, output_dir)?;

        // Load or generate final compression thin EVM proof (layer-4).
        let layer4_snark = self.prover_impl.load_or_gen_comp_snark(
            &name,
            LayerId::Layer4.id(),
            true,
            LayerId::Layer4.degree(),
            layer3_snark,
            output_dir,
        )?;
        log::info!("Got final compression thin EVM proof (layer-4): {name}");

        self.check_batch_vk();

        let pk = self.prover_impl.pk(LayerId::Layer4.id());
        let batch_proof = BatchProof::new(layer4_snark, pk, batch_hash)?;
        if let Some(output_dir) = output_dir {
            batch_proof.dump(output_dir, "agg")?;
        }

        Ok(batch_proof)
    }

    // Generate layer3 snark.
    // Then it could be used to generate a layer4 proof.
    pub fn load_or_gen_last_agg_snark<const N_SNARKS: usize>(
        &mut self,
        name: &str,
        batch: BatchProvingTask,
        output_dir: Option<&str>,
    ) -> Result<(Snark, H256)> {
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
        let batch_header = BatchHeader::construct_from_chunks(
            batch.batch_header.version,
            batch.batch_header.batch_index,
            batch.batch_header.l1_message_popped,
            batch.batch_header.total_l1_message_popped,
            batch.batch_header.parent_batch_hash,
            batch.batch_header.last_block_timestamp,
            &chunk_hashes,
        );

        // sanity check between:
        // - BatchHeader supplied from infra
        // - BatchHeader re-constructed by circuits
        //
        // for the fields data_hash, z, y, blob_versioned_hash.
        assert_eq!(
            batch_header.data_hash, batch.batch_header.data_hash,
            "BatchHeader(sanity) mismatch data_hash expected={}, got={}",
            batch.batch_header.data_hash, batch_header.data_hash
        );
        assert_eq!(
            batch_header.blob_data_proof[0], batch.batch_header.blob_data_proof[0],
            "BatchHeader(sanity) mismatch blob data proof (z) expected={}, got={}",
            batch.batch_header.blob_data_proof[0], batch_header.blob_data_proof[0],
        );
        assert_eq!(
            batch_header.blob_data_proof[1], batch.batch_header.blob_data_proof[1],
            "BatchHeader(sanity) mismatch blob data proof (y) expected={}, got={}",
            batch.batch_header.blob_data_proof[1], batch_header.blob_data_proof[1],
        );
        assert_eq!(
            batch_header.blob_versioned_hash, batch.batch_header.blob_versioned_hash,
            "BatchHeader(sanity) mismatch blob versioned hash expected={}, got={}",
            batch.batch_header.blob_versioned_hash, batch_header.blob_versioned_hash,
        );

        let batch_hash = batch_header.batch_hash();
        let batch_info: BatchHash<N_SNARKS> = BatchHash::construct(&chunk_hashes, batch_header);

        let layer3_snark = self.prover_impl.load_or_gen_agg_snark(
            name,
            LayerId::Layer3.id(),
            LayerId::Layer3.degree(),
            batch_info,
            &layer2_snarks,
            output_dir,
        )?;
        log::info!("Got aggregation snark (layer-3): {name}");

        Ok((layer3_snark, batch_hash))
    }

    // Given a bundle proving task that consists of a list of batch proofs for all intermediate
    // batches, bundles them into a single bundle proof using the RecursionCircuit, effectively
    // proving the validity of all those batches.
    pub fn gen_bundle_proof(
        &mut self,
        bundle: BundleProvingTask,
        name: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<BundleProof> {
        let name = name.map_or_else(|| bundle.identifier(), |name| name.to_string());

        let bundle_snarks = bundle
            .batch_proofs
            .iter()
            .map(|proof| proof.into())
            .collect::<Vec<_>>();

        let layer5_snark = self.prover_impl.load_or_gen_recursion_snark(
            &name,
            LayerId::Layer5.id(),
            LayerId::Layer5.degree(),
            &bundle_snarks,
            output_dir,
        )?;

        let layer6_evm_proof = self.prover_impl.load_or_gen_comp_evm_proof(
            &name,
            LayerId::Layer6.id(),
            true,
            LayerId::Layer6.degree(),
            layer5_snark,
            output_dir,
        )?;

        self.check_bundle_vk();

        let bundle_proof: BundleProof = layer6_evm_proof.proof.into();
        if let Some(output_dir) = output_dir {
            bundle_proof.dump(output_dir, "recursion")?;
        }

        Ok(bundle_proof)
    }

    /// Check vk generated is same with vk loaded from assets
    fn check_batch_vk(&self) {
        if self.raw_vk_batch.is_some() {
            let gen_vk = self
                .prover_impl
                .raw_vk(LayerId::Layer4.id())
                .unwrap_or_default();
            if gen_vk.is_empty() {
                log::warn!("no gen_vk found, skip check_vk");
                return;
            }
            let init_vk = self.raw_vk_batch.clone().unwrap_or_default();
            if gen_vk != init_vk {
                log::error!(
                    "batch-prover: generated VK is different with init one - gen_vk = {}, init_vk = {}",
                    base64::encode(gen_vk),
                    base64::encode(init_vk),
                );
            }
        }
    }

    /// Check vk generated is same with vk loaded from assets
    fn check_bundle_vk(&self) {
        if self.raw_vk_bundle.is_some() {
            let gen_vk = self
                .prover_impl
                .raw_vk(LayerId::Layer6.id())
                .unwrap_or_default();
            if gen_vk.is_empty() {
                log::warn!("no gen_vk found, skip check_vk");
                return;
            }
            let init_vk = self.raw_vk_bundle.clone().unwrap_or_default();
            if gen_vk != init_vk {
                log::error!(
                    "bundle-prover: generated VK is different with init one - gen_vk = {}, init_vk = {}",
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
