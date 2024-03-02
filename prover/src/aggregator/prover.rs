use crate::{
    common,
    config::{LayerId, AGG_DEGREES},
    consts::{AGG_KECCAK_ROW, AGG_VK_FILENAME, CHUNK_PROTOCOL_FILENAME},
    io::{force_to_read, try_to_read},
    BatchProof, ChunkProof,
};
use aggregator::{ChunkHash, MAX_AGG_SNARKS};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use snark_verifier_sdk::Snark;
use std::{env, iter::repeat};

#[derive(Debug)]
pub struct Prover {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Prover,
    pub chunk_protocol: Vec<u8>,
    raw_vk: Option<Vec<u8>>,
}

impl Prover {
    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        env::set_var("KECCAK_ROW", AGG_KECCAK_ROW.to_string());

        let inner = common::Prover::from_params_dir(params_dir, &AGG_DEGREES);
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
            inner,
            chunk_protocol,
            raw_vk,
        }
    }

    // Return true if chunk proofs are valid (same protocol), false otherwise.
    pub fn check_chunk_proofs(&self, chunk_proofs: &[ChunkProof]) -> bool {
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
        self.inner
            .raw_vk(LayerId::Layer4.id())
            .or_else(|| self.raw_vk.clone())
    }

    // Return the EVM proof for verification.
    pub fn gen_agg_evm_proof(
        &mut self,
        chunk_hashes_proofs: Vec<(ChunkHash, ChunkProof)>,
        name: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<BatchProof> {
        let name = name.map_or_else(
            || {
                chunk_hashes_proofs
                    .last()
                    .unwrap()
                    .0
                    .public_input_hash()
                    .to_low_u64_le()
                    .to_string()
            },
            |name| name.to_string(),
        );

        let layer3_snark =
            self.load_or_gen_last_agg_snark(&name, chunk_hashes_proofs, output_dir)?;

        // Load or generate final compression thin EVM proof (layer-4).
        let evm_proof = self.inner.load_or_gen_comp_evm_proof(
            &name,
            LayerId::Layer4.id(),
            true,
            LayerId::Layer4.degree(),
            layer3_snark,
            output_dir,
        )?;
        log::info!("Got final compression thin EVM proof (layer-4): {name}");

        self.check_and_clear_raw_vk();

        let batch_proof = BatchProof::from(evm_proof.proof);
        if let Some(output_dir) = output_dir {
            batch_proof.dump(output_dir, "agg")?;
        }

        Ok(batch_proof)
    }

    // Generate previous snark before the final one.
    // Then it could be used to generate a normal or EVM proof for verification.
    pub fn load_or_gen_last_agg_snark(
        &mut self,
        name: &str,
        chunk_hashes_proofs: Vec<(ChunkHash, ChunkProof)>,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let real_chunk_count = chunk_hashes_proofs.len();
        assert!((1..=MAX_AGG_SNARKS).contains(&real_chunk_count));

        check_chunk_hashes(name, &chunk_hashes_proofs)?;
        let (mut chunk_hashes, chunk_proofs): (Vec<_>, Vec<_>) =
            chunk_hashes_proofs.into_iter().unzip();

        if !self.check_chunk_proofs(&chunk_proofs) {
            bail!("non-match-chunk-protocol: {name}");
        }

        let mut layer2_snarks: Vec<_> = chunk_proofs.into_iter().map(|p| p.to_snark()).collect();

        if real_chunk_count < MAX_AGG_SNARKS {
            let padding_snark = layer2_snarks.last().unwrap().clone();
            let mut padding_chunk_hash = *chunk_hashes.last().unwrap();
            padding_chunk_hash.is_padding = true;

            // Extend to MAX_AGG_SNARKS for both chunk hashes and layer-2 snarks.
            chunk_hashes.extend(repeat(padding_chunk_hash).take(MAX_AGG_SNARKS - real_chunk_count));
            layer2_snarks.extend(repeat(padding_snark).take(MAX_AGG_SNARKS - real_chunk_count));
        }

        // Load or generate aggregation snark (layer-3).
        let layer3_snark = self.inner.load_or_gen_agg_snark(
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

    fn check_and_clear_raw_vk(&mut self) {
        if self.raw_vk.is_some() {
            // Check VK is same with the init one, and take (clear) init VK.
            let gen_vk = self.inner.raw_vk(LayerId::Layer4.id()).unwrap_or_default();
            let init_vk = self.raw_vk.take().unwrap_or_default();

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

macro_rules! compare_field {
    ($name:expr, $idx:expr, $field:ident, $lhs:ident, $rhs:ident) => {
        if $lhs.$field != $rhs.$field {
            bail!(
                "{} chunk-no-{}, different {}: {} != {}",
                $name,
                $idx,
                stringify!($field),
                $lhs.$field,
                $rhs.$field
            );
        }
    };
}

fn check_chunk_hashes(name: &str, chunk_hashes_proofs: &[(ChunkHash, ChunkProof)]) -> Result<()> {
    for (idx, (in_arg, chunk_proof)) in chunk_hashes_proofs.iter().enumerate() {
        if let Some(in_proof) = chunk_proof.chunk_hash {
            compare_field!(name, idx, chain_id, in_arg, in_proof);
            compare_field!(name, idx, prev_state_root, in_arg, in_proof);
            compare_field!(name, idx, post_state_root, in_arg, in_proof);
            compare_field!(name, idx, withdraw_root, in_arg, in_proof);
            compare_field!(name, idx, data_hash, in_arg, in_proof);
        }
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
            (ChunkHash::default(), ChunkProof::default()),
            (
                ChunkHash {
                    chain_id: 1,
                    prev_state_root: H256::zero(),
                    data_hash: [100; 32].into(),
                    ..Default::default()
                },
                ChunkProof {
                    chunk_hash: Some(ChunkHash {
                        chain_id: 1,
                        prev_state_root: [0; 32].into(),
                        data_hash: [100; 32].into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
            (
                ChunkHash {
                    post_state_root: H256::zero(),
                    ..Default::default()
                },
                ChunkProof {
                    chunk_hash: Some(ChunkHash {
                        post_state_root: [1; 32].into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        ];

        let result = check_chunk_hashes("test-batch", &chunk_hashes_proofs);
        assert_eq!(
            result.unwrap_err().downcast_ref::<String>().unwrap(),
            "test-batch chunk-no-2, different post_state_root: 0x0000…0000 != 0x0101…0101"
        );
    }
}
