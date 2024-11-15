use std::{env, path::PathBuf};

use aggregator::{decode_bytes, BatchData, BatchHash, BatchHeader, ChunkInfo, MAX_AGG_SNARKS};
use eth_types::H256;
use sha2::{Digest, Sha256};
use snark_verifier_sdk::Snark;

use crate::{
    aggregator::BatchProverError,
    common,
    config::LayerId,
    consts::{
        BATCH_KECCAK_ROW, BATCH_VK_FILENAME, BUNDLE_VK_FILENAME, FD_HALO2_CHUNK_PROTOCOL,
        FD_SP1_CHUNK_PROTOCOL,
    },
    types::BundleProvingTask,
    utils::{force_read, try_read},
    BatchProofV2, BatchProofV2Metadata, BatchProvingTask, BundleProofV2, ChunkKind, ChunkProof,
    ChunkProofV2, ParamsMap, ProverError,
};

/// Prover capable of generating [`BatchProof`] and [`BundleProof`].
#[derive(Debug)]
pub struct Prover<'params> {
    /// Encapsulating the common prover.
    pub prover_impl: common::Prover<'params>,
    /// The SNARK [`protocol`][snark_verifier::Protocol] for the halo2-based route, i.e. where
    /// the inner SNARK is generated using the [`SuperCircuit`][zkevm_circuits::super_circuit::SuperCircuit].
    halo2_protocol: Vec<u8>,
    /// The SNARK [`protocol`][snark_verifier::Protocol] for the sp1-based route, i.e. where the
    /// inner proof is an Sp1 compressed proof, later SNARKified using a halo2-backend.
    sp1_protocol: Vec<u8>,
    /// The verifying key for [`Layer-4`][LayerId::Layer4] in the proof generation pipeline, i.e.
    /// the [`CompressionCircuit`][aggregator::CompressionCircuit] SNARK on top of the
    /// [`BatchCircuit`][aggregator::BatchCircuit] SNARK.
    ///
    /// This is an optional field, as it is generated on-the-fly for dev-mode, while the verifying
    /// key is expected in production environments.
    ///
    /// The verifying key is specified in its raw byte-encoded format.
    raw_vk_batch: Option<Vec<u8>>,
    /// The verifying key for [`Layer-6`][LayerId::Layer6] in the proof generation pipeline, i.e.
    /// the [`CompressionCircuit`][aggregator::CompressionCircuit] SNARK on top of the
    /// [`RecursionCircuit`][aggregator::RecursionCircuit] SNARK.
    ///
    /// This is an optional field, as it is generated on-the-fly for dev-mode, while the verifying
    /// key is expected in production environments.
    ///
    /// The verifying key is specified in its raw byte-encoded format.
    raw_vk_bundle: Option<Vec<u8>>,
}

impl<'params> Prover<'params> {
    /// Construct batch prover given a map of degree to KZG setup parameters and a path to the
    /// assets directory.
    ///
    /// Panics if the SNARK [`protocols`][snark_verifier::Protocol] for both [`chunk proof variants`][crate::proof::ChunkKind]
    /// are not found in the assets directory.
    pub fn from_params_and_assets(params_map: &'params ParamsMap, assets_dir: &str) -> Self {
        // Set the number of rows in the keccak-circuit's config. The value is eventually read
        // to configure the keccak config at runtime.
        log::debug!("set env KECCAK_ROWS={}", BATCH_KECCAK_ROW.to_string());
        env::set_var("KECCAK_ROWS", BATCH_KECCAK_ROW.to_string());

        // Construct the inner common prover.
        let prover_impl = common::Prover::from_params_map(params_map);

        // The SNARK protocols for both variants of the Layer-2 SNARK must be available in the
        // assets directory before setting up the batch prover. The SNARK protocols are
        // specifically for the halo2-route and sp1-route of generating chunk proofs.
        let halo2_protocol =
            force_read(PathBuf::from(assets_dir).join(FD_HALO2_CHUNK_PROTOCOL.clone()));
        let sp1_protocol =
            force_read(PathBuf::from(assets_dir).join(FD_SP1_CHUNK_PROTOCOL.clone()));

        // Try to read the verifying key for both Layer-4 and Layer-6 compression circuits.
        let raw_vk_batch = try_read(PathBuf::from(assets_dir).join(BATCH_VK_FILENAME.clone()));
        let raw_vk_bundle = try_read(PathBuf::from(assets_dir).join(BUNDLE_VK_FILENAME.clone()));

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
            halo2_protocol,
            sp1_protocol,
            raw_vk_batch,
            raw_vk_bundle,
        }
    }

    /// Returns the optional verifying key for [`Layer-4`][LayerId::Layer4] in byte-encoded form.
    pub fn get_batch_vk(&self) -> Option<Vec<u8>> {
        self.prover_impl
            .raw_vk(LayerId::Layer4.id())
            .or_else(|| self.raw_vk_batch.clone())
    }

    /// Returns the optional verifying key for [`Layer-6`][LayerId::Layer6] in byte-encoded form.
    pub fn get_bundle_vk(&self) -> Option<Vec<u8>> {
        self.prover_impl
            .raw_vk(LayerId::Layer6.id())
            .or_else(|| self.raw_vk_bundle.clone())
    }

    /// Generate [`BatchProof`] given a [`BatchProvingTask`].
    ///
    /// The [`Layer-2`][LayerId::Layer2] SNARKs representing chunk proofs are aggregated using the
    /// [`Layer-3`][LayerId::Layer3] [`BatchCircuit`][aggregator::BatchCircuit] and this SNARK is
    /// then compressed using the [`Layer-4`][LayerId::Layer4]
    /// [`CompressionCircuit`][aggregator::CompressionCircuit].
    ///
    /// Returns early if a batch proof with a matching proof identifier is found on disk in the
    /// provided output directory.
    pub fn gen_batch_proof(
        &mut self,
        batch: BatchProvingTask,
        name: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<BatchProofV2, ProverError> {
        // Denotes the identifier for this batch proving task. Eventually a generated proof is
        // cached to disk using this identifier.
        let name = name.map_or_else(|| batch.identifier(), |name| name.to_string());

        // Return early if the batch proof was found on disk.
        if let Some(output_dir) = output_dir {
            if let Ok(batch_proof) = BatchProofV2::from_json(output_dir, &name) {
                return Ok(batch_proof);
            }
        }

        // Load from disk or generate the layer-3 SNARK using the batch circuit.
        let (layer3_snark, batch_hash) =
            self.load_or_gen_last_agg_snark::<MAX_AGG_SNARKS>(batch, &name, output_dir)?;

        // Load from disk or generate the layer-4 SNARK using thin compression circuit.
        let layer4_snark = self
            .prover_impl
            .load_or_gen_comp_snark(
                &name,
                LayerId::Layer4.id(),
                true,
                LayerId::Layer4.degree(),
                layer3_snark,
                output_dir,
            )
            .map_err(|e| BatchProverError::Custom(e.to_string()))?;
        log::info!("Got batch compression thin proof (layer-4): {name}");

        // Sanity check on the layer-4 verifying key.
        self.check_batch_vk()?;

        // Get the proving key for layer-4.
        let pk = self.prover_impl.pk(LayerId::Layer4.id());

        // Build a wrapper around the layer-4 SNARK, aka batch proof.
        let batch_proof_metadata = BatchProofV2Metadata::new(&layer4_snark, batch_hash)?;
        let batch_proof = BatchProofV2::new(layer4_snark, pk, batch_proof_metadata)?;

        // If an output directory was provided, write the generated batch proof and layer-4
        // verifying key to disk.
        if let Some(output_dir) = output_dir {
            batch_proof.dump(output_dir, &name)?;
        }

        Ok(batch_proof)
    }

    /// Generate [`BundleProof`] given a [`BundleProvingTask`].
    ///
    /// The bundle proving task consists of a list of [`Layer-4`][LayerId::Layer4]
    /// [`BatchProofs`][BatchProof] representing the batches being bundled.
    ///
    /// The [`RecursionCircuit`][aggregator::RecursionCircuit] recursively proves the correctness
    /// of all those batch proofs.
    pub fn gen_bundle_proof(
        &mut self,
        bundle: BundleProvingTask,
        name: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<BundleProofV2, ProverError> {
        // Denotes the identifier for this bundle proving task. Eventually a generated proof is
        // written to disk using this name.
        let name = name.map_or_else(|| bundle.identifier(), |name| name.to_string());

        // Collect the layer-4 SNARKs from the batch proofs.
        let bundle_snarks = bundle
            .batch_proofs
            .iter()
            .map(Snark::try_from)
            .collect::<Result<Vec<Snark>, _>>()?;

        // Load from disk or generate a layer-5 Recursive Circuit SNARK.
        let layer5_snark = self
            .prover_impl
            .load_or_gen_recursion_snark(
                &name,
                LayerId::Layer5.id(),
                LayerId::Layer5.degree(),
                &bundle_snarks,
                output_dir,
            )
            .map_err(|e| BatchProverError::Custom(e.to_string()))?;

        // Load from disk or generate a layer-6 Compression Circuit SNARK. Since we use a Keccak
        // hasher for the proof transcript at layer-6, the output proof is EVM-verifiable.
        let layer6_proof = self
            .prover_impl
            .load_or_gen_comp_evm_proof(
                &name,
                LayerId::Layer6.id(),
                true,
                LayerId::Layer6.degree(),
                layer5_snark,
                output_dir,
            )
            .map_err(|e| BatchProverError::Custom(e.to_string()))?;

        // Sanity check for the layer-6 verifying key.
        self.check_bundle_vk()?;

        // Wrap the layer-6 proof into the wrapper Bundle Proof.
        let bundle_proof = BundleProofV2::new_from_raw(
            &layer6_proof.proof.proof,
            &layer6_proof.proof.instances,
            &layer6_proof.proof.vk,
        )?;

        // If an output directory was provided, write the bundle proof to disk.
        if let Some(output_dir) = output_dir {
            bundle_proof.dump(output_dir, "recursion")?;
        }

        Ok(bundle_proof)
    }

    /// Generate the [`Layer-3`][LayerId::Layer3] SNARK using the [`BatchCircuit`][aggregator::BatchCircuit].
    ///
    /// Returns early if the SNARK was located on disk.
    fn load_or_gen_last_agg_snark<const N_SNARKS: usize>(
        &mut self,
        batch: BatchProvingTask,
        name: &str,
        output_dir: Option<&str>,
    ) -> Result<(Snark, H256), ProverError> {
        // Early return with an error if the number of SNARKs to aggregate is not within limits.
        let num_chunks = batch.chunk_proofs.len();
        if !(1..=MAX_AGG_SNARKS).contains(&num_chunks) {
            return Err(BatchProverError::Custom(format!(
                "1 <= num_chunks <= MAX_AGG_SNARKS, found={num_chunks}"
            ))
            .into());
        }

        // Sanity check on the chunk proof's SNARK protocols.
        self.check_protocol_of_chunks(&batch.chunk_proofs)?;

        // Split chunk info and snarks from the batch proving task.
        let mut chunk_infos = batch
            .chunk_proofs
            .iter()
            .map(|proof| proof.inner.chunk_info().clone())
            .collect::<Vec<_>>();
        let mut layer2_snarks = batch
            .chunk_proofs
            .iter()
            .map(Snark::try_from)
            .collect::<Result<Vec<Snark>, ProverError>>()?;

        // Pad the SNARKs with the last SNARK until we have MAX_AGG_SNARKS number of SNARKs.
        if num_chunks < MAX_AGG_SNARKS {
            let padding_chunk_info = {
                let mut last_chunk = chunk_infos.last().expect("num_chunks > 0").clone();
                last_chunk.is_padding = true;
                last_chunk
            };
            let padding_snark = layer2_snarks.last().expect("num_chunks > 0").clone();

            // Extend to MAX_AGG_SNARKS for both chunk infos and layer-2 snarks.
            chunk_infos.resize(MAX_AGG_SNARKS, padding_chunk_info);
            layer2_snarks.resize(MAX_AGG_SNARKS, padding_snark);
        }

        // Reconstruct the batch header.
        let batch_header = BatchHeader::construct_from_chunks(
            batch.batch_header.version,
            batch.batch_header.batch_index,
            batch.batch_header.l1_message_popped,
            batch.batch_header.total_l1_message_popped,
            batch.batch_header.parent_batch_hash,
            batch.batch_header.last_block_timestamp,
            &chunk_infos,
            &batch.blob_bytes,
        );
        let batch_hash = batch_header.batch_hash();

        // Sanity checks between the Batch Header supplied vs reconstructed.
        //
        // Batch's data_hash field must match.
        if batch_header.data_hash != batch.batch_header.data_hash {
            return Err(BatchProverError::Custom(format!(
                "BatchHeader(sanity) data_hash mismatch! expected={}, got={}",
                batch.batch_header.data_hash, batch_header.data_hash
            ))
            .into());
        }
        // Batch's random challenge point (z) must match.
        if batch_header.blob_data_proof[0] != batch.batch_header.blob_data_proof[0] {
            return Err(BatchProverError::Custom(format!(
                "BatchHeader(sanity) random challenge (z) mismatch! expected={}, got={}",
                batch.batch_header.blob_data_proof[0], batch_header.blob_data_proof[0],
            ))
            .into());
        }
        // Batch's evaluation at z, i.e. y, must match.
        if batch_header.blob_data_proof[1] != batch.batch_header.blob_data_proof[1] {
            return Err(BatchProverError::Custom(format!(
                "BatchHeader(sanity) evaluation (y) mismatch! expected={}, got={}",
                batch.batch_header.blob_data_proof[1], batch_header.blob_data_proof[1],
            ))
            .into());
        }
        // The versioned hash of the blob that encodes the batch must match.
        if batch_header.blob_versioned_hash != batch.batch_header.blob_versioned_hash {
            return Err(BatchProverError::Custom(format!(
                "BatchHeader(sanity) blob versioned_hash mismatch! expected={}, got={}",
                batch.batch_header.blob_versioned_hash, batch_header.blob_versioned_hash,
            ))
            .into());
        }

        // Build relevant types that are used for batch circuit witness assignments.
        let batch_info: BatchHash<N_SNARKS> =
            BatchHash::construct(&chunk_infos, batch_header, &batch.blob_bytes);
        let batch_data: BatchData<N_SNARKS> = BatchData::from(&batch_info);

        // Sanity check: validate that conditionally decoded blob should match batch data.
        let batch_bytes = batch_data.get_batch_data_bytes();
        let decoded_blob_bytes =
            decode_bytes(&batch.blob_bytes).map_err(|e| BatchProverError::Custom(e.to_string()))?;
        if batch_bytes != decoded_blob_bytes {
            return Err(BatchProverError::Custom(format!(
                "BatchProvingTask(sanity) decoded blob bytes do not match batch bytes! len(expected)={}, len(got)={}",
                decoded_blob_bytes.len(),
                batch_bytes.len(),
            )).into());
        }

        // Load from disk or generate the layer-3 SNARK using the batch circuit.
        let layer3_snark = self
            .prover_impl
            .load_or_gen_agg_snark(
                name,
                LayerId::Layer3.id(),
                LayerId::Layer3.degree(),
                batch_info,
                &self.halo2_protocol,
                &self.sp1_protocol,
                &layer2_snarks,
                output_dir,
            )
            .map_err(|e| BatchProverError::Custom(e.to_string()))?;

        Ok((layer3_snark, batch_hash))
    }

    /// Sanity check: validate that the SNARK [`protocol`][snark_verifier::Protocol] for the SNARKs
    /// being aggregated by the [`BatchCircuit`][aggregator::BatchCircuit] match the expected SNARK
    /// protocols conditional to the chunk proof generation route utilised, i.e. halo2 or sp1.
    fn check_protocol_of_chunks(&self, chunk_proofs: &[ChunkProofV2]) -> Result<(), ProverError> {
        for (i, proof) in chunk_proofs.iter().enumerate() {
            let expected = match proof.inner.chunk_kind() {
                ChunkKind::Halo2 => &self.halo2_protocol,
                ChunkKind::Sp1 => &self.sp1_protocol,
            };
            if proof.inner.protocol().ne(expected) {
                let expected_digest = format!("{:x}", Sha256::digest(expected));
                let found_digest = format!("{:x}", Sha256::digest(proof.inner.protocol()));
                log::error!(
                    "BatchProver: SNARK protocol mismatch! index={}, expected={}, found={}",
                    i,
                    expected_digest,
                    found_digest,
                );
                return Err(BatchProverError::ChunkProtocolMismatch(
                    i,
                    expected_digest,
                    found_digest,
                )
                .into());
            }
        }

        Ok(())
    }

    /// Sanity check for the [`VerifyinKey`][halo2_proofs::plonk::VerifyingKey] used to generate
    /// Layer-4 SNARK that is wrapped inside the [`BatchProof`]. The prover generated VK is
    /// expected to match the VK used to initialise the prover.
    fn check_batch_vk(&self) -> Result<(), ProverError> {
        let layer = LayerId::Layer4;
        if let Some(expected_vk) = self.raw_vk_batch.as_ref() {
            let base64_exp_vk = base64::encode(expected_vk);
            if let Some(generated_vk) = self.prover_impl.raw_vk(layer.id()).as_ref() {
                let base64_gen_vk = base64::encode(generated_vk);
                if generated_vk.ne(expected_vk) {
                    log::error!(
                        "BatchProver: {:?} VK mismatch! found={}, expected={}",
                        layer,
                        base64_gen_vk,
                        base64_exp_vk,
                    );
                    return Err(BatchProverError::VerifyingKeyMismatch(
                        layer,
                        base64_gen_vk,
                        base64_exp_vk,
                    )
                    .into());
                }
            } else {
                return Err(BatchProverError::VerifyingKeyNotFound(layer, base64_exp_vk).into());
            }
        }

        Ok(())
    }

    /// Sanity check for the [`VerifyinKey`][halo2_proofs::plonk::VerifyingKey] used to generate
    /// Layer-6 SNARK that is wrapped inside the [`BundleProof`]. The prover generated VK is
    /// expected to match the VK used to initialise the prover.
    fn check_bundle_vk(&self) -> Result<(), ProverError> {
        let layer = LayerId::Layer6;
        if let Some(expected_vk) = self.raw_vk_bundle.as_ref() {
            let base64_exp_vk = base64::encode(expected_vk);
            if let Some(generated_vk) = self.prover_impl.raw_vk(layer.id()).as_ref() {
                let base64_gen_vk = base64::encode(generated_vk);
                if generated_vk.ne(expected_vk) {
                    log::error!(
                        "BatchProver: {:?} VK mismatch! found={}, expected={}",
                        layer,
                        base64_gen_vk,
                        base64_exp_vk,
                    );
                    return Err(BatchProverError::VerifyingKeyMismatch(
                        layer,
                        base64_gen_vk,
                        base64_exp_vk,
                    )
                    .into());
                }
            } else {
                return Err(BatchProverError::VerifyingKeyNotFound(layer, base64_exp_vk).into());
            }
        }

        Ok(())
    }
}

pub fn check_chunk_hashes(
    name: &str,
    chunk_hashes_proofs: &[(ChunkInfo, ChunkProof)],
) -> anyhow::Result<()> {
    for (idx, (in_arg, chunk_proof)) in chunk_hashes_proofs.iter().enumerate() {
        let in_proof = &chunk_proof.chunk_info;
        if let Err(e) =
            crate::proof::compare_chunk_info(&format!("{name} chunk num {idx}"), in_arg, in_proof)
        {
            anyhow::bail!(e);
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
