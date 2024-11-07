use std::{env, path::PathBuf};

use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};

use crate::{
    common,
    config::{LAYER2_CONFIG_PATH, LAYER2_DEGREE},
    consts::chunk_vk_filename,
    utils::force_read,
    ChunkProofV2, ChunkProverError, ParamsMap, ProverError,
};

/// Verifier capable of verifying a [`ChunkProof`].
#[derive(Debug)]
pub struct Verifier<'params> {
    /// Encapsulates the common verifier.
    pub inner: common::Verifier<'params, CompressionCircuit>,
}

impl<'params> From<common::Verifier<'params, CompressionCircuit>> for Verifier<'params> {
    fn from(inner: common::Verifier<'params, CompressionCircuit>) -> Self {
        Self { inner }
    }
}

impl<'params> Verifier<'params> {
    /// Construct a new Verifier given the KZG parameters and a Verifying Key.
    pub fn new(params: &'params ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>) -> Self {
        common::Verifier::new(params, vk).into()
    }

    /// Construct a new Verifier given the path to an assets directory where the [`VerifyingKey`]
    /// is stored on disk. This method accepts a map of degree to the KZG parameters for that
    /// degree, and picks the appropriate parameters based on the degree of the
    /// [`Layer-2`][crate::config::LayerId::Layer2] [`CompressionCircuit`].
    ///
    /// Panics if the verifying key cannot be located in the given assets directory.
    pub fn from_params_and_assets(params_map: &'params ParamsMap, assets_dir: &str) -> Self {
        // Read the verifying key or panic.
        let path = PathBuf::from(assets_dir).join(chunk_vk_filename());
        let raw_vk = force_read(&path);

        // The Layer-2 compression circuit is configured with the shape as per
        // [`LAYER2_CONFIG_PATH`].
        env::set_var("COMPRESSION_CONFIG", &*LAYER2_CONFIG_PATH);

        let params = params_map
            .get(&*LAYER2_DEGREE)
            .unwrap_or_else(|| panic!("KZG params don't contain degree={:?}", LAYER2_DEGREE));

        Self {
            inner: common::Verifier::from_params(params, &raw_vk),
        }
    }

    /// Verify a chunk proof. Returns true if the verification is successful.
    pub fn verify_chunk_proof(&self, proof: &ChunkProofV2) -> Result<(), ProverError> {
        let snark = proof.try_into()?;
        if self.inner.verify_snark(snark) {
            Ok(())
        } else {
            Err(ChunkProverError::Verification.into())
        }
    }
}
