use std::env;

use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::Snark;

use crate::{
    common,
    config::{LAYER4_CONFIG_PATH, LAYER4_DEGREE},
    consts::{batch_vk_filename, DEPLOYMENT_CODE_FILENAME},
    evm::deploy_and_call,
    io::{force_to_read, try_to_read},
    proof::BundleProof,
    ParamsMap,
};

/// Verifier capable of verifying both [`BatchProof`][crate::BatchProof] and [`BundleProof`].
#[derive(Debug)]
pub struct Verifier<'params> {
    /// Encapsulate the common verifier.
    pub inner: common::Verifier<'params, CompressionCircuit>,
    /// The EVM deployment code for the verifier contract.
    ///
    /// This field is optional as it is not set in dev-mode. It is expected in production
    /// environments where we already have the verifier contract's deployment code available. In
    /// dev-mode or E2E testing, we generate the deployment code on-the-fly.
    deployment_code: Option<Vec<u8>>,
}

impl<'params> Verifier<'params> {
    /// Construct a new batch verifier.
    pub fn new(
        params: &'params ParamsKZG<Bn256>,
        vk: VerifyingKey<G1Affine>,
        deployment_code: Vec<u8>,
    ) -> Self {
        let inner = common::Verifier::new(params, vk);

        Self {
            inner,
            deployment_code: Some(deployment_code),
        }
    }

    /// Instantiate a new batch verifier given a map of degree to KZG setup parameters and a
    /// directory to find assets.
    ///
    /// Panics if the verifying key is not found in the assets directory.
    pub fn from_params_and_assets(params_map: &'params ParamsMap, assets_dir: &str) -> Self {
        // Read verifying key in the assets directory.
        let raw_vk = force_to_read(assets_dir, &batch_vk_filename());

        // Try to read the bytecode to deploy the verifier contract.
        let deployment_code = try_to_read(assets_dir, &DEPLOYMENT_CODE_FILENAME);

        // The Layer-4 compressioe circuit is configured with the shape as per
        // [`LAYER4_CONFIG_PATH`].
        env::set_var("COMPRESSION_CONFIG", &*LAYER4_CONFIG_PATH);

        let params = params_map.get(&*LAYER4_DEGREE).expect(&format!(
            "KZG params don't contain degree={:?}",
            LAYER4_DEGREE
        ));

        Self {
            inner: common::Verifier::from_params(params, &raw_vk),
            deployment_code,
        }
    }

    /// Verify a [`Layer-4`][crate::config::LayerId::Layer4] [`CompressionCircuit`] [`Snark`].
    pub fn verify_batch_proof<S: Into<Snark>>(&self, snark: S) -> bool {
        self.inner.verify_snark(snark.into())
    }

    /// Verify a [`Layer-6`][crate::config::LayerId::Layer6] EVM-verifiable
    /// [`Proof`][crate::proof::EvmProof], aka [`BundleProof`].
    ///
    /// Returns `false` if the verifier contract's deployment bytecode is not set. Otherwise
    /// deploys the contract and verifies the proof utilising an [`EVM Executor`][revm].
    pub fn verify_bundle_proof(&self, bundle_proof: BundleProof) -> bool {
        self.deployment_code.as_ref().map_or_else(
            || {
                log::error!("EVM verifier deployment code not found");
                false
            },
            |code| deploy_and_call(code.to_vec(), bundle_proof.calldata()).is_ok(),
        )
    }
}
