use crate::{
    common,
    config::{LAYER4_CONFIG_PATH, LAYER4_DEGREE},
    consts::{batch_vk_filename, DEPLOYMENT_CODE_FILENAME},
    io::{force_to_read, try_to_read},
    proof::BundleProof,
};
use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::verify_evm_calldata;
use snark_verifier_sdk::Snark;
use std::env;

#[derive(Debug)]
pub struct Verifier {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Verifier<CompressionCircuit>,
    deployment_code: Option<Vec<u8>>,
}

impl Verifier {
    pub fn new(
        params: ParamsKZG<Bn256>,
        vk: VerifyingKey<G1Affine>,
        deployment_code: Vec<u8>,
    ) -> Self {
        let inner = common::Verifier::new(params, vk);

        Self {
            inner,
            deployment_code: Some(deployment_code),
        }
    }

    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let raw_vk = force_to_read(assets_dir, &batch_vk_filename());
        let deployment_code = try_to_read(assets_dir, &DEPLOYMENT_CODE_FILENAME);

        env::set_var("COMPRESSION_CONFIG", &*LAYER4_CONFIG_PATH);
        let inner = common::Verifier::from_params_dir(params_dir, *LAYER4_DEGREE, &raw_vk);

        Self {
            inner,
            deployment_code,
        }
    }

    pub fn verify_batch_proof(&self, snark: impl Into<Snark>) -> bool {
        self.inner.verify_snark(snark.into())
    }

    pub fn verify_bundle_proof(&self, bundle_proof: BundleProof) -> bool {
        if let Some(deployment_code) = self.deployment_code.clone() {
            verify_evm_calldata(deployment_code, bundle_proof.calldata())
        } else {
            log::warn!("No deployment_code found for EVM verifier");
            false
        }
    }
}
