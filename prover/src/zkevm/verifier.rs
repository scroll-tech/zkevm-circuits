use crate::{
    common,
    config::{LAYER2_CONFIG_PATH, LAYER2_DEGREE},
    consts::CHUNK_VK_FILENAME,
    io::force_to_read,
    ChunkProof,
};
use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use std::env;

#[derive(Debug)]
pub struct Verifier {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Verifier<CompressionCircuit>,
}

impl From<common::Verifier<CompressionCircuit>> for Verifier {
    fn from(inner: common::Verifier<CompressionCircuit>) -> Self {
        Self { inner }
    }
}

impl Verifier {
    pub fn new(params: ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>) -> Self {
        common::Verifier::new(params, vk).into()
    }

    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let raw_vk = force_to_read(assets_dir, &CHUNK_VK_FILENAME);

        env::set_var("COMPRESSION_CONFIG", &*LAYER2_CONFIG_PATH);
        common::Verifier::from_params_dir(params_dir, *LAYER2_DEGREE, &raw_vk).into()
    }

    pub fn verify_chunk_proof(&self, proof: ChunkProof) -> bool {
        self.inner.verify_snark(proof.to_snark())
    }
}
