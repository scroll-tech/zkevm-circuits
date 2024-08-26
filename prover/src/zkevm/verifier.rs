use crate::{
    common,
    config::{LAYER2_CONFIG_PATH, LAYER2_DEGREE},
    consts::chunk_vk_filename,
    io::force_to_read,
    ChunkProof,
};
use aggregator::CompressionCircuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use std::{collections::BTreeMap, env};

#[derive(Debug)]
pub struct Verifier<'params> {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Verifier<'params, CompressionCircuit>,
}

impl<'params> From<common::Verifier<'params, CompressionCircuit>> for Verifier<'params> {
    fn from(inner: common::Verifier<'params, CompressionCircuit>) -> Self {
        Self { inner }
    }
}

impl<'params> Verifier<'params> {
    pub fn new(params: &'params ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>) -> Self {
        common::Verifier::new(params, vk).into()
    }

    pub fn from_params_and_assets(
        params_map: &'params BTreeMap<u32, ParamsKZG<Bn256>>,
        assets_dir: &str,
    ) -> Self {
        let raw_vk = force_to_read(assets_dir, &chunk_vk_filename());
        env::set_var("COMPRESSION_CONFIG", &*LAYER2_CONFIG_PATH);
        let params = params_map.get(&*LAYER2_DEGREE).expect("should be loaded");
        let verifier = common::Verifier::from_params(params, &raw_vk);
        verifier.into()
    }

    pub fn verify_chunk_proof(&self, proof: ChunkProof) -> bool {
        self.inner.verify_snark(proof.to_snark())
    }
}
