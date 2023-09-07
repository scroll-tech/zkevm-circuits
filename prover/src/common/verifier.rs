use crate::{io::deserialize_vk, utils::load_params, Proof};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use snark_verifier_sdk::{verify_snark_shplonk, CircuitExt, Snark};
use std::marker::PhantomData;

mod evm;
mod utils;

#[derive(Debug)]
pub struct Verifier<C: CircuitExt<Fr>> {
    params: ParamsKZG<Bn256>,
    vk: VerifyingKey<G1Affine>,
    phantom: PhantomData<C>,
}

impl<C: CircuitExt<Fr>> Verifier<C> {
    pub fn new(params: ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>) -> Self {
        Self {
            params,
            vk,
            phantom: PhantomData,
        }
    }

    pub fn from_params(params: ParamsKZG<Bn256>, raw_vk: &[u8]) -> Self {
        let vk = deserialize_vk::<C>(raw_vk);

        Self::new(params, vk)
    }

    pub fn from_params_dir(params_dir: &str, degree: u32, vk: &[u8]) -> Self {
        let params = load_params(params_dir, degree, None).unwrap();

        Self::from_params(params, vk)
    }

    pub fn verify_proof(&self, proof: Proof) -> bool {
        self.verify_snark(proof.to_snark())
    }

    pub fn verify_snark(&self, snark: Snark) -> bool {
        verify_snark_shplonk::<C>(self.params.verifier_params(), snark, &self.vk)
    }
}
