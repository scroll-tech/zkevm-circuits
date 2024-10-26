use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use snark_verifier_sdk::{verify_snark_shplonk, CircuitExt, Snark};
use std::marker::PhantomData;

use crate::utils::deserialize_vk;

mod evm;
mod utils;

#[derive(Debug)]
pub struct Verifier<'params, C: CircuitExt<Fr>> {
    params: &'params ParamsKZG<Bn256>,
    vk: VerifyingKey<G1Affine>,
    phantom: PhantomData<C>,
}

impl<'params, C: CircuitExt<Fr, Params = ()>> Verifier<'params, C> {
    pub fn new(params: &'params ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>) -> Self {
        Self {
            params,
            vk,
            phantom: PhantomData,
        }
    }

    pub fn from_params(params: &'params ParamsKZG<Bn256>, raw_vk: &[u8]) -> Self {
        let vk = deserialize_vk::<C>(raw_vk);
        Self::new(params, vk)
    }

    pub fn verify_snark(&self, snark: Snark) -> bool {
        verify_snark_shplonk::<C>(self.params.verifier_params(), snark, &self.vk)
    }
}
