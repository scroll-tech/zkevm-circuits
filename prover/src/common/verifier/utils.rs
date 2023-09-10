use super::Verifier;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::CircuitExt;

impl<C: CircuitExt<Fr>> Verifier<C> {
    pub fn params(&self) -> &ParamsKZG<Bn256> {
        &self.params
    }

    pub fn vk(&self) -> &VerifyingKey<G1Affine> {
        &self.vk
    }

    pub fn set_vk(&mut self, vk: VerifyingKey<G1Affine>) {
        self.vk = vk;
    }
}
