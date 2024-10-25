use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::CircuitExt;

use crate::{utils::gen_evm_verifier, EvmProof};

impl<'params, C: CircuitExt<Fr>> super::Verifier<'params, C> {
    pub fn gen_evm_verifier(&self, evm_proof: &EvmProof, output_dir: Option<&str>) {
        gen_evm_verifier::<C>(self.params, &self.vk, evm_proof, output_dir)
    }
}
