use super::Verifier;
use crate::EvmProof;
use ce_snark_verifier_sdk::CircuitExt as CeCircuitExt;
use halo2_proofs::halo2curves::bn256::Fr;

impl<'params, C: CeCircuitExt<Fr>> Verifier<'params, C> {
    pub fn gen_evm_verifier(&self, evm_proof: &EvmProof, output_dir: Option<&str>) {
        crate::evm::gen_evm_verifier::<C>(self.params, &self.vk, evm_proof, output_dir)
    }
}
