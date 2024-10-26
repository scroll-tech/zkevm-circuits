use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::CircuitExt;

impl<'params, C: CircuitExt<Fr>> super::Verifier<'params, C> {
    pub fn gen_evm_verifier(
        &self,
        evm_proof: &crate::EvmProof,
        output_dir: Option<&str>,
    ) -> Result<(), crate::ProverError> {
        crate::gen_evm_verifier::<C>(self.params, &self.vk, evm_proof, output_dir)
    }
}
