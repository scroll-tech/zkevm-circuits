use super::Prover;
use crate::{
    config::layer_config_path,
    utils::{gen_rng, read_env_var},
    EvmProof,
};
use aggregator::CompressionCircuit;
use anyhow::{anyhow, Result};
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;
use snark_verifier_sdk::{gen_evm_proof_shplonk, CircuitExt, Snark};
use std::env;

impl<'params> Prover<'params> {
    pub fn load_or_gen_comp_evm_proof(
        &mut self,
        name: &str,
        id: &str,
        has_accumulator: bool,
        degree: u32,
        prev_snark: Snark,
        output_dir: Option<&str>,
    ) -> Result<EvmProof> {
        let name = format!("{id}_{name}");
        match output_dir.and_then(|output_dir| EvmProof::from_json_file(output_dir, &name).ok()) {
            Some(proof) => Ok(proof),
            None => {
                env::set_var("COMPRESSION_CONFIG", layer_config_path(id));

                let mut rng = gen_rng();
                let circuit = CompressionCircuit::new(
                    self.params(degree),
                    prev_snark,
                    has_accumulator,
                    &mut rng,
                )
                .map_err(|err| anyhow!("Failed to construct compression circuit: {err:?}"))?;

                let result = self.gen_evm_proof(id, degree, &mut rng, circuit, output_dir);

                if let (Some(output_dir), Ok(proof)) = (output_dir, &result) {
                    proof.dump(output_dir, &name)?;
                }

                result
            }
        }
    }

    fn gen_evm_proof<C: CircuitExt<Fr>>(
        &mut self,
        id: &str,
        degree: u32,
        rng: &mut (impl Rng + Send),
        circuit: C,
        output_dir: Option<&str>,
    ) -> Result<EvmProof> {
        Self::assert_if_mock_prover(id, degree, &circuit);

        let (params, pk) = self.params_and_pk(id, degree, &circuit)?;
        log::info!(
            "gen_evm_proof vk transcript_repr {:?}",
            pk.get_vk().transcript_repr()
        );
        let instances = circuit.instances();
        let num_instance = circuit.num_instance();
        let proof = gen_evm_proof_shplonk(params, pk, circuit, instances.clone(), rng);
        let evm_proof = EvmProof::new(proof, &instances, num_instance, Some(pk))?;

        if read_env_var("SCROLL_PROVER_DUMP_YUL", false) {
            crate::evm::gen_evm_verifier::<C>(params, pk.get_vk(), &evm_proof, output_dir);
        }

        Ok(evm_proof)
    }
}
