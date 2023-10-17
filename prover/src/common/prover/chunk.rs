use super::Prover;
use crate::{
    config::LayerId,
    utils::gen_rng,
    zkevm::circuit::{SuperCircuit, TargetCircuit},
};
use aggregator::extract_proof_and_instances_with_pairing_check;
use anyhow::{anyhow, Result};
use halo2_proofs::{halo2curves::bn256::Fr, poly::commitment::ParamsProver};
use snark_verifier_sdk::{verify_snark_shplonk, Snark};
use std::slice;
use zkevm_circuits::evm_circuit::witness::Block;

impl Prover {
    pub fn load_or_gen_final_chunk_snark(
        &mut self,
        name: &str,
        witness_block: &Block<Fr>,
        inner_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let layer1_snark =
            self.load_or_gen_last_chunk_snark(name, witness_block, inner_id, output_dir)?;

        // Load or generate compression thin snark (layer-2).
        let layer2_snark = self.load_or_gen_comp_snark(
            name,
            LayerId::Layer2.id(),
            true,
            LayerId::Layer2.degree(),
            layer1_snark,
            output_dir,
        )?;
        log::info!("Got compression thin snark (layer-2): {name}");

        Ok(layer2_snark)
    }

    // Generate previous snark before the final one.
    // Then it could be used to generate a normal or EVM proof for verification.
    pub fn load_or_gen_last_chunk_snark(
        &mut self,
        name: &str,
        witness_block: &Block<Fr>,
        inner_id: Option<&str>,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        // Load or generate inner snark.
        let inner_id = inner_id.unwrap_or(LayerId::Inner.id());
        let inner_snark =
            self.load_or_gen_inner_snark(name, inner_id, witness_block, output_dir)?;
        log::info!("Got inner snark: {name}");

        // Check pairing for super circuit snark.
        self.check_pairing_for_inner_snark(inner_id, &inner_snark)?;
        log::info!("Check pairing for inner snark successfully: {name}");

        // Load or generate compression wide snark (layer-1).
        let layer1_snark = self.load_or_gen_comp_snark(
            name,
            LayerId::Layer1.id(),
            false,
            LayerId::Layer1.degree(),
            inner_snark,
            output_dir,
        )?;
        log::info!("Got compression wide snark (layer-1): {name}");

        Ok(layer1_snark)
    }

    fn check_pairing_for_inner_snark(&self, inner_id: &str, inner_snark: &Snark) -> Result<()> {
        // Params must exist.
        let params = &self.params_map[&LayerId::Layer1.degree()];

        // Check pairing for snark.
        let pairing_result = extract_proof_and_instances_with_pairing_check(
            params,
            slice::from_ref(inner_snark),
            gen_rng(),
        );
        if pairing_result.is_ok() {
            return Ok(());
        }

        // Verify snark if failed to check pairing.
        let verified_result = if let Some(pk) = self.pk(inner_id) {
            // WARN: this may impact performance if failed to check pairing frequently.
            let verified = verify_snark_shplonk::<<SuperCircuit as TargetCircuit>::Inner>(
                params.verifier_params(),
                inner_snark.clone(),
                pk.get_vk(),
            );
            format!("inner snark verified = {verified}")
        } else {
            "no inner pk".to_string()
        };

        Err(anyhow!("Failed to check pairing for super circuit: {pairing_result:?}, verified result: {verified_result}"))
    }
}
