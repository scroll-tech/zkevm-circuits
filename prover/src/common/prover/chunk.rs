use super::Prover;
use crate::{config::LayerId, utils::gen_rng};
use aggregator::extract_proof_and_instances_with_pairing_check;
use anyhow::{anyhow, Result};
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::Snark;
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
        let inner_snark = self.load_or_gen_inner_snark(
            name,
            inner_id.unwrap_or(LayerId::Inner.id()),
            witness_block,
            output_dir,
        )?;
        log::info!("Got inner snark: {name}");

        // Check pairing for super circuit.
        extract_proof_and_instances_with_pairing_check(
            self.params(LayerId::Layer1.degree()),
            &[inner_snark.clone()],
            gen_rng(),
        )
        .map_err(|err| anyhow!("Failed to check pairing for super circuit: {err:?}"))?;

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
}
