use std::path::Path;

use anyhow::Result;
use rand::Rng;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};
use zkevm_circuits::evm_circuit::witness::Block;

use crate::{
    config::INNER_DEGREE,
    utils::{gen_rng, metric_of_witness_block, read_json_deep, write_json},
    zkevm::circuit::{SuperCircuit, TargetCircuit},
};

impl<'params> super::Prover<'params> {
    pub fn load_or_gen_inner_snark(
        &mut self,
        name: &str,
        id: &str,
        witness_block: &Block,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        // If an output directory is provided and we are successfully able to locate a SNARK with
        // the same identifier on disk, return early.
        if let Some(dir) = output_dir {
            let path = Path::new(dir).join(format!("inner_snark_{}_{}.json", id, name));
            if let Ok(snark) = read_json_deep(&path) {
                return Ok(snark);
            }
        }

        // Generate the inner SNARK.
        let rng = gen_rng();
        let snark = self.gen_inner_snark::<SuperCircuit>(id, rng, witness_block)?;

        // Write to disk if an output directory is provided.
        if let Some(dir) = output_dir {
            let path = Path::new(dir).join(format!("inner_snark_{}_{}.json", id, name));
            write_json(&path, &snark)?;
        }

        Ok(snark)
    }

    fn gen_inner_snark<C: TargetCircuit>(
        &mut self,
        id: &str,
        mut rng: impl Rng + Send,
        witness_block: &Block,
    ) -> Result<Snark> {
        log::info!(
            "Proving the chunk: {:?}",
            metric_of_witness_block(witness_block)
        );

        let degree = *INNER_DEGREE;

        let circuit = C::from_witness_block(witness_block)?;

        Self::assert_if_mock_prover(id, degree, &circuit);

        let (params, pk) = self.params_and_pk(id, degree, &C::dummy_inner_circuit()?)?;
        log::info!(
            "gen_inner_snark vk transcript_repr {:?}",
            pk.get_vk().transcript_repr()
        );
        let snark = gen_snark_shplonk(params, pk, circuit, &mut rng, None::<String>)?;

        Ok(snark)
    }
}
