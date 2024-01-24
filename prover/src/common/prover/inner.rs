use super::Prover;
use crate::{
    config::INNER_DEGREE,
    io::{load_snark, write_snark},
    utils::{gen_rng, metric_of_witness_block},
    zkevm::circuit::{SuperCircuit, TargetCircuit},
};
use anyhow::Result;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};
use zkevm_circuits::evm_circuit::witness::Block;

impl Prover {
    pub fn gen_inner_snark<C: TargetCircuit>(
        &mut self,
        id: &str,
        mut rng: impl Rng + Send,
        witness_block: &Block<Fr>,
    ) -> Result<Snark> {
        log::info!(
            "Proving the chunk: {:?}",
            metric_of_witness_block(witness_block)
        );

        let degree = *INNER_DEGREE;

        let (circuit, _instance) = C::from_witness_block(witness_block)?;

        Self::assert_if_mock_prover(id, degree, &circuit);

        let (params, pk) = self.params_and_pk(id, degree, &C::dummy_inner_circuit())?;
        let snark = gen_snark_shplonk(params, pk, circuit, &mut rng, None::<String>);

        Ok(snark)
    }

    pub fn load_or_gen_inner_snark(
        &mut self,
        name: &str,
        id: &str,
        witness_block: &Block<Fr>,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let file_path = format!(
            "{}/inner_snark_{}_{}.json",
            output_dir.unwrap_or_default(),
            id,
            name
        );

        match output_dir.and_then(|_| load_snark(&file_path).ok().flatten()) {
            Some(snark) => Ok(snark),
            None => {
                let rng = gen_rng();
                let result = self.gen_inner_snark::<SuperCircuit>(id, rng, witness_block);
                if let (Some(_), Ok(snark)) = (output_dir, &result) {
                    write_snark(&file_path, snark);
                }

                result
            }
        }
    }
}
