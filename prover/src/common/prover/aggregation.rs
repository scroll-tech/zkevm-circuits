use super::Prover;
use crate::{
    config::layer_config_path,
    io::{load_snark, write_snark},
    utils::gen_rng,
};
use aggregator::{BatchCircuit, BatchHash};
use anyhow::{anyhow, Result};
use halo2_proofs::halo2curves::bn256::G1Affine;
use rand::Rng;
use snark_verifier_sdk::Snark;
use std::env;

impl<'params> Prover<'params> {
    #[allow(clippy::too_many_arguments)]
    pub fn gen_agg_snark<const N_SNARKS: usize>(
        &mut self,
        id: &str,
        degree: u32,
        mut rng: impl Rng + Send,
        batch_info: BatchHash<N_SNARKS>,
        halo2_protocol: &[u8],
        sp1_protocol: &[u8],
        previous_snarks: &[Snark],
    ) -> Result<Snark> {
        env::set_var("AGGREGATION_CONFIG", layer_config_path(id));

        let halo2_protocol =
            serde_json::from_slice::<snark_verifier::Protocol<G1Affine>>(halo2_protocol)?;
        let sp1_protocol =
            serde_json::from_slice::<snark_verifier::Protocol<G1Affine>>(sp1_protocol)?;

        let circuit: BatchCircuit<N_SNARKS> = BatchCircuit::new(
            self.params(degree),
            previous_snarks,
            &mut rng,
            batch_info,
            halo2_protocol,
            sp1_protocol,
        )
        .map_err(|err| anyhow!("Failed to construct aggregation circuit: {err:?}"))?;

        self.gen_snark(id, degree, &mut rng, circuit, "gen_agg_snark")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn load_or_gen_agg_snark<const N_SNARKS: usize>(
        &mut self,
        name: &str,
        id: &str,
        degree: u32,
        batch_info: BatchHash<N_SNARKS>,
        halo2_protocol: &[u8],
        sp1_protocol: &[u8],
        previous_snarks: &[Snark],
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let file_path = format!(
            "{}/aggregation_snark_{}_{}.json",
            output_dir.unwrap_or_default(),
            id,
            name
        );

        match output_dir.and_then(|_| load_snark(&file_path).ok().flatten()) {
            Some(snark) => Ok(snark),
            None => {
                let rng = gen_rng();
                let result = self.gen_agg_snark(
                    id,
                    degree,
                    rng,
                    batch_info,
                    halo2_protocol,
                    sp1_protocol,
                    previous_snarks,
                );
                if let (Some(_), Ok(snark)) = (output_dir, &result) {
                    write_snark(&file_path, snark);
                }

                result
            }
        }
    }
}
