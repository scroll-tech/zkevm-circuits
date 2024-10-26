use std::{env, path::Path};

use aggregator::{BatchCircuit, BatchHash};
use anyhow::{anyhow, Result};
use halo2_proofs::halo2curves::bn256::G1Affine;
use rand::Rng;
use snark_verifier_sdk::Snark;

use crate::{
    config::layer_config_path,
    utils::{gen_rng, read_json_deep, write_json},
};

impl<'params> super::Prover<'params> {
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
        // If an output directory is provided and we are successfully able to locate a SNARK with
        // the same identifier on disk, return early.
        if let Some(dir) = output_dir {
            let path = Path::new(dir).join(format!("aggregation_snark_{}_{}.json", id, name));
            if let Ok(snark) = read_json_deep(&path) {
                return Ok(snark);
            }
        }

        // Generate the layer-3 SNARK.
        let rng = gen_rng();
        let snark = self.gen_agg_snark(
            id,
            degree,
            rng,
            batch_info,
            halo2_protocol,
            sp1_protocol,
            previous_snarks,
        )?;

        // Write to disk if an output directory is provided.
        if let Some(dir) = output_dir {
            let path = Path::new(dir).join(format!("aggregation_snark_{}_{}.json", id, name));
            write_json(&path, &snark)?;
        }

        Ok(snark)
    }

    #[allow(clippy::too_many_arguments)]
    fn gen_agg_snark<const N_SNARKS: usize>(
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
}
