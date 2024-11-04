use std::{env, path::Path};

use aggregator::CompressionCircuit;
use anyhow::{anyhow, Result};
use rand::Rng;
use snark_verifier_sdk::Snark;

use crate::{
    config::layer_config_path,
    utils::{gen_rng, read_json_deep, write_json},
};

impl<'params> super::Prover<'params> {
    pub fn load_or_gen_comp_snark(
        &mut self,
        name: &str,
        id: &str,
        has_accumulator: bool,
        degree: u32,
        prev_snark: Snark,
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        // If an output directory is provided and we are successfully able to locate a SNARK with
        // the same identifier on disk, return early.
        if let Some(dir) = output_dir {
            let path = Path::new(dir).join(format!("compression_snark_{}_{}.json", id, name));
            if let Ok(snark) = read_json_deep(&path) {
                return Ok(snark);
            }
        }

        // Generate the compression SNARK.
        let rng = gen_rng();
        let snark = self.gen_comp_snark(id, has_accumulator, degree, rng, prev_snark)?;

        // Write to disk if an output directory is provided.
        if let Some(dir) = output_dir {
            let path = Path::new(dir).join(format!("compression_snark_{}_{}.json", id, name));
            write_json(&path, &snark)?;
        }

        Ok(snark)
    }

    fn gen_comp_snark(
        &mut self,
        id: &str,
        has_accumulator: bool,
        degree: u32,
        mut rng: impl Rng + Send,
        prev_snark: Snark,
    ) -> Result<Snark> {
        env::set_var("COMPRESSION_CONFIG", layer_config_path(id));

        let circuit =
            CompressionCircuit::new(self.params(degree), prev_snark, has_accumulator, &mut rng)
                .map_err(|err| anyhow!("Failed to construct compression circuit: {err:?}"))?;
        self.gen_snark(id, degree, &mut rng, circuit, "gen_comp_snark")
    }
}
