use super::Prover;
use crate::{
    config::layer_config_path,
    io::{load_snark, write_snark},
    utils::gen_rng,
};
use aggregator::{AggregationCircuit, BatchHash, ChunkHash};
use anyhow::{anyhow, Result};
use rand::Rng;
use snark_verifier_sdk::Snark;
use std::env;

impl Prover {
    pub fn gen_agg_snark(
        &mut self,
        id: &str,
        degree: u32,
        mut rng: impl Rng + Send,
        chunk_hashes: &[ChunkHash],
        previous_snarks: &[Snark],
    ) -> Result<Snark> {
        env::set_var("AGGREGATION_CONFIG", layer_config_path(id));

        let batch_hash = BatchHash::construct(chunk_hashes);

        let circuit =
            AggregationCircuit::new(self.params(degree), previous_snarks, &mut rng, batch_hash)
                .map_err(|err| anyhow!("Failed to construct aggregation circuit: {err:?}"))?;

        self.gen_snark(id, degree, &mut rng, circuit)
    }

    pub fn load_or_gen_agg_snark(
        &mut self,
        name: &str,
        id: &str,
        degree: u32,
        chunk_hashes: &[ChunkHash],
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
                let result = self.gen_agg_snark(id, degree, rng, chunk_hashes, previous_snarks);
                if let (Some(_), Ok(snark)) = (output_dir, &result) {
                    write_snark(&file_path, snark);
                }

                result
            }
        }
    }
}
