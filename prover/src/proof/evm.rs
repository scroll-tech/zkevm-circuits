use super::{dump_as_json, dump_vk, from_json_file, Proof};
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::ProvingKey,
};
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvmProof {
    pub proof: Proof,
    pub num_instance: Vec<usize>,
}

impl EvmProof {
    pub fn new(
        proof: Vec<u8>,
        instances: &[Vec<Fr>],
        num_instance: Vec<usize>,
        pk: Option<&ProvingKey<G1Affine>>,
    ) -> Result<Self> {
        let proof = Proof::new(proof, instances, pk);

        Ok(Self {
            proof,
            num_instance,
        })
    }

    pub fn from_json_file(dir: &str, name: &str) -> Result<Self> {
        from_json_file(dir, &dump_filename(name))
    }

    pub fn dump(&self, dir: &str, name: &str) -> Result<()> {
        let filename = dump_filename(name);

        dump_vk(dir, &filename, &self.proof.vk);
        dump_as_json(dir, &filename, &self)
    }
}

fn dump_filename(name: &str) -> String {
    format!("evm_{name}")
}
