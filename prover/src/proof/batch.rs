use std::path::Path;

use anyhow::Result;
use eth_types::{base64, H256};
use halo2_proofs::{halo2curves::bn256::G1Affine, plonk::ProvingKey};
use serde_derive::{Deserialize, Serialize};
use snark_verifier::Protocol;
use snark_verifier_sdk::Snark;

use crate::utils::read_json_deep;

use super::{dump_as_json, dump_vk, InnerProof};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchProof {
    #[serde(with = "base64")]
    pub protocol: Vec<u8>,
    #[serde(flatten)]
    proof: InnerProof,
    pub batch_hash: H256,
}

impl From<&BatchProof> for Snark {
    fn from(value: &BatchProof) -> Self {
        let instances = value.proof.instances();
        let protocol = serde_json::from_slice::<Protocol<G1Affine>>(&value.protocol).unwrap();

        Self {
            protocol,
            proof: value.proof.proof.clone(),
            instances,
        }
    }
}

impl BatchProof {
    pub fn new(snark: Snark, pk: Option<&ProvingKey<G1Affine>>, batch_hash: H256) -> Result<Self> {
        let protocol = serde_json::to_vec(&snark.protocol)?;
        let proof = InnerProof::new(snark.proof, &snark.instances, pk);

        Ok(Self {
            protocol,
            proof,
            batch_hash,
        })
    }

    pub fn from_json_file(dir: &str, name: &str) -> Result<Self> {
        let file_path = Path::new(dir).join(dump_filename(name));
        Ok(read_json_deep(&file_path)?)
    }

    pub fn dump_vk(&self, dir: &str, name: &str) -> Result<()> {
        let filename = dump_filename(name);
        if self.proof.vk.is_empty() {
            log::warn!("batch proof vk is empty, skip dumping");
        } else {
            dump_vk(dir, &filename, &self.proof.vk)?;
        }
        Ok(())
    }

    pub fn dump(&self, dir: &str, name: &str) -> Result<()> {
        let filename = dump_filename(name);
        dump_as_json(dir, &filename, &self)
    }
}

fn dump_filename(name: &str) -> String {
    format!("batch_{name}")
}
