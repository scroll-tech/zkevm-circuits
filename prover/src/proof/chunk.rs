use super::{dump_as_json, dump_data, dump_vk, from_json_file, Proof};
use crate::types::base64;
use aggregator::ChunkHash;
use anyhow::Result;
use halo2_proofs::{halo2curves::bn256::G1Affine, plonk::ProvingKey};
use serde_derive::{Deserialize, Serialize};
use snark_verifier::Protocol;
use snark_verifier_sdk::Snark;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ChunkProof {
    #[serde(with = "base64")]
    pub protocol: Vec<u8>,
    #[serde(flatten)]
    pub proof: Proof,
    #[serde(rename = "chunk_info")]
    pub chunk_hash: Option<ChunkHash>,
}

impl ChunkProof {
    pub fn new(
        snark: Snark,
        pk: Option<&ProvingKey<G1Affine>>,
        chunk_hash: Option<ChunkHash>,
    ) -> Result<Self> {
        let protocol = serde_json::to_vec(&snark.protocol)?;
        let proof = Proof::new(snark.proof, &snark.instances, pk);

        Ok(Self {
            protocol,
            proof,
            chunk_hash,
        })
    }

    pub fn from_json_file(dir: &str, name: &str) -> Result<Self> {
        from_json_file(dir, &dump_filename(name))
    }

    pub fn dump(&self, dir: &str, name: &str) -> Result<()> {
        let filename = dump_filename(name);

        // Dump vk and protocol.
        dump_vk(dir, &filename, &self.proof.vk);
        dump_data(dir, &format!("chunk_{filename}.protocol"), &self.protocol);

        dump_as_json(dir, &filename, &self)
    }

    pub fn to_snark(self) -> Snark {
        let instances = self.proof.instances();
        let protocol = serde_json::from_slice::<Protocol<G1Affine>>(&self.protocol).unwrap();

        Snark {
            protocol,
            proof: self.proof.proof,
            instances,
        }
    }
}

fn dump_filename(name: &str) -> String {
    format!("chunk_{name}")
}
