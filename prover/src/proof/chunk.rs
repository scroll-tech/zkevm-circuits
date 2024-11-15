use std::path::Path;

use aggregator::ChunkInfo;
use eth_types::base64;
use halo2_proofs::{halo2curves::bn256::G1Affine, plonk::ProvingKey};
use serde_derive::{Deserialize, Serialize};
use snark_verifier::Protocol;
use snark_verifier_sdk::Snark;

use crate::{utils::read_json_deep, zkevm::SubCircuitRowUsage};

use super::{dump_as_json, dump_data, dump_vk, InnerProof};

/// The innermost SNARK belongs to the following variants.
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum ChunkKind {
    /// halo2-based SuperCircuit.
    Halo2,
    /// sp1-based STARK with a halo2-backend.
    Sp1,
}

impl Default for ChunkKind {
    fn default() -> Self {
        Self::Halo2
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ChunkProof {
    #[serde(with = "base64")]
    pub protocol: Vec<u8>,
    #[serde(flatten)]
    pub proof: InnerProof,
    pub chunk_info: ChunkInfo,
    pub chunk_kind: ChunkKind,
    #[serde(default)]
    pub row_usages: Vec<SubCircuitRowUsage>,
}

macro_rules! compare_field {
    ($desc:expr, $field:ident, $lhs:ident, $rhs:ident) => {
        if $lhs.$field != $rhs.$field {
            return Err(format!(
                "{} chunk different {}: {} != {}",
                $desc,
                stringify!($field),
                $lhs.$field,
                $rhs.$field
            ));
        }
    };
}

/// Check chunk info is consistent with chunk info embedded inside proof
pub fn compare_chunk_info(name: &str, lhs: &ChunkInfo, rhs: &ChunkInfo) -> Result<(), String> {
    compare_field!(name, chain_id, lhs, rhs);
    compare_field!(name, prev_state_root, lhs, rhs);
    compare_field!(name, post_state_root, lhs, rhs);
    compare_field!(name, withdraw_root, lhs, rhs);
    compare_field!(name, data_hash, lhs, rhs);
    if lhs.tx_bytes != rhs.tx_bytes {
        return Err(format!(
            "{} chunk different {}: {} != {}",
            name,
            "tx_bytes",
            hex::encode(&lhs.tx_bytes),
            hex::encode(&rhs.tx_bytes)
        ));
    }

    Ok(())
}

impl ChunkProof {
    pub fn new(
        snark: Snark,
        pk: Option<&ProvingKey<G1Affine>>,
        chunk_info: ChunkInfo,
        chunk_kind: ChunkKind,
        row_usages: Vec<SubCircuitRowUsage>,
    ) -> anyhow::Result<Self> {
        let protocol = serde_json::to_vec(&snark.protocol)?;
        let proof = InnerProof::new(snark.proof, &snark.instances, pk);

        Ok(Self {
            protocol,
            proof,
            chunk_info,
            chunk_kind,
            row_usages,
        })
    }

    pub fn from_json_file(dir: &str, name: &str) -> anyhow::Result<Self> {
        let path = Path::new(dir).join(dump_filename(name));
        Ok(read_json_deep(&path)?)
    }

    pub fn dump(&self, dir: &str, name: &str) -> anyhow::Result<()> {
        let filename = dump_filename(name);

        // Dump vk and protocol.
        dump_vk(dir, &filename, &self.proof.vk)?;
        dump_data(dir, &format!("chunk_{filename}.protocol"), &self.protocol)?;
        dump_as_json(dir, &filename, &self)?;

        Ok(())
    }

    pub fn to_snark(&self) -> Snark {
        let instances = self.proof.instances();
        let protocol = serde_json::from_slice::<Protocol<G1Affine>>(&self.protocol).unwrap();

        Snark {
            protocol,
            proof: self.proof.proof.clone(),
            instances,
        }
    }
}

fn dump_filename(name: &str) -> String {
    format!("chunk_{name}")
}
