use std::{fs::File, path::Path};

use anyhow::Result;
use eth_types::base64;
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{Circuit, ProvingKey, VerifyingKey},
};
use serde_derive::{Deserialize, Serialize};
use snark_verifier_sdk::Snark;

use crate::utils::{
    deploy_and_call, deserialize_fr, deserialize_vk, serialize_fr, serialize_vk, short_git_version,
    write,
};

mod batch;
pub use batch::BatchProof;

mod bundle;
pub use bundle::BundleProof;

mod chunk;
pub use chunk::{compare_chunk_info, ChunkKind, ChunkProof};

mod evm;
pub use evm::EvmProof;

mod proof_v2;
pub use proof_v2::*;

/// Proof extracted from [`Snark`].
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct InnerProof {
    /// The raw bytes of the proof in the [`Snark`].
    ///
    /// Serialized using base64 format in order to not bloat the JSON-encoded proof dump.
    #[serde(with = "base64")]
    pub proof: Vec<u8>,
    /// The public values, aka instances of this [`Snark`].
    #[serde(with = "base64")]
    pub instances: Vec<u8>,
    /// The raw bytes of the [`VerifyingKey`] of the [`Circuit`] used to generate the [`Snark`].
    #[serde(with = "base64")]
    pub vk: Vec<u8>,
    /// The git ref of the codebase.
    ///
    /// Generally useful for debug reasons to know the exact commit using which this proof was
    /// generated.
    pub git_version: String,
}

impl InnerProof {
    pub fn new(proof: Vec<u8>, instances: &[Vec<Fr>], pk: Option<&ProvingKey<G1Affine>>) -> Self {
        let instances = serialize_instances(instances);
        let vk = pk.map_or_else(Vec::new, |pk| serialize_vk(pk.get_vk()));
        let git_version = short_git_version();

        Self {
            proof,
            instances,
            vk,
            git_version,
        }
    }

    pub fn from_snark(snark: Snark, vk: Vec<u8>) -> Self {
        let proof = snark.proof;
        let instances = serialize_instances(&snark.instances);
        let git_version = short_git_version();

        Self {
            proof,
            instances,
            vk,
            git_version,
        }
    }

    pub fn dump(&self, dir: &str, filename: &str) -> Result<()> {
        dump_vk(dir, filename, &self.vk)?;
        dump_as_json(dir, filename, &self)?;

        Ok(())
    }

    pub fn evm_verify(&self, deployment_code: Vec<u8>) -> bool {
        let instances = self.instances();
        let proof = self.proof().to_vec();
        let calldata = snark_verifier::loader::evm::encode_calldata(&instances, &proof);
        deploy_and_call(deployment_code, calldata).is_ok()
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        let instance: Vec<Fr> = self
            .instances
            .chunks(32)
            .map(|bytes| deserialize_fr(bytes.iter().rev().cloned().collect()))
            .collect();

        vec![instance]
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn raw_vk(&self) -> &[u8] {
        &self.vk
    }

    pub fn vk<C: Circuit<Fr, Params = ()>>(&self) -> VerifyingKey<G1Affine> {
        deserialize_vk::<C>(&self.vk)
    }
}

pub fn dump_as_json<T: serde::Serialize>(dir: &str, filename: &str, proof: &T) -> Result<()> {
    let mut fd = File::create(dump_proof_path(dir, filename))?;
    serde_json::to_writer(&mut fd, proof)?;

    Ok(())
}

pub fn dump_data(dir: &str, filename: &str, data: &[u8]) -> Result<()> {
    let path = Path::new(dir).join(filename);
    Ok(write(&path, data)?)
}

pub fn dump_vk(dir: &str, filename: &str, raw_vk: &[u8]) -> Result<()> {
    dump_data(dir, &format!("vk_{filename}.vkey"), raw_vk)
}

fn dump_proof_path(dir: &str, filename: &str) -> String {
    format!("{dir}/full_proof_{filename}.json")
}

/// Encode instances as concatenated U256
fn serialize_instance(instance: &[Fr]) -> Vec<u8> {
    let bytes: Vec<_> = instance
        .iter()
        .flat_map(|value| serialize_fr(value).into_iter().rev())
        .collect();
    assert_eq!(bytes.len() % 32, 0);
    bytes
}

fn serialize_instances(instances: &[Vec<Fr>]) -> Vec<u8> {
    assert_eq!(instances.len(), 1);
    serialize_instance(&instances[0])
}
