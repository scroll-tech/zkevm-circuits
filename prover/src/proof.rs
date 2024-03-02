use crate::{
    io::{deserialize_fr, deserialize_vk, serialize_fr, serialize_vk, write_file},
    types::base64,
    utils::short_git_version,
};
use anyhow::{bail, Result};
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{Circuit, ProvingKey, VerifyingKey},
};
use serde_derive::{Deserialize, Serialize};
use snark_verifier::{
    util::{
        arithmetic::Domain,
        protocol::{Expression, QuotientPolynomial},
    },
    Protocol,
};
use snark_verifier_sdk::{verify_evm_proof, Snark};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

mod batch;
mod chunk;
mod evm;

pub use batch::BatchProof;
pub use chunk::ChunkProof;
pub use evm::EvmProof;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Proof {
    #[serde(with = "base64")]
    proof: Vec<u8>,
    #[serde(with = "base64")]
    instances: Vec<u8>,
    #[serde(with = "base64")]
    vk: Vec<u8>,
    pub git_version: Option<String>,
}

impl Proof {
    pub fn new(proof: Vec<u8>, instances: &[Vec<Fr>], pk: Option<&ProvingKey<G1Affine>>) -> Self {
        let instances = serialize_instances(instances);
        let vk = pk.map_or_else(Vec::new, |pk| serialize_vk(pk.get_vk()));
        let git_version = Some(short_git_version());

        Self {
            proof,
            instances,
            vk,
            git_version,
        }
    }

    pub fn from_json_file(dir: &str, filename: &str) -> Result<Self> {
        from_json_file(dir, filename)
    }

    pub fn from_snark(snark: Snark, vk: Vec<u8>) -> Self {
        let proof = snark.proof;
        let instances = serialize_instances(&snark.instances);
        let git_version = Some(short_git_version());

        Proof {
            proof,
            instances,
            vk,
            git_version,
        }
    }

    pub fn dump(&self, dir: &str, filename: &str) -> Result<()> {
        dump_vk(dir, filename, &self.vk);

        dump_as_json(dir, filename, &self)
    }

    pub fn evm_verify(&self, deployment_code: Vec<u8>) -> bool {
        verify_evm_proof(deployment_code, self.instances(), self.proof().to_vec())
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

    pub fn to_snark(self) -> Snark {
        let instances = self.instances();

        Snark {
            protocol: dummy_protocol(),
            proof: self.proof,
            instances,
        }
    }

    pub fn vk<C: Circuit<Fr>>(&self) -> VerifyingKey<G1Affine> {
        deserialize_vk::<C>(&self.vk)
    }
}

pub fn dump_as_json<P: serde::Serialize>(dir: &str, filename: &str, proof: &P) -> Result<()> {
    // Write full proof as json.
    let mut fd = File::create(dump_proof_path(dir, filename))?;
    serde_json::to_writer(&mut fd, proof)?;

    Ok(())
}

pub fn dump_data(dir: &str, filename: &str, data: &[u8]) {
    write_file(&mut PathBuf::from(dir), filename, data);
}

pub fn dump_vk(dir: &str, filename: &str, raw_vk: &[u8]) {
    dump_data(dir, &format!("vk_{filename}.vkey"), raw_vk);
}

pub fn from_json_file<'de, P: serde::Deserialize<'de>>(dir: &str, filename: &str) -> Result<P> {
    let file_path = dump_proof_path(dir, filename);
    if !Path::new(&file_path).exists() {
        bail!("File {file_path} doesn't exist");
    }

    let fd = File::open(file_path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(fd);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);

    Ok(serde::Deserialize::deserialize(deserializer)?)
}

fn dump_proof_path(dir: &str, filename: &str) -> String {
    format!("{dir}/full_proof_{filename}.json")
}

fn dummy_protocol() -> Protocol<G1Affine> {
    Protocol {
        domain: Domain {
            k: 0,
            n: 0,
            n_inv: Fr::zero(),
            gen: Fr::zero(),
            gen_inv: Fr::zero(),
        },
        preprocessed: vec![],
        num_instance: vec![],
        num_witness: vec![],
        num_challenge: vec![],
        evaluations: vec![],
        queries: vec![],
        quotient: QuotientPolynomial {
            chunk_degree: 0,
            numerator: Expression::Challenge(1),
        },
        //Default::default(),
        transcript_initial_state: None,
        instance_committing_key: None,
        linearization: None,
        accumulator_indices: Default::default(),
    }
}

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
