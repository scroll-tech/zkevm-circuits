use super::{dump_as_json, dump_data, dump_vk, from_json_file, serialize_instance, Proof};
use crate::utils::short_git_version;
use anyhow::Result;
use serde_derive::{Deserialize, Serialize};
use snark_verifier_sdk::encode_calldata;

const ACC_LEN: usize = 12;
const PI_LEN: usize = 32;

const ACC_BYTES: usize = ACC_LEN * 32;
const PI_BYTES: usize = PI_LEN * 32;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchProof {
    #[serde(flatten)]
    raw: Proof,
}

impl From<Proof> for BatchProof {
    fn from(proof: Proof) -> Self {
        let instances = proof.instances();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].len(), ACC_LEN + PI_LEN);

        let vk = proof.vk;
        let git_version = proof.git_version;

        // raw_proof = acc + proof
        let proof = serialize_instance(&instances[0][..ACC_LEN])
            .into_iter()
            .chain(proof.proof)
            .collect();

        // raw_instances = pi_data
        let instances = serialize_instance(&instances[0][ACC_LEN..]);

        Self {
            raw: Proof {
                proof,
                instances,
                vk,
                git_version,
            },
        }
    }
}

impl BatchProof {
    pub fn from_json_file(dir: &str, name: &str) -> Result<Self> {
        from_json_file(dir, &dump_filename(name))
    }

    pub fn calldata(self) -> Vec<u8> {
        let proof = self.proof_to_verify();

        // calldata = instances + proof
        let mut calldata = proof.instances;
        calldata.extend(proof.proof);

        calldata
    }

    pub fn dump(&self, dir: &str, name: &str) -> Result<()> {
        let filename = dump_filename(name);

        dump_data(dir, &format!("pi_{filename}.data"), &self.raw.instances);
        dump_data(dir, &format!("proof_{filename}.data"), &self.raw.proof);

        dump_vk(dir, &filename, &self.raw.vk);

        dump_as_json(dir, &filename, &self)
    }

    pub fn proof_to_verify(self) -> Proof {
        assert!(self.raw.proof.len() > ACC_BYTES);
        assert_eq!(self.raw.instances.len(), PI_BYTES);

        // instances = raw_proof[..12] (acc) + raw_instances (pi_data)
        // proof = raw_proof[12..]
        let mut instances = self.raw.proof;
        let proof = instances.split_off(ACC_BYTES);
        instances.extend(self.raw.instances);

        let vk = self.raw.vk;
        let git_version = Some(short_git_version());

        Proof {
            proof,
            instances,
            vk,
            git_version,
        }
    }

    pub fn assert_calldata(self) {
        let real_calldata = self.clone().calldata();

        let proof = self.proof_to_verify();
        let expected_calldata = encode_calldata(&proof.instances(), &proof.proof);

        assert_eq!(real_calldata, expected_calldata);
    }
}

fn dump_filename(name: &str) -> String {
    format!("batch_{name}")
}
