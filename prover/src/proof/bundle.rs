use super::{dump_as_json, dump_data, dump_vk, serialize_instance};
use crate::{utils::short_git_version, Proof};
use anyhow::Result;
use serde_derive::{Deserialize, Serialize};

// 3 limbs per field element, 4 field elements
const ACC_LEN: usize = 12;

// - Accmulator (4*LIMBS)
// - PREPROCESS_DIGEST, ROUND
// - (hi, lo) finalised state root
// - (hi, lo) finalised batch hash
// - (hi, lo) pending state root
// - (hi, lo) pending batch hash
// - chain id
// - (hi, lo) pending withdraw root
// - bundle count

const PI_LEN: usize = 13;

const ACC_BYTES: usize = ACC_LEN * 32;
const PI_BYTES: usize = PI_LEN * 32;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BundleProof {
    #[serde(flatten)]
    on_chain_proof: Proof,
}

impl From<Proof> for BundleProof {
    fn from(proof: Proof) -> Self {
        let instances = proof.instances();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].len(), ACC_LEN + PI_LEN);

        let vk = proof.vk;
        let git_version = proof.git_version;

        // "onchain proof" = accumulator + proof
        let proof = serialize_instance(&instances[0][..ACC_LEN])
            .into_iter()
            .chain(proof.proof)
            .collect();

        // "onchain instances" = pi_data
        let instances = serialize_instance(&instances[0][ACC_LEN..]);

        Self {
            on_chain_proof: Proof {
                proof,
                instances,
                vk,
                git_version,
            },
        }
    }
}

impl BundleProof {
    /// Returns the calldata given to YUL verifier.
    /// Format: Accumulator(12x32bytes) || PI(13x32bytes) || Proof
    pub fn calldata(self) -> Vec<u8> {
        let proof = self.proof_to_verify();

        // calldata = instances + proof
        let mut calldata = proof.instances;
        calldata.extend(proof.proof);

        calldata
    }

    pub fn dump(&self, dir: &str, name: &str) -> Result<()> {
        let filename = format!("bundle_{name}");

        dump_data(
            dir,
            &format!("pi_{filename}.data"),
            &self.on_chain_proof.instances,
        );
        dump_data(
            dir,
            &format!("proof_{filename}.data"),
            &self.on_chain_proof.proof,
        );

        dump_vk(dir, &filename, &self.on_chain_proof.vk);

        dump_as_json(dir, &filename, &self)
    }

    // Recover a `Proof` which follows halo2 semantic of "proof" and "instance",
    // where "accumulators" are instance instead of proof, not like "onchain proof".
    pub fn proof_to_verify(self) -> Proof {
        // raw.proof is accumulator + proof
        assert!(self.on_chain_proof.proof.len() > ACC_BYTES);
        // raw.instances is PI
        assert_eq!(self.on_chain_proof.instances.len(), PI_BYTES);

        // instances = raw_proof[..12] (acc) + raw_instances (pi_data)
        // proof = raw_proof[12..]
        let mut instances = self.on_chain_proof.proof;
        let proof = instances.split_off(ACC_BYTES);
        instances.extend(self.on_chain_proof.instances);

        let vk = self.on_chain_proof.vk;
        let git_version = Some(short_git_version());

        Proof {
            proof,
            instances,
            vk,
            git_version,
        }
    }
}
