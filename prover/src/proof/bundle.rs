use serde_derive::{Deserialize, Serialize};

use crate::{utils::short_git_version, Proof};

// 3 limbs per field element, 4 field elements
const ACC_LEN: usize = 12;

// - chain id
// - (hi, lo) finalised state root
// - (hi, lo) finalised batch hash
// - (hi, lo) pending state root
// - (hi, lo) pending withdraw root
// - (hi, lo) pending batch hash
const PI_LEN: usize = 11;

const ACC_BYTES: usize = ACC_LEN * 32;
const PI_BYTES: usize = PI_LEN * 32;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BundleProof {
    #[serde(flatten)]
    raw: Proof,
}

impl BundleProof {
    /// Returns the calldata given to YUL verifier.
    /// Format: Accumulator(12x32bytes) || PI(11x32bytes) || Proof
    pub fn calldata(self) -> Vec<u8> {
        let proof = self.proof_to_verify();

        // calldata = instances + proof
        let mut calldata = proof.instances;
        calldata.extend(proof.proof);

        calldata
    }

    // Recover a `Proof` which follows halo2 semantic of "proof" and "instance",
    // where "accumulators" are instance instead of proof, not like "onchain proof".
    pub fn proof_to_verify(self) -> Proof {
        // raw.proof is accumulator + proof
        assert!(self.raw.proof.len() > ACC_BYTES);
        // raw.instances is PI
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
}
