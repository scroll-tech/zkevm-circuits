use eth_types::base64;
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{Circuit, ProvingKey, VerifyingKey},
    SerdeFormat,
};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::Snark;

use crate::{
    util::{deserialize_be, serialize_be, GIT_VERSION},
    ProofLayer, ProverError,
};

/// Describes an output from a [`Prover`]'s proof generation process when given a [`ProvingTask`].
#[derive(Serialize, Deserialize)]
pub struct Proof<Aux> {
    /// Version of the source code (git describe --abbrev=8) used for proof generation.
    git_version: String,
    /// The proof layer.
    layer: ProofLayer,
    /// Verification key for this SNARK proof.
    #[serde(with = "base64")]
    vk: Vec<u8>,
    /// The public instances (flattened bytes) to the SNARK.
    #[serde(with = "base64")]
    instances: Vec<u8>,
    /// The protocol computed for SNARK.
    #[serde(with = "base64")]
    protocol: Vec<u8>,
    /// The inner proof.
    #[serde(with = "base64")]
    proof: Vec<u8>,
    /// Auxiliary data to attach with the proof. This data would generally be required by the next
    /// layer's proof generation process.
    #[serde(flatten)]
    aux: Aux,
}

impl<Aux> Proof<Aux> {
    /// Construct a new [`Proof`] given the SNARK for the proof layer and some auxiliary data.
    pub fn new_from_snark(
        layer: ProofLayer,
        snark: Snark,
        pk: &ProvingKey<G1Affine>,
        aux: Aux,
    ) -> Result<Self, ProverError> {
        let git_version = GIT_VERSION.to_string();
        let vk = pk.get_vk().to_bytes(SerdeFormat::Processed);
        let protocol = serde_json::to_vec(&snark.protocol)?;
        let instances = snark.instances[0]
            .iter()
            .flat_map(serialize_be)
            .collect::<Vec<_>>();
        let proof = snark.proof;

        Ok(Self {
            git_version,
            layer,
            vk,
            protocol,
            instances,
            proof,
            aux,
        })
    }

    /// Construct a new [`Proof`] given the raw proof and instances for an EVM-verifiable proof.
    pub fn new_from_raw(
        layer: ProofLayer,
        instances: &[Fr],
        proof: &[u8],
        pk: &ProvingKey<G1Affine>,
        aux: Aux,
    ) -> Self {
        let git_version = GIT_VERSION.to_string();
        let vk = pk.get_vk().to_bytes(SerdeFormat::Processed);
        let instances = instances.iter().flat_map(serialize_be).collect::<Vec<_>>();

        Self {
            git_version,
            layer,
            vk,
            protocol: vec![],
            instances,
            proof: proof.to_vec(),
            aux,
        }
    }
}

impl<Aux> Proof<Aux> {
    /// Deserialize and return the verifying key.
    pub fn verifying_key<C: Circuit<Fr>>(&self) -> Result<VerifyingKey<G1Affine>, ProverError> {
        Ok(VerifyingKey::from_bytes::<C>(
            &self.vk,
            SerdeFormat::Processed,
        )?)
    }
}

impl<Aux> TryInto<Snark> for Proof<Aux> {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<Snark, Self::Error> {
        let protocol = serde_json::from_slice(&self.protocol)?;
        let instances = self
            .instances
            .chunks_exact(32)
            .map(deserialize_be)
            .collect::<Vec<_>>();
        let proof = self.proof;

        Ok(Snark {
            protocol,
            instances: vec![instances],
            proof,
        })
    }
}
