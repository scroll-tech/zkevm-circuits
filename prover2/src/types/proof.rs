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

/// Describes an output from a [`Prover`][prover]'s proof generation process when
/// given a [`ProvingTask`][proving_task].
///
/// [prover]: crate::prover::Prover
/// [proving_task]: crate::ProvingTask
#[derive(Serialize, Deserialize, Debug)]
pub struct Proof<Aux, const EVM_VERIFY: bool> {
    /// Version of the source code (git describe --abbrev=8) used for proof generation.
    pub git_version: String,
    /// The proof layer.
    pub layer: ProofLayer,
    /// The raw [`VerificationKey`][vk] for this [`SNARK`][snark] proof.
    ///
    /// [vk]: halo2_proofs::plonk::VerifyingKey
    /// [snark]: snark_verifier_sdk::Snark
    #[serde(with = "base64")]
    pub vk: Vec<u8>,
    /// The public instances (flattened bytes) to the SNARK.
    #[serde(with = "base64")]
    pub instances: Vec<u8>,
    /// The protocol computed for SNARK.
    #[serde(with = "base64")]
    pub protocol: Vec<u8>,
    /// The inner proof.
    #[serde(with = "base64")]
    pub proof: Vec<u8>,
    /// Auxiliary data to attach with the proof. This data would generally be required
    /// by the next layer's proof generation process.
    #[serde(flatten)]
    pub aux: Aux,
}

impl<Aux, const EVM_VERIFY: bool> Proof<Aux, EVM_VERIFY> {
    /// Construct a new proof given the SNARK for the proof layer and some auxiliary data.
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

    /// Construct a new proof given the raw proof and instances for an EVM-verifiable proof.
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

impl<Aux, const EVM_VERIFY: bool> Proof<Aux, EVM_VERIFY> {
    /// Deserialize and return the verifying key.
    pub fn verifying_key<C: Circuit<Fr>>(&self) -> Result<VerifyingKey<G1Affine>, ProverError> {
        Ok(VerifyingKey::from_bytes::<C>(
            &self.vk,
            SerdeFormat::Processed,
        )?)
    }
}

impl<Aux, const EVM_VERIFY: bool> TryInto<Snark> for Proof<Aux, EVM_VERIFY> {
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
