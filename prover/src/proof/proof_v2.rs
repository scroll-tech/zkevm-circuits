use std::path::{Path, PathBuf};

use aggregator::ChunkInfo;
use eth_types::{base64, H256};
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::ProvingKey,
};
use serde_derive::{Deserialize, Serialize};
use snark_verifier::Protocol;
use snark_verifier_sdk::Snark;

use crate::{
    deserialize_fr, read_json_deep, serialize_vk, short_git_version, write, write_json,
    zkevm::RowUsage, BatchProverError, ChunkKind, ProverError,
};

use super::serialize_instances;

/// Proof generated at certain checkpoints in the proof generation pipeline.
///
/// Variants of [`ProofV2`] are [`ChunkProofV2`], [`BatchProofV2`] and [`BundleProofV2`], that are
/// the output of proof generation at [`Layer-2`][crate::LayerId::Layer2], [`Layer-4`][crate::LayerId::Layer4]
/// and [`Layer-6`][crate::LayerId::Layer6] respectively.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofV2<Inner: Proof> {
    /// The inner data that differs between chunk proofs, batch proofs and bundle proofs.
    #[serde(flatten)]
    pub inner: Inner,
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

impl<Inner: Proof + serde::de::DeserializeOwned> TryFrom<&ProofV2<Inner>> for Snark {
    type Error = ProverError;

    fn try_from(value: &ProofV2<Inner>) -> Result<Self, Self::Error> {
        let protocol = value
            .inner
            .protocol()
            .ok_or(ProverError::Custom(String::from(
                "protocol either not found or cannot be deserialized successfully",
            )))?;

        let instances = value.deserialize_instances();

        let proof = value.proof.to_vec();

        Ok(Self {
            protocol,
            proof,
            instances,
        })
    }
}

impl<Inner: Proof + serde::de::DeserializeOwned> ProofV2<Inner> {
    /// Construct a new proof given the inner metadata, proving key and the
    /// [`Snark`][snark_verifier_sdk::Snark].
    pub fn new(
        snark: Snark,
        proving_key: Option<&ProvingKey<G1Affine>>,
        inner: Inner,
    ) -> Result<Self, ProverError> {
        let instances = serialize_instances(&snark.instances);
        let vk = proving_key.map_or_else(Vec::new, |pk| serialize_vk(pk.get_vk()));

        Ok(Self {
            inner,
            proof: snark.proof,
            instances,
            vk,
            git_version: short_git_version(),
        })
    }

    /// Read and deserialize the proof.
    pub fn from_json<P: AsRef<Path>>(dir: P, suffix: &str) -> Result<Self, ProverError> {
        let path = Self::path_proof(dir, suffix);
        read_json_deep(path)
    }

    /// Serialize the proof and other peripheral data, before dumping in the provided directory.
    pub fn dump<P: AsRef<Path>>(&self, dir: P, suffix: &str) -> Result<(), ProverError> {
        // Dump the verifying key.
        write(Self::path_vk(&dir, suffix), &self.vk)?;

        // Dump the proof itself.
        write_json(Self::path_proof(&dir, suffix), &self)?;

        // Dump any other data for the inner data.
        self.inner.dump(&dir, suffix)?;

        Ok(())
    }

    /// Deserialize public values in the native scalar field.
    fn deserialize_instances(&self) -> Vec<Vec<Fr>> {
        vec![self
            .instances
            .chunks(32)
            .map(|bytes| deserialize_fr(bytes.iter().rev().cloned().collect()))
            .collect::<Vec<_>>()]
    }

    /// Path to the JSON-encoded proof in the directory.
    fn path_proof<P: AsRef<Path>>(dir: P, suffix: &str) -> PathBuf {
        Inner::path_proof(dir, suffix)
    }

    /// Path to the encoded [`VerifyingKey`][halo2_proofs::plonk::VerifyingKey] in the directory.
    fn path_vk<P: AsRef<Path>>(dir: P, suffix: &str) -> PathBuf {
        Inner::path_vk(dir, suffix)
    }
}

pub trait Proof: Clone + std::fmt::Debug + serde::Serialize {
    /// Name of the proof layer.
    const NAME: &'static str;

    /// <dir>/proof_{NAME}_{suffix}.json
    fn path_proof<P: AsRef<Path>>(dir: P, suffix: &str) -> PathBuf {
        dir.as_ref()
            .join(format!("proof_{}_{}.json", Self::NAME, suffix))
    }

    /// <dir>/vk_{NAME}_{suffix}.vkey
    fn path_vk<P: AsRef<Path>>(dir: P, suffix: &str) -> PathBuf {
        dir.as_ref()
            .join(format!("vk_{}_{}.vkey", Self::NAME, suffix))
    }

    /// <dir>/protocol_{NAME}_{suffix}.protocol
    fn path_protocol<P: AsRef<Path>>(dir: P, suffix: &str) -> PathBuf {
        dir.as_ref()
            .join(format!("protocol_{}_{}.protocol", Self::NAME, suffix,))
    }

    /// Returns the SNARK protocol, if any in the metadata.
    fn protocol(&self) -> Option<Protocol<G1Affine>>;

    /// Dump relevant fields from the proof metadata in the provided directory.
    fn dump<P: AsRef<Path>>(&self, dir: P, suffix: &str) -> Result<(), ProverError>;
}

/// Alias for convenience.
pub type ChunkProofV2 = ProofV2<ChunkProofV2Metadata>;

/// Alias for convenience.
pub type BatchProofV2 = ProofV2<BatchProofV2Metadata>;

/// Alias for convenience.
pub type BundleProofV2 = ProofV2<BundleProofV2Metadata>;

/// The number of scalar field elements used to encode the KZG accumulator.
///
/// The accumulator is essentially an `(lhs, rhs)` pair of [`G1Affine`] points, where each
/// `G1Affine` point comprises of 2 base field elements `(x, y)`. But since each base field
/// element is split into 3 limbs each, where each limb is our native scalar [`Fr`], in total we
/// have 12 scalar field elements to represent this accumulator.
const ACCUMULATOR_LEN: usize = 12;

/// Each scalar field [`Fr`] element is encoded using 32 bytes.
const ACCUMULATOR_BYTES: usize = ACCUMULATOR_LEN * 32;

/// The public input (excluding the accumulator) for the outermost
/// [`Layer-6`][crate::LayerId::Layer6] circuit is basically the public input carried forward from
/// the `Layer-5` [`RecursionCircuit`][aggregator::RecursionCircuit].
///
/// They are the following:
/// - Fr: Preprocessed Digest
/// - Fr: Recursion Round
/// - (Fr, Fr): Pre State Root (finalized)
/// - (Fr, Fr): Pre Batch Hash (finalized)
/// - (Fr, Fr): Post State Root (pending finalization)
/// - (Fr, Fr): Post Batch Hash (pending finalization)
/// - Fr: Chain ID
/// - (Fr, Fr): Post Withdraw Root (pending finalization)
///
/// In total these are 13 scalar field elements.
const PUBLIC_INPUT_LEN: usize = 13;

/// Each scalar field [`Fr`] element is encoded using 32 bytes.
const PUBLIC_INPUT_BYTES: usize = PUBLIC_INPUT_LEN * 32;

impl BundleProofV2 {
    /// Construct a new proof given raw proof and instance values. Generally to be used in the case
    /// of final EVM proof using the [`gen_evm_verifier`][snark_verifier_sdk::gen_evm_verifier]
    /// method.
    pub fn new_from_raw(proof: &[u8], instances: &[u8], vk: &[u8]) -> Result<Self, ProverError> {
        // Sanity check on the number of public input bytes.
        let expected_len = ACCUMULATOR_BYTES + PUBLIC_INPUT_BYTES;
        let got_len = instances.len();
        if got_len != expected_len {
            return Err(BatchProverError::PublicInputsMismatch(expected_len, got_len).into());
        }

        Ok(Self {
            inner: BundleProofV2Metadata,
            proof: proof.to_vec(),
            instances: instances.to_vec(),
            vk: vk.to_vec(),
            git_version: short_git_version(),
        })
    }

    /// Encode the calldata for the proof verification transaction to be made on-chain.
    ///
    /// [ public_input_bytes | accumulator_bytes | proof ]
    pub fn calldata(&self) -> Vec<u8> {
        std::iter::empty()
            .chain(self.instances.iter())
            .chain(self.proof.iter())
            .cloned()
            .collect::<Vec<_>>()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkProofV2Metadata {
    /// The [`Protocol`][snark_verifier::Protocol] for the SNARK construction for the chunk proof.
    #[serde(with = "base64")]
    protocol: Vec<u8>,
    /// The chunk proof can be for either the halo2 or sp1 routes.
    chunk_kind: ChunkKind,
    /// The EVM execution traces as a result of executing all txs in the chunk.
    chunk_info: ChunkInfo,
    /// Optional [Circuit-Capacity Checker][ccc] row usage statistics from the halo2-route.
    ///
    /// Is `None` for the sp1-route.
    ///
    /// [ccc]: crate::zkevm::CircuitCapacityChecker
    row_usage: Option<RowUsage>,
}

impl ChunkProofV2Metadata {
    /// Construct new chunk proof metadata.
    pub fn new(
        snark: &Snark,
        chunk_kind: ChunkKind,
        chunk_info: ChunkInfo,
        row_usage: Option<RowUsage>,
    ) -> Result<Self, ProverError> {
        let protocol = serde_json::to_vec(&snark.protocol)?;

        Ok(Self {
            protocol,
            chunk_kind,
            chunk_info,
            row_usage,
        })
    }
    /// Get the chunk info embedded
    pub fn chunk_info(&self) -> &ChunkInfo {
        &self.chunk_info
    }
    /// Get the chunk kind
    pub fn chunk_kind(&self) -> ChunkKind {
        self.chunk_kind
    }
    /// Get the chunk protocol
    pub fn protocol(&self) -> &Vec<u8> {
        &self.protocol
    }
}

impl Proof for ChunkProofV2Metadata {
    const NAME: &'static str = "chunk";

    fn protocol(&self) -> Option<Protocol<G1Affine>> {
        serde_json::from_slice(&self.protocol).ok()
    }

    fn dump<P: AsRef<Path>>(&self, dir: P, suffix: &str) -> Result<(), ProverError> {
        write(Self::path_protocol(&dir, suffix), &self.protocol)?;

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchProofV2Metadata {
    /// The [`Protocol`][snark_verifier::Protocol] for the SNARK construction for the chunk proof.
    #[serde(with = "base64")]
    protocol: Vec<u8>,
    /// The hash of [`BatchHeader`][aggregator::BatchHeader] of the batch.
    pub batch_hash: H256,
}

impl BatchProofV2Metadata {
    /// Create new batch proof metadata.
    pub fn new(snark: &Snark, batch_hash: H256) -> Result<Self, ProverError> {
        let protocol = serde_json::to_vec(&snark.protocol)?;

        Ok(Self {
            protocol,
            batch_hash,
        })
    }
}

impl Proof for BatchProofV2Metadata {
    const NAME: &'static str = "batch";

    fn protocol(&self) -> Option<Protocol<G1Affine>> {
        serde_json::from_slice(&self.protocol).ok()
    }

    fn dump<P: AsRef<Path>>(&self, dir: P, suffix: &str) -> Result<(), ProverError> {
        write(Self::path_protocol(&dir, suffix), &self.protocol)?;

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BundleProofV2Metadata;

impl Proof for BundleProofV2Metadata {
    const NAME: &'static str = "bundle";

    fn protocol(&self) -> Option<Protocol<G1Affine>> {
        None
    }

    fn dump<P: AsRef<Path>>(&self, _dir: P, _suffix: &str) -> Result<(), ProverError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;

    use crate::{deploy_and_call, read, read_json, BundleProofV2, EvmProof};

    #[test]
    fn bundle_proof_backwards_compat() -> anyhow::Result<()> {
        // Read [`EvmProof`] from test data.
        let evm_proof = read_json::<_, EvmProof>("test_data/evm-proof.json")?;

        // Build bundle proofs.
        let bundle_proof_v2 = BundleProofV2::new_from_raw(
            &evm_proof.proof.proof,
            &evm_proof.proof.instances,
            &evm_proof.proof.vk,
        )?;
        let bundle_proof = crate::BundleProof::from(evm_proof.proof);

        assert_eq!(bundle_proof.calldata(), bundle_proof_v2.calldata());

        Ok(())
    }

    #[test]
    fn verify_bundle_proof() -> anyhow::Result<()> {
        // Create a tmp test directory.
        let dir = TempDir::new("proof_v2")?;

        // Read [`EvmProof`] from test data.
        let evm_proof = read_json::<_, EvmProof>("test_data/evm-proof.json")?;
        let verifier = read("test_data/evm-verifier.bin")?;

        // Build bundle proof v2.
        let bundle_proof = BundleProofV2::new_from_raw(
            &evm_proof.proof.proof,
            &evm_proof.proof.instances,
            &evm_proof.proof.vk,
        )?;

        // Dump the bundle proof v2.
        bundle_proof.dump(&dir, "suffix")?;

        // Verify the bundle proof v2 with EVM verifier contract.
        assert!(deploy_and_call(verifier, bundle_proof.calldata()).is_ok());

        Ok(dir.close()?)
    }
}
