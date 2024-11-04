/// Errors encountered in the proof generation pipeline for batch and bundle proving.
#[derive(thiserror::Error, Debug)]
pub enum BatchProverError {
    /// Represents a mismatch in the verifying key at the specified proof layer.
    #[error("verifying key mismatch: layer={0}, expected={1}, found={2}")]
    VerifyingKeyMismatch(crate::config::LayerId, String, String),
    /// Verifying key for the specified layer was not found in the prover.
    #[error("verifying key not found: layer={0}, expected={1}")]
    VerifyingKeyNotFound(crate::config::LayerId, String),
    /// Sanity check failure indicating that the [`Snark`][snark_verifier_sdk::Snark]
    /// [`protocol`][snark_verifier::Protocol] did not match the expected protocols.
    #[error("SNARK protocol mismatch: index={0}, expected={1}, found={2}")]
    ChunkProtocolMismatch(usize, String, String),
    /// Indicates that after generating an EVM verifier contract, the proof itself could not be
    /// verified successfully, implying that this sanity check failed.
    #[error("EVM verifier contract could not verify proof")]
    SanityEVMVerifier,
    /// Error indicating that the verification of batch proof failed.
    #[error("proof verification failure")]
    Verification,
    /// Error indicating that the verifier contract's deployment code is not found.
    #[error("EVM verifier deployment code not found!")]
    VerifierCodeMissing,
    /// Error indicating that in the final [`BundleProof`][crate::BundleProofV2] the number of
    /// instances found does not match the number of instances expected.
    #[error("number of instances in bundle proof mismatch! expected={0}, got={1}")]
    PublicInputsMismatch(usize, usize),
    /// This variant represents other errors.
    #[error("custom: {0}")]
    Custom(String),
}

impl From<String> for BatchProverError {
    fn from(value: String) -> Self {
        Self::Custom(value)
    }
}

impl From<anyhow::Error> for BatchProverError {
    fn from(value: anyhow::Error) -> Self {
        Self::Custom(value.to_string())
    }
}
