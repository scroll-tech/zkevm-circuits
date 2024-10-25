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
