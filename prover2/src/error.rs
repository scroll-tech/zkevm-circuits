use thiserror::Error;

/// Represents error variants possibly encountered during the proof generation process.
#[derive(Debug, Error)]
pub enum ProverError {
    /// Error encountered while doing I/O operations.
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Error encountered during serialization/deserialization of JSON.
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
}
