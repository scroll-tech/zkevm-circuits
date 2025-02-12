use std::path::PathBuf;

use crate::{BatchProverError, ChunkProverError};

/// Represents error variants possibly encountered during the proof generation process.
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    /// Error occurred while doing i/o operations.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Error encountered while reading from or writing to files.
    #[error("error during read/write! path={path}, e={source}")]
    IoReadWrite {
        /// The path we tried to read from or write to.
        path: PathBuf,
        /// The source error.
        source: std::io::Error,
    },
    /// Error occurred while doing serde operations.
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    /// Error encountered during JSON serde.
    #[error("error during read/write json! path={path}, e={source}")]
    JsonReadWrite {
        /// The path of the file we tried to serialize/deserialize.
        path: PathBuf,
        /// The source error.
        source: serde_json::Error,
    },
    /// Error encountered while reading variable from the process environment.
    #[error("error while reading env var! key={key}, e={source}")]
    EnvVar {
        /// The key tried to be read.
        key: String,
        /// The source error.
        source: std::env::VarError,
    },
    /// Error propagated in the [`ChunkProver`][crate::ChunkProver] pipeline.
    #[error(transparent)]
    ChunkProverError(#[from] ChunkProverError),
    /// Error propagated from the [`BatchProver`][crate::BatchProver] pipeline.
    #[error(transparent)]
    BatchProverError(#[from] BatchProverError),
    /// Other errors.
    #[error("custom error: {0}")]
    Custom(String),
}
