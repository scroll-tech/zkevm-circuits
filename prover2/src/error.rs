use std::path::PathBuf;

use thiserror::Error;

use crate::ProofLayer;

/// Represents error variants possibly encountered during the proof generation process.
#[derive(Debug, Error)]
pub enum ProverError {
    /// Error occurred while doing other I/O operations.
    #[error(transparent)]
    OtherIo(#[from] std::io::Error),
    /// Error encountered while reading from or writing to files.
    #[error("an error occurred while reading/writing {path}: {source}")]
    IoReadWrite {
        /// The path we tried to read from or write to.
        path: PathBuf,
        /// The source error.
        source: std::io::Error,
    },
    /// Error encountered during serialization/deserialization of JSON.
    #[error("an error occurred while reading/writing json {path}: {source}")]
    ReadWriteJson {
        /// The path of the file we tried to serialize/deserialize.
        path: PathBuf,
        /// The source error.
        source: serde_json::Error,
    },
    /// Error encountered while reading variable from the process environment.
    #[error("an error occurred while reading variable from the environment {key}: {source}")]
    EnvVar {
        /// The key tried to be read.
        key: String,
        /// The source error.
        source: std::env::VarError,
    },
    /// Error encountered while parsing a string.
    #[error("an error occurred while parsing string {src}: {err}")]
    Parse {
        /// Source string that we tried to parse.
        src: String,
        /// Parsing error.
        err: String,
    },
    /// Error that indicates the KZG setup parameters for specified layer are missing from prover
    /// config.
    #[error("prover {0} missing KZG setup params for {1:?}")]
    MissingKzgParams(String, ProofLayer),
    /// Custom error.
    #[error("custom error: {0}")]
    Custom(String),
}
