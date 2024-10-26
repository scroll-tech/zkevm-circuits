/// Various errors potentially encountered during proof generation.
#[derive(thiserror::Error, Debug)]
pub enum ChunkProverError {
    /// Indicates that the halo2-based [`SuperCircuit`][super_circ] does not have sufficient
    /// capacity to populate block traces from all the blocks in the chunk. The error encapsulates
    /// the [`RowUsage`][row_usage] observed from populating the chunk.
    ///
    /// [super_circ]: zkevm_circuits::super_circuit::SuperCircuit
    /// [row_usage]: crate::zkevm::RowUsage
    #[error("halo2 circuit-capacity exceeded")]
    CircuitCapacityOverflow(crate::zkevm::RowUsage),
    /// Represents an error propagated from the [`bus_mapping`] crate.
    #[error(transparent)]
    CircuitBuilder(#[from] bus_mapping::Error),
    /// Represents the [`halo2 error`][halo2_error] being propagated.
    ///
    /// [halo2_error]: halo2_proofs::plonk::Error
    #[error(transparent)]
    Halo2(#[from] halo2_proofs::plonk::Error),
    /// Error indicating that the verifying key found post proof generation does not match the
    /// expected verifying key.
    #[error("verifying key mismatch: found={0}, expected={1}")]
    VerifyingKeyMismatch(String, String),
    /// Error indicating that no verifying key was found post proof generation.
    #[error("verifying key not found: expected={0}")]
    VerifyingKeyNotFound(String),
    /// Error indicating that proof verification failed.
    #[error("proof verification failure")]
    Verification,
    /// Represents all other custom errors.
    #[error("custom error: {0}")]
    Custom(String),
}

impl From<String> for ChunkProverError {
    fn from(value: String) -> Self {
        Self::Custom(value)
    }
}
