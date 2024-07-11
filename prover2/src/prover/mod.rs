use crate::{
    types::{ProverTypeBatch, ProverTypeBundle, ProverTypeChunk},
    Proof, ProverConfig, ProverError,
};

pub mod config;
pub mod params;

/// Convenience type for chunk prover.
pub type ChunkProver = Prover<ProverTypeChunk>;

/// Convenience type for batch prover.
pub type BatchProver = Prover<ProverTypeBatch>;

/// Convenience type for bundle prover.
pub type BundleProver = Prover<ProverTypeBundle>;

/// A generic prover that is capable of generating proofs for given tasks.
pub struct Prover<T> {
    /// Config for the prover.
    pub config: ProverConfig<T>,
}

impl<T> Prover<T> {
    pub fn new(config: ProverConfig<T>) -> Self {
        Self { config }
    }
}

impl<T> Prover<T> {
    pub fn gen_proof() -> Result<Proof, ProverError> {
        unimplemented!()
    }
}
