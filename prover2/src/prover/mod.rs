use aggregator::MAX_AGG_SNARKS;
use tracing::instrument;

use crate::{
    types::{ProverType, ProverTypeBatch, ProverTypeBundle, ProverTypeChunk},
    Proof, ProverConfig, ProverError,
};

pub mod config;
pub mod params;

/// Convenience type for chunk prover.
pub type ChunkProver = Prover<ProverTypeChunk>;

/// Convenience type for batch prover.
pub type BatchProver = Prover<ProverTypeBatch<MAX_AGG_SNARKS>>;

/// Convenience type for bundle prover.
pub type BundleProver = Prover<ProverTypeBundle>;

/// A generic prover that is capable of generating proofs for given tasks.
#[derive(Debug)]
pub struct Prover<T> {
    /// Config for the prover.
    pub config: ProverConfig<T>,
}

impl<T> Prover<T> {
    /// Construct a new prover.
    pub fn new(config: ProverConfig<T>) -> Self {
        Self { config }
    }
}

impl<Type: ProverType> Prover<Type> {
    /// Generate a proof for the given task.
    #[instrument(name = "Prover::gen_proof", skip(self))]
    pub fn gen_proof(&mut self, task: Type::Task) -> Result<Proof, ProverError> {
        // generate SNARKs for the different layers.
        //
        // - re-use SNARK if cache hit and early return
        // - gen SNARK
        // - write SNARK to cache
        let _base_layer = Type::base_layer()?;
        let _compression_layers = Type::compression_layers();

        // dump outermost SNARK proof to cache.

        unimplemented!()
    }
}
