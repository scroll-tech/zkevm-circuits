use crate::{Proof, ProverConfig, ProverError};

pub mod config;
pub mod params;

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
