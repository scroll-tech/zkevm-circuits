use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Describes the behaviour to be supported by a [`ProverType`][prover_type] that
/// can be used as an input (or a task) to instruct a [`Prover`][prover] to generate
/// a proof.
///
/// [prover_type]: crate::types::ProverType
/// [prover]: crate::prover::Prover
pub trait ProvingTask: Serialize + DeserializeOwned + std::fmt::Debug {
    /// A unique identifier for the proving task.
    fn id(&self) -> String;
}

/// A [`ProvingTask`] used to build the base circuit, i.e. [`SuperCircuit`][super_circuit],
/// for the [`ChunkProver`][chunk_prover].
///
/// [super_circuit]: zkevm_circuits::super_circuit::SuperCircuit
/// [chunk_prover]: crate::types::ProverTypeChunk
#[derive(Debug, Serialize, Deserialize)]
pub struct ChunkProvingTask;

/// A [`ProvingTask`] used to build the base circuit, i.e. [`BatchCircuit`][batch_circuit],
/// for the [`BatchProver`][batch_prover].
///
/// [batch_circuit]: aggregator::BatchCircuit
/// [batch_prover]: crate::types::ProverTypeBatch
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchProvingTask<const N_SNARKS: usize>;

/// A [`ProvingTask`] used to build the base circuit, i.e. [`RecursionCircuit`][recursion_circuit],
/// for the [`BundleProver`][bundle_prover].
///
/// [recursion_circuit]: aggregator::RecursionCircuit
/// [bundle_prover]: crate::types::ProverTypeBundle
#[derive(Debug, Serialize, Deserialize)]
pub struct BundleProvingTask;

impl ProvingTask for ChunkProvingTask {
    fn id(&self) -> String {
        "chunk".into()
    }
}

impl<const N_SNARKS: usize> ProvingTask for BatchProvingTask<N_SNARKS> {
    fn id(&self) -> String {
        "batch".into()
    }
}

impl ProvingTask for BundleProvingTask {
    fn id(&self) -> String {
        "bundle".into()
    }
}
