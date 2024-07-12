use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Describes the behaviour to be supported by a type that can be used as an input (or a task) to
/// instruct a [`Prover`] to generate a proof.
pub trait ProvingTask: Serialize + DeserializeOwned + std::fmt::Debug {
    /// An identifier for the proving task.
    fn id(&self) -> String;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChunkProvingTask;

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchProvingTask<const N_SNARKS: usize>;

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
