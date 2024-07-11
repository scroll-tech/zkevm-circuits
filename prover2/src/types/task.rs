use serde::{de::DeserializeOwned, ser::Serialize};

/// Describes the behaviour to be supported by a type that can be used as an input (or a task) to
/// instruct a [`Prover`] to generate a proof.
trait ProvingTask: Serialize + DeserializeOwned {
    /// An identifier for the proving task.
    fn id(&self) -> String;
}
