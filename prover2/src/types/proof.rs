use serde::{Deserialize, Serialize};

use super::layer::ProofLayer;

/// Describes an output from a [`Prover`]'s proof generation process when given a [`ProvingTask`].
#[derive(Serialize, Deserialize)]
pub struct Proof {
    /// The proof layer.
    layer: ProofLayer,
}
