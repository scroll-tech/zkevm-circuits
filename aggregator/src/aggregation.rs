/// Config to evaluate blob polynomial at a random challenge.
mod barycentric;
/// Config to constrain batch data (decoded blob data)
mod batch_data;
/// Config to constrain blob data (encoded batch data)
mod blob_data;
/// Circuit implementation of aggregation circuit.
mod circuit;
/// Config for aggregation circuit
mod config;
/// Config for decoding zstd-encoded data.
mod decoder;
/// config for RLC circuit
mod rlc;
/// Utility module
mod util;

pub(crate) use barycentric::{
    interpolate, AssignedBarycentricEvaluationConfig, BarycentricEvaluationConfig, BLS_MODULUS,
};
pub(crate) use batch_data::BatchDataConfig;
pub(crate) use blob_data::BlobDataConfig;
pub(crate) use decoder::{witgen, DecoderConfig, DecoderConfigArgs};
pub(crate) use rlc::RlcConfig;

pub use circuit::BatchCircuit;
pub use config::BatchCircuitConfig;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use snark_verifier::Protocol;

/// Alias for a list of G1 points.
pub type PreprocessedPolyCommits = Vec<G1Affine>;
/// Alias for the transcript's initial state.
pub type TranscriptInitState = Fr;

/// Alias for the fixed part of the protocol which consists of the commitments to the preprocessed
/// polynomials and the initial state of the transcript.
#[derive(Clone)]
pub struct FixedProtocol {
    /// The commitments to the preprocessed polynomials.
    pub preprocessed: PreprocessedPolyCommits,
    /// The initial state of the transcript.
    pub init_state: TranscriptInitState,
}

impl From<Protocol<G1Affine>> for FixedProtocol {
    fn from(protocol: Protocol<G1Affine>) -> Self {
        Self {
            preprocessed: protocol.preprocessed,
            init_state: protocol
                .transcript_initial_state
                .expect("protocol transcript init state None"),
        }
    }
}

impl From<&Protocol<G1Affine>> for FixedProtocol {
    fn from(protocol: &Protocol<G1Affine>) -> Self {
        Self {
            preprocessed: protocol.preprocessed.clone(),
            init_state: protocol
                .transcript_initial_state
                .clone()
                .expect("protocol transcript init state None"),
        }
    }
}
