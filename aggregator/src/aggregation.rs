/// Config to constrain batch data (decoded blob data)
pub mod batch_data;
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

pub use batch_data::BatchData;
pub(crate) use batch_data::BatchDataConfig;
pub use decoder::{decode_bytes, encode_bytes};
pub(crate) use decoder::{witgen, DecoderConfig, DecoderConfigArgs};
pub(crate) use rlc::{RlcConfig, POWS_OF_256};

pub use circuit::BatchCircuit;
pub use config::BatchCircuitConfig;
