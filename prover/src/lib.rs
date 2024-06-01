#![feature(lazy_cell)]

/// Meaning of each circuit:
///   inner: first layer EVM super circuit
///   layer1: compression circuit of "inner"
///   layer2: comppresion circuit of "layer1"
///   layer3: batch circuit. Proving many "layer2" circuits, plus blob/kzg handling.
///   layer4: compression circuit of "layer3". Final layer circuit currently.
pub mod aggregator;
pub mod common;
pub mod config;
pub mod consts;
pub mod inner;
pub mod io;
pub mod proof;
#[cfg(feature = "test")]
pub mod test;
pub mod types;
pub mod utils;
pub mod zkevm;

pub use aggregator::{check_chunk_hashes, BatchHash, MAX_AGG_SNARKS};
pub use common::{ChunkInfo, CompressionCircuit};
pub use eth_types::l2_types::BlockTrace;
pub use proof::{BatchProof, ChunkProof, EvmProof, Proof};
pub use snark_verifier_sdk::{CircuitExt, Snark};
pub use types::{BatchProvingTask, ChunkProvingTask, WitnessBlock};
