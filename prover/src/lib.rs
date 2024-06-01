#![feature(lazy_cell)]

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
