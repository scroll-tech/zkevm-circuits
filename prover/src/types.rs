use aggregator::ChunkInfo;
use eth_types::l2_types::BlockTrace;
use serde::{Deserialize, Serialize};
use zkevm_circuits::evm_circuit::witness::Block;

pub type WitnessBlock = Block;

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct BlockTraceJsonRpcResult {
    pub result: BlockTrace,
}
pub use eth_types::base64;

use crate::ChunkProof;

#[derive(Debug, Deserialize, Serialize)]
pub struct ChunkProvingTask {
    /// Prover needs to check `chunk_info` is consistent with block traces
    pub chunk_info: ChunkInfo,
    pub block_traces: Vec<BlockTrace>,
}

impl ChunkProvingTask {
    pub fn is_empty(&self) -> bool {
        self.block_traces.is_empty()
    }
    /// Used for cache/load proof from disk
    pub fn identifier(&self) -> String {
        self.block_traces
            .first()
            .map_or(0, |trace: &BlockTrace| {
                trace.header.number.expect("block num").low_u64()
            })
            .to_string()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BatchProvingTask {
    pub chunk_proofs: Vec<ChunkProof>,
}

impl BatchProvingTask {
    /// Used for cache/load proof from disk
    pub fn identifier(&self) -> String {
        self.chunk_proofs
            .last()
            .unwrap()
            .chunk_info
            .public_input_hash()
            .to_low_u64_le()
            .to_string()
    }
}
