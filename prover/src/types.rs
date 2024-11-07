use aggregator::{BatchHeader, ChunkInfo, MAX_AGG_SNARKS};
use eth_types::{base64, l2_types::BlockTrace};
use serde::{Deserialize, Serialize};
use zkevm_circuits::evm_circuit::witness::Block;

use crate::{BatchProofV2, ChunkProofV2};

/// Alias for convenience.
pub type WitnessBlock = Block;

/// Helper type to deserialize JSON-encoded RPC result for [`BlockTrace`].
#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct BlockTraceJsonRpcResult {
    /// The value of the "result" key.
    pub result: BlockTrace,
}

/// Defines a proving task for chunk proof generation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChunkProvingTask {
    /// Optional chunk data encapsulated within the proving task.
    ///
    /// As part of a sanity check, the prover reconstructs the chunk data using the EVM execution
    /// traces from all blocks in the chunk and compares against the supplied chunk data.
    pub chunk_info: Option<ChunkInfo>,
    /// The EVM execution traces for all blocks in the chunk.
    pub block_traces: Vec<BlockTrace>,
}

impl ChunkProvingTask {
    /// Create a new chunk proving task given the chunk trace.
    pub fn new(block_traces: Vec<BlockTrace>) -> Self {
        Self {
            block_traces,
            chunk_info: None,
        }
    }

    /// Returns true if there are no block traces in the chunk.
    pub fn is_empty(&self) -> bool {
        self.block_traces.is_empty()
    }

    /// An identifier for the chunk. It is the block number of the first block in the chunk.
    ///
    /// This is used as a file descriptor to save to (load from) disk in order to avoid proof
    /// generation if the same proof/SNARK is already found on disk.
    pub fn identifier(&self) -> String {
        self.block_traces
            .first()
            .map_or(0, |trace: &BlockTrace| {
                trace
                    .header
                    .number
                    .expect("block number should be present")
                    .low_u64()
            })
            .to_string()
    }
}

/// Defines a proving task for batch proof generation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BatchProvingTask {
    /// Chunk proofs for the contiguous list of chunks within the batch.
    pub chunk_proofs: Vec<ChunkProofV2>,
    /// The [`BatchHeader`], as computed on-chain for this batch.
    ///
    /// Ref: https://github.com/scroll-tech/scroll-contracts/blob/2ac4f3f7e090d7127db4b13b3627cb3ce2d762bc/src/libraries/codec/BatchHeaderV3Codec.sol
    pub batch_header: BatchHeader<MAX_AGG_SNARKS>,
    /// The bytes encoding the batch data that will finally be published on-chain in the form of an
    /// EIP-4844 blob.
    #[serde(with = "base64")]
    pub blob_bytes: Vec<u8>,
}

impl BatchProvingTask {
    /// An identifier for the batch. It is the public input hash of the last chunk in the batch.
    ///
    /// This is used as a file descriptor to save to (load from) disk in order to avoid proof
    /// generation if the same proof/SNARK is already found on disk.
    pub fn identifier(&self) -> String {
        self.chunk_proofs
            .last()
            .unwrap()
            .inner
            .chunk_info()
            .public_input_hash()
            .to_low_u64_le()
            .to_string()
    }
}

/// Defines a proving task for bundle proof generation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BundleProvingTask {
    /// The [`BatchProofs`][BatchProof] for the contiguous list of batches to be bundled together.
    pub batch_proofs: Vec<BatchProofV2>,
}

impl BundleProvingTask {
    /// An identifier for the bundle. It is the batch hash of the last batch in the bundle.
    ///
    /// This is used as a file descriptor to save to (load from) disk in order to avoid proof
    /// generation if the same proof/SNARK is already found on disk.
    pub fn identifier(&self) -> String {
        self.batch_proofs
            .last()
            .unwrap()
            .inner
            .batch_hash
            .to_string()
    }
}
