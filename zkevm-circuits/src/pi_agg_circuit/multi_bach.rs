//! This module implements `MultiBatch` related data types.
//! A multi_batch is a list of chunk.

use super::chunk::ChunkPublicData;
use ethers_core::utils::keccak256;

#[derive(Default, Debug, Clone)]
/// MultiBatchPublicData is a list of ChunkPublicData, each corresponds to a chunk
/// with max_txn transactions.
pub struct MultiBatchPublicData {
    pub(crate) public_data_vec: Vec<ChunkPublicData>,
    pub(crate) max_txs: usize,
}

impl MultiBatchPublicData {
    /// Compute the raw_data_hash_bytes bytes from the verifier's perspective.
    pub(crate) fn raw_data_hash_bytes(&self) -> Vec<u8> {
        let mut to_be_hashed = vec![];

        self.public_data_vec.iter().for_each(|chunk_public_data| {
            to_be_hashed
                .extend_from_slice(
                    // extract all the data from each chunk
                    chunk_public_data.raw_data_hash_bytes().as_ref(),
                )
                .into()
        });
        // data hash is the keccak hash of concatenation of all data fields
        keccak256::<&[u8]>(to_be_hashed.as_ref()).into()
    }

    /// Compute the raw_public_inputs_bytes bytes from the verifier's perspective.
    pub(crate) fn raw_public_input_bytes(&self) -> Vec<u8> {
        let mut to_be_hashed = vec![];
        self.public_data_vec.iter().for_each(|chunk_public_data| {
            to_be_hashed
                .extend_from_slice(
                    // extract all the data from each chunk
                    chunk_public_data.raw_public_input_bytes().as_ref(),
                )
                .into()
        });
        keccak256::<&[u8]>(to_be_hashed.as_ref()).into()
    }
}
