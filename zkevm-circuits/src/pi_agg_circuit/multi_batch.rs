//! This module implements `MultiBatch` related data types.
//! A multi_batch is a list of chunk.

use super::chunk::ChunkPublicData;

use eth_types::H256;
use ethers_core::utils::keccak256;

#[derive(Default, Debug, Clone)]
/// MultiBatchPublicData is a list of ChunkPublicData, each corresponds to a chunk
/// with max_txn transactions.
pub struct MultiBatchPublicData<const MAX_TXS: usize> {
    pub(crate) public_data_chunks: Vec<ChunkPublicData<MAX_TXS>>,
}

impl<const MAX_TXS: usize> MultiBatchPublicData<MAX_TXS> {
    /// Compute the raw_data_hash_bytes bytes from the verifier's perspective.
    pub(crate) fn raw_data_hash_bytes(&self) -> Vec<u8> {
        let (_, digest) = self.raw_data_hash();
        digest.as_bytes().to_vec()
    }

    /// Compute the raw_data_hash_bytes bytes from the verifier's perspective.
    pub(crate) fn raw_data_hash(&self) -> (Vec<u8>, H256) {
        let mut to_be_hashed = vec![];

        self.public_data_chunks
            .iter()
            .for_each(|public_data_chunk| {
                to_be_hashed
                    .extend_from_slice(
                        // extract all the data from each chunk
                        public_data_chunk.raw_data_hash_bytes().as_ref(),
                    )
                    .into()
            });
        // data hash is the keccak hash of concatenation of all data fields
        let digest = keccak256::<&[u8]>(to_be_hashed.as_ref()).into();
        (to_be_hashed, digest)
    }

    /// Compute the raw_public_inputs_bytes bytes from the verifier's perspective.
    pub(crate) fn raw_public_input_hash_bytes(&self) -> Vec<u8> {
        let (_, digest) = self.raw_public_input_hash();
        digest.as_bytes().to_vec()
    }

    /// Compute the raw_public_inputs_bytes bytes from the verifier's perspective.
    pub(crate) fn raw_public_input_hash(&self) -> (Vec<u8>, H256) {
        let mut to_be_hashed = vec![];
        self.public_data_chunks
            .iter()
            .for_each(|public_data_chunk| {
                to_be_hashed
                    .extend_from_slice(
                        // extract all the data from each chunk
                        public_data_chunk.raw_public_input_hash_bytes().as_ref(),
                    )
                    .into()
            });
        let digest = keccak256::<&[u8]>(to_be_hashed.as_ref()).into();
        (to_be_hashed, digest)
    }

    /// Extract all the hash inputs and outputs that will ever be computed
    /// for this given multi_batch
    /// Ordered as:
    /// - the hash preimage/digest pairs for all blocks
    /// - the hash preimage/digest pair for the data_hash
    /// - the hash preimage/digest pair for the public_input_hash
    /// Returns the
    /// - hash input
    /// - hash output
    pub(crate) fn extract_hashes(&self) -> (Vec<Vec<u8>>, Vec<H256>) {
        let mut preimages = vec![];
        let mut digests = vec![];
        self.public_data_chunks
            .iter()
            .for_each(|public_data_chunk| {
                let (preimage, digest) = public_data_chunk.extract_hashes();
                preimages.extend_from_slice(preimage.as_ref());
                digests.extend_from_slice(digest.as_ref())
            });
        let data_hash_pair = self.raw_data_hash();
        let pi_hash_pair = self.raw_public_input_hash();

        preimages.extend_from_slice(&[data_hash_pair.0, pi_hash_pair.0]);
        digests.extend_from_slice(&[data_hash_pair.1, pi_hash_pair.1]);

        (preimages, digests)
    }
}
