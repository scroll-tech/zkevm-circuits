//! This module implements `Chunk` related data types.
//! A chunk is a list of blocks.
use crate::pi_circuit::PublicData;
use eth_types::H256;
use ethers_core::utils::keccak256;

#[derive(Default, Debug, Clone)]
/// ChunkPublicData is a list of PublicData, each corresponds to a block
/// with max_txn transactions.
pub struct ChunkPublicData<const MAX_TXS: usize> {
    pub(crate) public_data_vec: Vec<PublicData>,
}

impl<const MAX_TXS: usize> ChunkPublicData<MAX_TXS> {
    /// Compute the raw_data_hash_bytes bytes from the verifier's perspective.
    pub(crate) fn raw_data_hash_bytes(&self) -> Vec<u8> {
        let (_, digest) = self.raw_data_hash();
        digest.as_bytes().to_vec()
    }

    /// Compute the raw_data_hash, return both the preimage and the hash
    pub(crate) fn raw_data_hash(&self) -> (Vec<u8>, H256) {
        let mut to_be_hashed = vec![];

        self.public_data_vec.iter().for_each(|public_data| {
            to_be_hashed
                .extend_from_slice(
                    // extract all the data from transactions
                    public_data.get_pi(MAX_TXS).as_bytes(),
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

    /// Compute the raw_public_input_hash, return both the preimage and the hash
    pub(crate) fn raw_public_input_hash(&self) -> (Vec<u8>, H256) {
        let mut to_be_hashed = vec![];
        // extract the prev state root of the first block
        // and the next state root of the last block
        to_be_hashed.extend_from_slice(self.public_data_vec[0].prev_state_root.as_bytes());
        to_be_hashed.extend_from_slice(
            self.public_data_vec
                .last()
                .unwrap()
                .prev_state_root
                .as_bytes(),
        );
        // withdraw root
        //
        // FIXME: for each block we have a withdraw_trie_root
        // This is different from the spec.
        // Double check this.
        self.public_data_vec.iter().for_each(|public_data| {
            to_be_hashed.extend_from_slice(public_data.withdraw_trie_root.as_bytes())
        });

        let digest = keccak256::<&[u8]>(to_be_hashed.as_ref()).into();
        (to_be_hashed, digest)
    }

    /// Extract all the hash inputs and outputs that will ever be computed
    /// for this given multi_batch
    /// Ordered as:
    /// - the hash preimage/digest pair for the data_hash
    /// - the hash preimage/digest pair for the public_input_hash
    pub(crate) fn extract_hashes(&self) -> (Vec<Vec<u8>>, Vec<H256>) {
        let data_hash_pair = self.raw_data_hash();
        let pi_hash_pair = self.raw_public_input_hash();
        (
            vec![data_hash_pair.0, pi_hash_pair.0],
            vec![data_hash_pair.1, pi_hash_pair.1],
        )
    }
}
