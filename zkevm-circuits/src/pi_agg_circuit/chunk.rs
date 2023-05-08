//! This module implements `Chunk` related data types.
//! A chunk is a list of blocks.
use crate::pi_circuit::PublicData;
use ethers_core::utils::keccak256;

#[derive(Default, Debug, Clone)]
/// ChunkPublicData is a list of PublicData, each corresponds to a block
/// with max_txn transactions.
pub struct ChunkPublicData {
    pub(crate) public_data_vec: Vec<PublicData>,
    pub(crate) max_txs: usize,
}

impl ChunkPublicData {
    /// Compute the raw_data_hash_bytes bytes from the verifier's perspective.
    pub(crate) fn raw_data_hash_bytes(&self) -> Vec<u8> {
        let mut to_be_hashed = vec![];

        self.public_data_vec.iter().for_each(|public_data| {
            to_be_hashed
                .extend_from_slice(
                    // extract all the data from transactions
                    public_data.get_pi(self.max_txs).as_ref(),
                )
                .into()
        });
        // data hash is the keccak hash of concatenation of all data fields
        keccak256::<&[u8]>(to_be_hashed.as_ref()).into()
    }

    /// Compute the raw_public_inputs_bytes bytes from the verifier's perspective.
    pub(crate) fn raw_public_input_bytes(&self) -> Vec<u8> {
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
        // FIXME: for each block we hav a withdraw_trie_root
        // This is different from the spec.
        // Double check this.
        self.public_data_vec.iter().for_each(|public_data| {
            to_be_hashed.extend_from_slice(public_data.withdraw_trie_root.as_bytes())
        });

        keccak256::<&[u8]>(to_be_hashed.as_ref()).into()
    }
}
