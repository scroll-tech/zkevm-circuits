//! This module implements `Chunk` related data types.
//! A chunk is a list of blocks.
use eth_types::H256;
use ethers_core::utils::keccak256;

#[derive(Default, Debug, Clone, Copy)]
/// A chunk is a set of continuous blocks.
/// A ChunkHash consists of 4 hashes, representing the changes incurred by this chunk of blocks:
/// - state root before this chunk
/// - state root after this chunk
/// - the withdraw root of this chunk
/// - the data hash of this chunk
pub struct ChunkHash {
    /// Chain identifier
    pub(crate) chain_id: u64,
    /// state root before this chunk
    pub(crate) prev_state_root: H256,
    /// state root after this chunk
    pub(crate) post_state_root: H256,
    /// the withdraw root of this chunk
    pub(crate) withdraw_root: H256,
    /// the data hash of this chunk
    pub(crate) data_hash: H256,
}

impl ChunkHash {
    /// Sample a chunk hash from random (for testing)
    #[cfg(test)]
    pub(crate) fn mock_chunk_hash<R: rand::RngCore>(r: &mut R) -> Self {
        let mut prev_state_root = [0u8; 32];
        r.fill_bytes(&mut prev_state_root);
        let mut post_state_root = [0u8; 32];
        r.fill_bytes(&mut post_state_root);
        let mut withdraw_root = [0u8; 32];
        r.fill_bytes(&mut withdraw_root);
        let mut data_hash = [0u8; 32];
        r.fill_bytes(&mut data_hash);
        Self {
            chain_id: 0,
            prev_state_root: prev_state_root.into(),
            post_state_root: post_state_root.into(),
            withdraw_root: withdraw_root.into(),
            data_hash: data_hash.into(),
        }
    }

    /// Public input hash for a given chunk is defined as
    ///  keccak( chain id || prev state root || post state root || withdraw root || data hash )
    pub fn public_input_hash(&self) -> H256 {
        let preimage = self.extract_hash_preimage();
        keccak256::<&[u8]>(preimage.as_ref()).into()
    }

    /// Extract the preimage for the hash
    ///  chain id || prev state root || post state root || withdraw root || data hash
    pub fn extract_hash_preimage(&self) -> Vec<u8> {
        [
            self.chain_id.to_be_bytes().as_ref(),
            self.prev_state_root.as_bytes(),
            self.post_state_root.as_bytes(),
            self.withdraw_root.as_bytes(),
            self.data_hash.as_bytes(),
        ]
        .concat()
    }
}
