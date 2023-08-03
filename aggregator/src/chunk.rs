//! This module implements `Chunk` related data types.
//! A chunk is a list of blocks.
use eth_types::{ToBigEndian, H256};
use ethers_core::utils::keccak256;
use halo2_proofs::halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};
use std::iter;
use zkevm_circuits::witness::Block;

#[derive(Default, Debug, Clone, Copy, Deserialize, Serialize)]
/// A chunk is a set of continuous blocks.
/// A ChunkHash consists of 4 hashes, representing the changes incurred by this chunk of blocks:
/// - state root before this chunk
/// - state root after this chunk
/// - the withdraw root after this chunk
/// - the data hash of this chunk
/// - if the chunk is padded (en empty but valid chunk that is padded for aggregation)
pub struct ChunkHash {
    /// Chain identifier
    pub chain_id: u64,
    /// state root before this chunk
    pub prev_state_root: H256,
    /// state root after this chunk
    pub post_state_root: H256,
    /// the withdraw root after this chunk
    pub withdraw_root: H256,
    /// the data hash of this chunk
    pub data_hash: H256,
    /// if the chunk is a padded chunk
    pub is_padding: bool,
}

impl ChunkHash {
    /// Construct by a witness block.
    pub fn from_witness_block(block: &Block<Fr>, is_padding: bool) -> Self {
        // <https://github.com/scroll-tech/zkevm-circuits/blob/25dd32aa316ec842ffe79bb8efe9f05f86edc33e/bus-mapping/src/circuit_input_builder.rs#L690>

        let data_bytes = iter::empty()
            .chain(block.context.ctxs.iter().flat_map(|(b_num, b_ctx)| {
                let num_txs = block
                    .txs
                    .iter()
                    .filter(|tx| tx.block_number == *b_num)
                    .count() as u16;

                iter::empty()
                    // Block Values
                    .chain(b_ctx.number.as_u64().to_be_bytes())
                    .chain(b_ctx.timestamp.as_u64().to_be_bytes())
                    .chain(b_ctx.base_fee.to_be_bytes())
                    .chain(b_ctx.gas_limit.to_be_bytes())
                    .chain(num_txs.to_be_bytes())
            }))
            // Tx Hashes
            .chain(block.txs.iter().flat_map(|tx| tx.hash.to_fixed_bytes()))
            .collect::<Vec<u8>>();

        let data_hash = H256(keccak256(data_bytes));

        let post_state_root = block
            .context
            .ctxs
            .last_key_value()
            .map(|(_, b_ctx)| b_ctx.eth_block.state_root)
            .unwrap_or(H256(block.prev_state_root.to_be_bytes()));

        Self {
            chain_id: block.chain_id,
            prev_state_root: H256(block.prev_state_root.to_be_bytes()),
            post_state_root,
            withdraw_root: H256(block.withdraw_root.to_be_bytes()),
            data_hash,
            is_padding,
        }
    }

    /// Sample a chunk hash from random (for testing)
    #[cfg(test)]
    pub(crate) fn mock_random_chunk_hash_for_testing<R: rand::RngCore>(r: &mut R) -> Self {
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
            is_padding: false,
        }
    }

    /// Build a padded chunk from previous one
    #[cfg(test)]
    pub(crate) fn mock_padded_chunk_hash_for_testing(previous_chunk: &Self) -> Self {
        assert!(
            !previous_chunk.is_padding,
            "previous chunk is padded already"
        );
        Self {
            chain_id: previous_chunk.chain_id,
            prev_state_root: previous_chunk.prev_state_root,
            post_state_root: previous_chunk.post_state_root,
            withdraw_root: previous_chunk.withdraw_root,
            data_hash: previous_chunk.data_hash,
            is_padding: true,
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
