//! This module implements related functions that aggregates public inputs of many chunks into a
//! single one.
//!
//! # Spec
//!
//! A chunk is a list of continuous blocks. It consists of 4 hashes:
//! - state root before this chunk
//! - state root after this chunk
//! - the withdraw root of this chunk
//! - the data hash of this chunk
//! Those 4 hashes are obtained from the caller.
//!
//! A chunk's public input hash is then derived from the above 4 attributes via
//!
//! - chunk_pi_hash   := keccak(chain_id || prev_state_root || post_state_root || withdraw_root ||
//!   chunk_data_hash)
//!
//! A batch is a list of continuous chunks. It consists of 2 hashes
//!
//! - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
//!
//! - batch_pi_hash   := keccak(chain_id || chunk_0.prev_state_root || chunk_k-1.post_state_root ||
//!   chunk_k-1.withdraw_root || batch_data_hash)
//!
//! Note that chain_id is used for all public input hashes. But not for any data hashes.
//!
//! # Circuit
//!
//! A BatchHashCircuit asserts that the batch is well-formed.
//!
//! ## Public Input
//! The public inputs of the circuit (32 Field elements) is constructed as
//! - batch_pi_hash: 32 Field elements
//!
//! ## Constraints
//! The circuit attests the following statements:
//!
//! 1. all hashes are computed correctly
//! 2. the relations between hash preimages and digests are satisfied
//!     - batch_data_hash is part of the input to compute batch_pi_hash
//!     - batch_pi_hash used same roots as chunk_pi_hash
//!     - same data_hash is used to compute batch_data_hash and chunk_pi_hash for all chunks
//!     - chunks are continuous: they are linked via the state roots
//!     - all hashes uses a same chain_id
//! 3. the batch_pi_hash matches the circuit's public input (32 field elements) above

use eth_types::{Field, H256};
use ethers_core::utils::keccak256;

use super::chunk::ChunkHash;

#[derive(Default, Debug, Clone)]
/// A batch is a set of continuous chunks.
/// A BatchHash consists of 2 hashes.
/// - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
/// - batch_pi_hash   := keccak(chain_id || chunk_0.prev_state_root || chunk_k-1.post_state_root ||
///   chunk_k-1.withdraw_root || batch_data_hash)
pub struct BatchHash {
    pub(crate) chain_id: u64,
    pub(crate) chunks: Vec<ChunkHash>,
    pub(crate) data_hash: H256,
    pub(crate) public_input_hash: H256,
}

impl BatchHash {
    /// Sample a batch hash circuit from random (for testing)
    #[cfg(test)]
    pub(crate) fn mock_batch_hash_circuit<R: rand::RngCore>(r: &mut R, size: usize) -> Self {
        let mut chunks = (0..size)
            .map(|_| ChunkHash::mock_chunk_hash(r))
            .collect::<Vec<_>>();
        for i in 0..size - 1 {
            chunks[i + 1].prev_state_root = chunks[i].post_state_root;
        }

        Self::construct(&chunks)
    }

    /// Build Batch hash from a list of chunks
    pub(crate) fn construct(chunk_hashes: &[ChunkHash]) -> Self {
        assert!(!chunk_hashes.is_empty(), "input chunk slice is empty");

        // sanity: the chunks are continuous
        for i in 0..chunk_hashes.len() - 1 {
            assert_eq!(
                chunk_hashes[i].post_state_root,
                chunk_hashes[i + 1].prev_state_root,
            );
            assert_eq!(chunk_hashes[i].chain_id, chunk_hashes[i + 1].chain_id,)
        }

        // batch's data hash is build as
        //  keccak( chunk[0].data_hash || ... || chunk[k-1].data_hash)
        let preimage = chunk_hashes
            .iter()
            .flat_map(|chunk_hash| chunk_hash.data_hash.0.iter())
            .cloned()
            .collect::<Vec<_>>();
        let data_hash = keccak256(preimage);

        // public input hash is build as
        //  keccak(
        //      chain_id ||
        //      chunk[0].prev_state_root ||
        //      chunk[k-1].post_state_root ||
        //      chunk[k-1].withdraw_root ||
        //      batch_data_hash )
        let preimage = [
            chunk_hashes[0].chain_id.to_le_bytes().as_ref(),
            chunk_hashes[0].prev_state_root.as_bytes(),
            chunk_hashes.last().unwrap().post_state_root.as_bytes(),
            chunk_hashes.last().unwrap().withdraw_root.as_bytes(),
            data_hash.as_slice(),
        ]
        .concat();
        let public_input_hash = keccak256(preimage);

        Self {
            chain_id: chunk_hashes[0].chain_id,
            chunks: chunk_hashes.to_vec(),
            data_hash: data_hash.into(),
            public_input_hash: public_input_hash.into(),
        }
    }

    /// Extract all the hash inputs that will ever be used
    /// orders:
    /// - batch_public_input_hash
    /// - batch_data_hash_preimage
    /// - chunk\[i\].piHash for i in \[0, k)
    pub(crate) fn extract_hash_preimages(&self) -> Vec<Vec<u8>> {
        let mut res = vec![];

        // batchPiHash =
        //  keccak(
        //      chain_id ||
        //      chunk[0].prev_state_root ||
        //      chunk[k-1].post_state_root ||
        //      chunk[k-1].withdraw_root ||
        //      batch_data_hash )
        let batch_public_input_hash_preimage = [
            self.chain_id.to_le_bytes().as_ref(),
            self.chunks[0].prev_state_root.as_bytes(),
            self.chunks.last().unwrap().post_state_root.as_bytes(),
            self.chunks.last().unwrap().withdraw_root.as_bytes(),
            self.data_hash.as_bytes(),
        ]
        .concat();
        res.push(batch_public_input_hash_preimage);

        // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
        let batch_data_hash_preimage = self
            .chunks
            .iter()
            .flat_map(|x| x.data_hash.as_bytes().iter())
            .cloned()
            .collect();
        res.push(batch_data_hash_preimage);

        // compute piHash for each chunk for i in [0..k)
        // chunk[i].piHash =
        // keccak(
        //        chain id ||
        //        chunk[i].prevStateRoot || chunk[i].postStateRoot || chunk[i].withdrawRoot ||
        //        chunk[i].datahash)
        for chunk in self.chunks.iter() {
            let chunk_pi_hash_preimage = [
                self.chain_id.to_le_bytes().as_ref(),
                chunk.prev_state_root.as_bytes(),
                chunk.post_state_root.as_bytes(),
                chunk.withdraw_root.as_bytes(),
                chunk.data_hash.as_bytes(),
            ]
            .concat();
            res.push(chunk_pi_hash_preimage)
        }

        res
    }

    fn num_instance(&self) -> Vec<usize> {
        // 12 elements from the accumulators
        // 32 elements from batch_data_hash_digest
        vec![44]
    }

    /// Compute the public inputs for this circuit
    /// which is the public_input_hash
    pub(crate) fn instances<F: Field>(&self) -> Vec<Vec<F>> {
        vec![self
            .public_input_hash
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64))
            .collect()]
    }
}
