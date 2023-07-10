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

use crate::constants::MAX_AGG_SNARKS;

use super::chunk::ChunkHash;

#[derive(Default, Debug, Clone)]
/// A batch is a set of continuous chunks.
/// A BatchHash consists of 2 hashes.
/// - batch_pi_hash   := keccak(chain_id || chunk_0.prev_state_root || chunk_k-1.post_state_root ||
///   chunk_k-1.withdraw_root || batch_data_hash)
/// - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
pub struct BatchHash {
    pub(crate) chain_id: u64,
    // chunks with padding.
    // - the first [0..number_of_valid_chunks) are real ones
    // - the last [number_of_valid_chunks, MAX_AGG_SNARKS) are padding
    pub(crate) chunks_with_padding: [ChunkHash; MAX_AGG_SNARKS],
    pub(crate) data_hash: H256,
    pub(crate) public_input_hash: H256,
    pub(crate) number_of_valid_chunks: usize,
}

impl BatchHash {
    /// Build Batch hash from a list of chunks
    #[allow(dead_code)]
    pub(crate) fn construct(chunks_without_padding: &[ChunkHash]) -> Self {
        assert!(
            !chunks_without_padding.is_empty(),
            "input chunk slice is empty"
        );
        let number_of_valid_chunks = chunks_without_padding.len();
        assert!(
            number_of_valid_chunks <= MAX_AGG_SNARKS,
            "input #chunks ({}) exceed maximum allowed ({})",
            number_of_valid_chunks,
            MAX_AGG_SNARKS
        );

        // pad the chunks with dummy ones
        let mut chunks_with_padding = chunks_without_padding.to_vec();
        if chunks_without_padding.len() != MAX_AGG_SNARKS {
            let dummy_chunk = ChunkHash::dummy_chunk_hash(chunks_without_padding.last().unwrap()); // Safe unwrap
            chunks_with_padding = [
                chunks_with_padding,
                vec![dummy_chunk; MAX_AGG_SNARKS - chunks_without_padding.len()],
            ]
            .concat();
        }
        log::trace!("chunks with padding");
        for (i, chunks) in chunks_with_padding.iter().enumerate() {
            log::trace!("{}-th chunk: {:?}", i, chunks);
        }

        // sanity checks
        // todo: return errors instead
        for i in 0..MAX_AGG_SNARKS - 1 {
            assert_eq!(
                chunks_with_padding[i].post_state_root,
                chunks_with_padding[i + 1].prev_state_root,
            );
            assert_eq!(
                chunks_with_padding[i].chain_id,
                chunks_with_padding[i + 1].chain_id,
            )
        }

        // batch's data hash is build as
        //  keccak( chunk[0].data_hash || ... || chunk[k-1].data_hash)
        let preimage = chunks_without_padding
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
            chunks_with_padding[0].chain_id.to_be_bytes().as_ref(),
            chunks_with_padding[0].prev_state_root.as_bytes(),
            chunks_with_padding[MAX_AGG_SNARKS - 1]
                .post_state_root
                .as_bytes(),
            chunks_with_padding[MAX_AGG_SNARKS - 1]
                .withdraw_root
                .as_bytes(),
            data_hash.as_slice(),
        ]
        .concat();
        let public_input_hash = keccak256(preimage);

        Self {
            chain_id: chunks_with_padding[0].chain_id,
            chunks_with_padding: chunks_with_padding.try_into().unwrap(),
            data_hash: data_hash.into(),
            public_input_hash: public_input_hash.into(),
            number_of_valid_chunks,
        }
    }

    /// Extract all the hash inputs that will ever be used.
    /// There are MAX_AGG_SNARKS + 2 hashes.
    ///
    /// orders:
    /// - batch_public_input_hash
    /// - chunk\[i\].piHash for i in \[0, MAX_AGG_SNARKS)
    /// - batch_data_hash_preimage
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
            self.chain_id.to_be_bytes().as_ref(),
            self.chunks_with_padding[0].prev_state_root.as_bytes(),
            self.chunks_with_padding
                .last()
                .unwrap()
                .post_state_root
                .as_bytes(),
            self.chunks_with_padding
                .last()
                .unwrap()
                .withdraw_root
                .as_bytes(),
            self.data_hash.as_bytes(),
        ]
        .concat();
        res.push(batch_public_input_hash_preimage);

        // compute piHash for each chunk for i in [0..MAX_AGG_SNARKS)
        // chunk[i].piHash =
        // keccak(
        //        chain id ||
        //        chunk[i].prevStateRoot || chunk[i].postStateRoot || chunk[i].withdrawRoot ||
        //        chunk[i].datahash)
        for chunk in self.chunks_with_padding.iter() {
            let chunk_public_input_hash_preimage = [
                self.chain_id.to_be_bytes().as_ref(),
                chunk.prev_state_root.as_bytes(),
                chunk.post_state_root.as_bytes(),
                chunk.withdraw_root.as_bytes(),
                chunk.data_hash.as_bytes(),
            ]
            .concat();
            res.push(chunk_public_input_hash_preimage)
        }

        // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
        let batch_data_hash_preimage = self
            .chunks_with_padding
            .iter()
            .take(self.number_of_valid_chunks)
            .flat_map(|x| x.data_hash.as_bytes().iter())
            .cloned()
            .collect();
        res.push(batch_data_hash_preimage);

        res
    }

    /// Compute the public inputs for this circuit, excluding the accumulator.
    /// Content: the public_input_hash
    pub(crate) fn instances_exclude_acc<F: Field>(&self) -> Vec<Vec<F>> {
        vec![self
            .public_input_hash
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64))
            .collect()]
    }
}
