//! This module implements related functions that aggregates public inputs of many chunks into a
//! single one.

use eth_types::{Field, H256};
use ethers_core::utils::keccak256;

use crate::constants::MAX_AGG_SNARKS;

use super::chunk::ChunkHash;

#[derive(Default, Debug, Clone)]
/// A batch is a set of MAX_AGG_SNARKS num of continuous chunks
/// - the first k chunks are from real traces
/// - the last (#MAX_AGG_SNARKS-k) chunks are from empty traces
/// A BatchHash consists of 3 hashes.
/// - batch_pi_hash   := keccak(chain_id || chunk_0.prev_state_root || chunk_k-1.post_state_root ||
///   chunk_k-1.withdraw_root || batch_data_hash || chunk_k-1.last_applied_l1_block || batch_l1_block_range_hash)
/// - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
/// - batch_l1_block_range_hash := keccak(chunk_0.l1_block_range_hash || ... || chunk_k-1.l1_block_range_hash)
pub struct BatchHash {
    pub(crate) chain_id: u64,
    // chunks with padding.
    // - the first [0..number_of_valid_chunks) are real ones
    // - the last [number_of_valid_chunks, MAX_AGG_SNARKS) are padding
    pub(crate) chunks_with_padding: [ChunkHash; MAX_AGG_SNARKS],
    pub(crate) data_hash: H256,
    pub(crate) l1_block_range_hash: H256,
    pub(crate) public_input_hash: H256,
    pub(crate) number_of_valid_chunks: usize,
}

impl BatchHash {
    /// Build Batch hash from an ordered list of #MAX_AGG_SNARKS of chunks.
    #[allow(dead_code)]
    pub fn construct(chunks_with_padding: &[ChunkHash]) -> Self {
        assert_eq!(
            chunks_with_padding.len(),
            MAX_AGG_SNARKS,
            "input chunk slice does not match MAX_AGG_SNARKS"
        );

        let number_of_valid_chunks = match chunks_with_padding
            .iter()
            .enumerate()
            .find(|(_index, chunk)| chunk.is_padding)
        {
            Some((index, _)) => index,
            None => MAX_AGG_SNARKS,
        };

        assert_ne!(
            number_of_valid_chunks, 0,
            "input chunk slice does not contain real chunks"
        );
        log::trace!("build a Batch with {number_of_valid_chunks} real chunks");

        log::trace!("chunks with padding");
        for (i, chunk) in chunks_with_padding.iter().enumerate() {
            log::trace!("{}-th chunk: {:?}", i, chunk);
        }

        // ========================
        // sanity checks
        // ========================
        // todo: return errors instead
        for i in 0..MAX_AGG_SNARKS - 1 {
            assert_eq!(
                chunks_with_padding[i].chain_id,
                chunks_with_padding[i + 1].chain_id,
            );
            if chunks_with_padding[i + 1].is_padding {
                assert_eq!(
                    chunks_with_padding[i + 1].data_hash,
                    chunks_with_padding[i].data_hash
                );
                assert_eq!(
                    chunks_with_padding[i + 1].prev_state_root,
                    chunks_with_padding[i].prev_state_root
                );
                assert_eq!(
                    chunks_with_padding[i + 1].post_state_root,
                    chunks_with_padding[i].post_state_root
                );
                assert_eq!(
                    chunks_with_padding[i + 1].withdraw_root,
                    chunks_with_padding[i].withdraw_root
                );
                assert_eq!(
                    chunks_with_padding[i + 1].last_applied_l1_block,
                    chunks_with_padding[i].last_applied_l1_block
                );
                assert_eq!(
                    chunks_with_padding[i + 1].l1_block_range_hash,
                    chunks_with_padding[i].l1_block_range_hash
                );
            } else {
                assert_eq!(
                    chunks_with_padding[i].post_state_root,
                    chunks_with_padding[i + 1].prev_state_root,
                );
            }
        }

        // batch's data hash is build as
        //  keccak( chunk[0].data_hash || ... || chunk[k-1].data_hash)
        let batch_data_hash_preimage = chunks_with_padding
            .iter()
            .take(number_of_valid_chunks)
            .flat_map(|chunk_hash| chunk_hash.data_hash.0.iter())
            .cloned()
            .collect::<Vec<_>>();
        let batch_data_hash = keccak256(batch_data_hash_preimage);

        // batch's l1 block range hash is build as
        //  keccak( chunk[0].l1_block_range_hash || ... || chunk[k-1].l1_block_range_hash)
        let batch_l1_block_range_preimage = chunks_with_padding
            .iter()
            .take(number_of_valid_chunks)
            .flat_map(|chunk_hash| chunk_hash.l1_block_range_hash.0.iter())
            .cloned()
            .collect::<Vec<_>>();
        let batch_l1_block_range_hash = keccak256(batch_l1_block_range_preimage);

        // public input hash is build as
        //  keccak(
        //      chain_id ||
        //      chunk[0].prev_state_root ||
        //      chunk[k-1].post_state_root ||
        //      chunk[k-1].withdraw_root ||
        //      batch_data_hash ||
        //      batch_l1_block_range_hash ||
        //      chunk[k-1].last_applied_l1_block )
        let preimage = [
            chunks_with_padding[0].chain_id.to_be_bytes().as_ref(),
            chunks_with_padding[0].prev_state_root.as_bytes(),
            chunks_with_padding[MAX_AGG_SNARKS - 1]
                .post_state_root
                .as_bytes(),
            chunks_with_padding[MAX_AGG_SNARKS - 1]
                .withdraw_root
                .as_bytes(),
            batch_data_hash.as_slice(),
            chunks_with_padding[MAX_AGG_SNARKS - 1].last_applied_l1_block.to_be_bytes().as_ref(),
            batch_l1_block_range_hash.as_slice(),
        ]
        .concat();
        let public_input_hash = keccak256(preimage);

        Self {
            chain_id: chunks_with_padding[0].chain_id,
            chunks_with_padding: chunks_with_padding.try_into().unwrap(), // safe unwrap
            data_hash: batch_data_hash.into(),
            l1_block_range_hash: batch_l1_block_range_hash.into(),
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
    /// - batch_l1_block_range_hash_preimage
    pub(crate) fn extract_hash_preimages(&self) -> Vec<Vec<u8>> {
        let mut res = vec![];

        // batchPiHash =
        //  keccak(
        //      chain_id ||
        //      chunk[0].prev_state_root ||
        //      chunk[k-1].post_state_root ||
        //      chunk[k-1].withdraw_root ||
        //      batch_data_hash ||
        //      chunk[k-1].last_applied_l1_block ||
        //      batch_l1_block_range_hash)
        let batch_public_input_hash_preimage = [
            self.chain_id.to_be_bytes().as_ref(),
            self.chunks_with_padding[0].prev_state_root.as_bytes(),
            self.chunks_with_padding[MAX_AGG_SNARKS - 1]
                .post_state_root
                .as_bytes(),
            self.chunks_with_padding[MAX_AGG_SNARKS - 1]
                .withdraw_root
                .as_bytes(),
            self.data_hash.as_bytes(),
            self.l1_block_range_hash.as_bytes(),
            self.chunks_with_padding[MAX_AGG_SNARKS - 1].last_applied_l1_block.to_be_bytes().as_ref(),
        ]
        .concat();
        res.push(batch_public_input_hash_preimage);

        // compute piHash for each chunk for i in [0..MAX_AGG_SNARKS)
        // chunk[i].piHash =
        // keccak(
        //        chain id ||
        //        chunk[i].prevStateRoot || chunk[i].postStateRoot || chunk[i].withdrawRoot ||
        //        chunk[i].datahash || chunk[i].lastAppliedL1Block || chunk[i].l1BlockRangeHash)
        for chunk in self.chunks_with_padding.iter() {
            let chunk_public_input_hash_preimage = [
                self.chain_id.to_be_bytes().as_ref(),
                chunk.prev_state_root.as_bytes(),
                chunk.post_state_root.as_bytes(),
                chunk.withdraw_root.as_bytes(),
                chunk.data_hash.as_bytes(),
                chunk.l1_block_range_hash.as_bytes(),
                chunk.last_applied_l1_block.to_be_bytes().as_ref(),
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

        // batchL1BlockRangeHash = keccak(chunk[0].l1BlockRangeHash || ... || chunk[k-1].l1BlockRangeHash)
        let batch_l1_block_range_hash_preimage = self
            .chunks_with_padding
            .iter()
            .take(self.number_of_valid_chunks)
            .flat_map(|x| x.l1_block_range_hash.as_bytes().iter())
            .cloned()
            .collect();
        res.push(batch_l1_block_range_hash_preimage);

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
