//! This module implements related functions that aggregates public inputs of many chunks into a
//! single one.

use eth_types::{Field, ToBigEndian, H256};
use ethers_core::utils::keccak256;

use crate::{
    blob::{BlobAssignments, BlobData},
    chunk::ChunkHash,
};

#[derive(Default, Debug, Clone)]
/// A batch is a set of N_SNARKS num of continuous chunks
/// - the first k chunks are from real traces
/// - the last (#N_SNARKS-k) chunks are from empty traces
/// A BatchHash consists of 2 hashes.
/// - batch_pi_hash   := keccak(chain_id || chunk_0.prev_state_root || chunk_k-1.post_state_root ||
///   chunk_k-1.withdraw_root || batch_data_hash)
/// - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
pub struct BatchHash<const N_SNARKS: usize> {
    /// Chain ID of the network.
    pub(crate) chain_id: u64,
    /// chunks with padding.
    /// - the first [0..number_of_valid_chunks) are real ones
    /// - the last [number_of_valid_chunks, N_SNARKS) are padding
    pub(crate) chunks_with_padding: Vec<ChunkHash>,
    /// The batch data hash:
    /// - keccak256([chunk.hash for chunk in batch])
    pub(crate) data_hash: H256,
    /// The public input hash, as calculated on-chain:
    /// - keccak256( chain_id || prev_state_root || next_state_root || withdraw_trie_root ||
    ///   batch_data_hash || z || y )
    pub(crate) public_input_hash: H256,
    /// The number of chunks that contain meaningful data, i.e. not padded chunks.
    pub(crate) number_of_valid_chunks: usize,
    /// 4844-Blob related fields.
    pub(crate) blob: BlobAssignments,
    /// The 4844 versioned hash for the blob.
    pub(crate) versioned_hash: H256,
}

impl<const N_SNARKS: usize> BatchHash<N_SNARKS> {
    /// Build Batch hash from an ordered list of #N_SNARKS of chunks.
    #[allow(dead_code)]
    pub fn construct(chunks_with_padding: &[ChunkHash]) -> Self {
        assert_eq!(
            chunks_with_padding.len(),
            N_SNARKS,
            "input chunk slice does not match N_SNARKS"
        );

        let number_of_valid_chunks = match chunks_with_padding
            .iter()
            .enumerate()
            .find(|(_index, chunk)| chunk.is_padding)
        {
            Some((index, _)) => index,
            None => N_SNARKS,
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
        for i in 0..N_SNARKS - 1 {
            assert_eq!(
                chunks_with_padding[i].chain_id,
                chunks_with_padding[i + 1].chain_id,
            );
            if chunks_with_padding[i + 1].is_padding {
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
                    chunks_with_padding[i + 1].data_hash,
                    chunks_with_padding[i].data_hash
                );
                assert_eq!(
                    chunks_with_padding[i + 1].tx_bytes_hash(),
                    chunks_with_padding[i].tx_bytes_hash(),
                );
            } else {
                assert_eq!(
                    chunks_with_padding[i].post_state_root,
                    chunks_with_padding[i + 1].prev_state_root,
                );
            }
        }

        // batch's data hash is build as
        // keccak( chunk[0].data_hash || ... || chunk[k-1].data_hash )
        let preimage = chunks_with_padding
            .iter()
            .take(number_of_valid_chunks)
            .flat_map(|chunk_hash| chunk_hash.data_hash.0.iter())
            .cloned()
            .collect::<Vec<_>>();
        let batch_data_hash = keccak256(preimage);

        let blob_data = BlobData::<N_SNARKS>::new(number_of_valid_chunks, chunks_with_padding);
        let blob_assignments = BlobAssignments::from(&blob_data);
        let versioned_hash = blob_data.get_versioned_hash();

        // public input hash is build as
        // keccak(
        //     chain_id ||
        //     chunk[0].prev_state_root ||
        //     chunk[k-1].post_state_root ||
        //     chunk[k-1].withdraw_root ||
        //     batch_data_hash ||
        //     z ||
        //     y ||
        //     versioned_hash
        // )
        let preimage = [
            chunks_with_padding[0].chain_id.to_be_bytes().as_ref(),
            chunks_with_padding[0].prev_state_root.as_bytes(),
            chunks_with_padding[N_SNARKS - 1].post_state_root.as_bytes(),
            chunks_with_padding[N_SNARKS - 1].withdraw_root.as_bytes(),
            batch_data_hash.as_slice(),
            blob_assignments.challenge.to_be_bytes().as_ref(),
            blob_assignments.evaluation.to_be_bytes().as_ref(),
            versioned_hash.as_bytes(),
        ]
        .concat();
        let public_input_hash: H256 = keccak256(preimage).into();
        log::info!(
            "batch pihash {:?}, datahash {}, z {} y {}",
            public_input_hash,
            hex::encode(batch_data_hash),
            hex::encode(blob_assignments.challenge.to_be_bytes()),
            hex::encode(blob_assignments.evaluation.to_be_bytes())
        );

        Self {
            chain_id: chunks_with_padding[0].chain_id,
            chunks_with_padding: chunks_with_padding.to_vec(),
            data_hash: batch_data_hash.into(),
            public_input_hash,
            number_of_valid_chunks,
            blob: blob_assignments,
            versioned_hash,
        }
    }

    /// Return the blob polynomial and its evaluation at challenge
    pub fn blob_assignments(&self) -> BlobAssignments {
        self.blob.clone()
    }

    /// Extract all the hash inputs that will ever be used.
    /// There are N_SNARKS + 2 hashes.
    ///
    /// orders:
    /// - batch_public_input_hash
    /// - chunk\[i\].piHash for i in \[0, N_SNARKS)
    /// - batch_data_hash_preimage
    /// - preimage for blob metadata
    /// - chunk\[i\].flattened_l2_signed_data for i in \[0, N_SNARKS)
    /// - preimage for challenge digest
    pub(crate) fn extract_hash_preimages(&self) -> Vec<Vec<u8>> {
        let mut res = vec![];

        // batchPiHash =
        //  keccak(
        //      chain_id ||
        //      chunk[0].prev_state_root ||
        //      chunk[k-1].post_state_root ||
        //      chunk[k-1].withdraw_root ||
        //      batch_data_hash ||
        //      z ||
        //      y ||
        //      blob_versioned_hash
        //  )
        let batch_public_input_hash_preimage = [
            self.chain_id.to_be_bytes().as_ref(),
            self.chunks_with_padding[0].prev_state_root.as_bytes(),
            self.chunks_with_padding[N_SNARKS - 1]
                .post_state_root
                .as_bytes(),
            self.chunks_with_padding[N_SNARKS - 1]
                .withdraw_root
                .as_bytes(),
            self.data_hash.as_bytes(),
            &self.blob.challenge.to_be_bytes(),
            &self.blob.evaluation.to_be_bytes(),
            self.versioned_hash.as_bytes(),
        ]
        .concat();
        res.push(batch_public_input_hash_preimage);

        // compute piHash for each chunk for i in [0..N_SNARKS)
        // chunk[i].piHash =
        // keccak(
        //     chain id ||
        //     chunk[i].prevStateRoot ||
        //     chunk[i].postStateRoot ||
        //     chunk[i].withdrawRoot ||
        //     chunk[i].datahash ||
        //     chunk[i].tx_data_hash
        // )
        for chunk in self.chunks_with_padding.iter() {
            res.push(chunk.extract_hash_preimage());
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

        // This is the end of part where preimages to the keccak hashing function are of known
        // size. We now move to the part where the preimage is dynamic.
        //
        // These include:
        // - preimage for blob metadata
        // - preimage for each chunk's flattened L2 signed tx data
        // - preimage for the challenge digest
        let blob_data = BlobData::from(self);
        let dynamic_preimages = blob_data.preimages();
        for dynamic_preimage in dynamic_preimages {
            res.push(dynamic_preimage);
        }

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
