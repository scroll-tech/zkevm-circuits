//! This module implements related functions that aggregates public inputs of many chunks into a
//! single one.

use eth_types::{ToBigEndian, H256};
use ethers_core::utils::keccak256;
use gadgets::{util::split_h256, Field};
use serde::{Deserialize, Serialize};
use std::iter::repeat;

use crate::{
    blob::{BatchData, PointEvaluationAssignments},
    chunk::ChunkInfo,
    eip4844::{get_coefficients, get_versioned_hash},
};

/// Batch header provides additional fields from the context (within recursion)
/// for constructing the preimage of the batch hash.
#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BatchHeader<const N_SNARKS: usize> {
    /// the batch version
    pub version: u8,
    /// the index of the batch
    pub batch_index: u64,
    /// Number of L1 messages popped in the batch
    pub l1_message_popped: u64,
    /// Number of total L1 messages popped after the batch
    pub total_l1_message_popped: u64,
    /// The parent batch hash
    pub parent_batch_hash: H256,
    /// The timestamp of the last block in this batch
    pub last_block_timestamp: u64,
    /// The data hash of the batch
    pub data_hash: H256,
    /// The versioned hash of the blob with this batch's data
    pub blob_versioned_hash: H256,
    /// The blob data proof: z (32), y (32)
    pub blob_data_proof: [H256; 2],
}

impl<const N_SNARKS: usize> BatchHeader<N_SNARKS> {
    /// Constructs the correct batch header from chunks data and context variables
    #[allow(clippy::too_many_arguments)]
    pub fn construct_from_chunks(
        version: u8,
        batch_index: u64,
        l1_message_popped: u64,
        total_l1_message_popped: u64,
        parent_batch_hash: H256,
        last_block_timestamp: u64,
        chunks: &[ChunkInfo],
        blob_bytes: &[u8],
    ) -> Self {
        assert_ne!(chunks.len(), 0);
        assert!(chunks.len() <= N_SNARKS);

        let mut chunks_with_padding = chunks.to_vec();
        if chunks.len() < N_SNARKS {
            let last_chunk = chunks.last().unwrap();
            let mut padding_chunk = last_chunk.clone();
            padding_chunk.is_padding = true;
            chunks_with_padding
                .extend(std::iter::repeat(padding_chunk).take(N_SNARKS - chunks.len()));
        }

        let number_of_valid_chunks = match chunks_with_padding
            .iter()
            .enumerate()
            .find(|(_index, chunk)| chunk.is_padding)
        {
            Some((index, _)) => index,
            None => N_SNARKS,
        };

        let batch_data_hash_preimage = chunks_with_padding
            .iter()
            .take(number_of_valid_chunks)
            .flat_map(|chunk_info| chunk_info.data_hash.0.iter())
            .cloned()
            .collect::<Vec<_>>();
        let batch_data_hash = keccak256(batch_data_hash_preimage);

        let batch_data = BatchData::<N_SNARKS>::new(number_of_valid_chunks, &chunks_with_padding);
        let coeffs = get_coefficients(blob_bytes);
        let blob_versioned_hash = get_versioned_hash(&coeffs);
        let point_evaluation_assignments =
            PointEvaluationAssignments::new(&batch_data, blob_bytes, blob_versioned_hash);

        Self {
            version,
            batch_index,
            l1_message_popped,
            total_l1_message_popped,
            parent_batch_hash,
            last_block_timestamp,
            data_hash: batch_data_hash.into(),
            blob_versioned_hash,
            blob_data_proof: [
                H256::from_slice(&point_evaluation_assignments.challenge.to_be_bytes()),
                H256::from_slice(&point_evaluation_assignments.evaluation.to_be_bytes()),
            ],
        }
    }

    pub fn batch_hash_preimage(&self) -> Vec<u8> {
        // keccak256(
        //     version ||
        //     batch_index ||
        //     l1_message_popped ||
        //     total_l1_message_popped ||
        //     batch_data_hash ||
        //     versioned_hash ||
        //     parent_batch_hash ||
        //     last_block_timestamp ||
        //     z ||
        //     y
        // )
        [
            vec![self.version].as_slice(),
            self.batch_index.to_be_bytes().as_ref(),
            self.l1_message_popped.to_be_bytes().as_ref(),
            self.total_l1_message_popped.to_be_bytes().as_ref(),
            self.data_hash.as_bytes(),
            self.blob_versioned_hash.as_bytes(),
            self.parent_batch_hash.as_bytes(),
            self.last_block_timestamp.to_be_bytes().as_ref(),
            self.blob_data_proof[0].to_fixed_bytes().as_ref(),
            self.blob_data_proof[1].to_fixed_bytes().as_ref(),
        ]
        .concat()
    }

    /// Returns the batch hash as per BatchHeaderV3.
    pub fn batch_hash(&self) -> H256 {
        H256::from(keccak256(self.batch_hash_preimage()))
    }
}

/// Batch is a list of up to N_SNARKS continuous chunks, with at least a single chunk.
#[derive(Default, Debug, Clone)]
pub struct BatchInfo<const N_SNARKS: usize> {
    /// Chain ID of the network.
    pub(crate) chain_id: u64,
    /// The number of chunks that contain meaningful data, i.e. not padded chunks.
    pub(crate) num_valid_chunks: usize,
    /// N_SNARKS number of chunks, with only the first `num_valid_chunks` valid chunks, followed by
    /// `N_SNARKS - num_valid_chunks` padded chunks. The last valid chunk is used to pad.
    pub(crate) padded_chunks: Vec<ChunkInfo>,
    /// State root of the parent batch
    pub(crate) parent_state_root: H256,
    /// State root after applying the current batch.
    pub(crate) state_root: H256,
    /// Withdraw trie root from the last chunk in the current batch.
    pub(crate) withdraw_root: H256,
    /// Hash of this batch.
    pub(crate) batch_hash: H256,
    /// EIP-4844 point evaluation related assignments.
    pub(crate) point_evaluation_assignments: PointEvaluationAssignments,
    /// EIP-4844 versioned hash for the blob that carries the batch data.
    pub(crate) versioned_hash: H256,
    /// Batch header of the batch.
    pub(crate) batch_header: BatchHeader<N_SNARKS>,
    /// The actual bytes in the EIP-4844 blob. A blob consists of 4096 BLS12-381 scalars, i.e. a
    /// total of 4096*32 bytes. However, since each 32-bytes chunk must represent a BLS12-381
    /// scalar in its canonical form, we explicitly set the most-significant byte as 0. The blob
    /// bytes here represent the meaningful 4096*31 bytes.
    pub(crate) blob_bytes: Vec<u8>,
}

impl<const N_SNARKS: usize> BatchInfo<N_SNARKS> {
    /// Construct a [`BatchInfo`] given an ordered list of chunks that may be unpadded.
    pub fn construct_with_unpadded(
        unpadded_chunks: &[ChunkInfo],
        batch_header: BatchHeader<N_SNARKS>,
        blob_bytes: &[u8],
    ) -> Self {
        // A batch consists of at least one chunk.
        assert_ne!(
            unpadded_chunks.len(),
            0,
            "batch consists of at least one chunk"
        );

        // A batch consists of up to N_SNARKS number of chunks.
        assert!(
            unpadded_chunks.len() <= N_SNARKS,
            "batch consists of up to {N_SNARKS} number of chunks, but found {n_chunks}",
            n_chunks = unpadded_chunks.len()
        );

        // The last valid chunk will be used to pad the unpadded chunks.
        let mut padded_chunk = unpadded_chunks
            .last()
            .cloned()
            .expect("batch consists of at least one chunk");
        padded_chunk.is_padding = true;

        // Pad the unpadded chunks to collect exactly N_SNARKS number of chunks.
        let padded_chunks = unpadded_chunks
            .to_vec()
            .into_iter()
            .chain(repeat(padded_chunk))
            .take(N_SNARKS)
            .collect::<Vec<_>>();

        Self::construct(&padded_chunks, batch_header, blob_bytes)
    }

    /// Construct a [`BatchInfo`] given an ordered list of exactly `N_SNARKS` number of chunks.
    pub fn construct(
        padded_chunks: &[ChunkInfo],
        batch_header: BatchHeader<N_SNARKS>,
        blob_bytes: &[u8],
    ) -> Self {
        // We expect exactly N_SNARKS number of chunks.
        assert_eq!(
            padded_chunks.len(),
            N_SNARKS,
            "Expected {N_SNARKS} number of chunks, found {n_chunks}",
            n_chunks = padded_chunks.len(),
        );

        // The number of valid chunks is the first k chunks that are "not" padded.
        let num_valid_chunks = match padded_chunks
            .iter()
            .enumerate()
            .find(|(_index, chunk)| chunk.is_padding)
        {
            Some((index, _)) => index,
            None => N_SNARKS,
        };

        // A batch consists of at least one chunk.
        assert_ne!(num_valid_chunks, 0, "batch consists of at least one chunk",);

        // Sanity checks on the chunk infos.
        for window in padded_chunks.windows(2) {
            let (prev_chunk, curr_chunk) = (&window[0], &window[1]);
            assert_eq!(prev_chunk.chain_id, curr_chunk.chain_id,);
            if curr_chunk.is_padding {
                assert_eq!(curr_chunk.prev_state_root, prev_chunk.prev_state_root);
                assert_eq!(curr_chunk.post_state_root, prev_chunk.post_state_root);
                assert_eq!(curr_chunk.withdraw_root, prev_chunk.withdraw_root);
                assert_eq!(curr_chunk.data_hash, prev_chunk.data_hash);
                assert_eq!(curr_chunk.tx_bytes_hash(), prev_chunk.tx_bytes_hash(),);
            } else {
                assert_eq!(curr_chunk.prev_state_root, prev_chunk.post_state_root,);
            }
        }

        let batch_data = BatchData::<N_SNARKS>::new(num_valid_chunks, padded_chunks);
        let coeffs = get_coefficients(blob_bytes);
        let versioned_hash = get_versioned_hash(&coeffs);
        let point_evaluation_assignments =
            PointEvaluationAssignments::new(&batch_data, blob_bytes, versioned_hash);

        assert_eq!(
            batch_header.blob_data_proof[0],
            H256::from_slice(&point_evaluation_assignments.challenge.to_be_bytes()),
            "Expect provided BatchHeader's blob_data_proof field 0 to be correct"
        );
        assert_eq!(
            batch_header.blob_data_proof[1],
            H256::from_slice(&point_evaluation_assignments.evaluation.to_be_bytes()),
            "Expect provided BatchHeader's blob_data_proof field 1 to be correct"
        );
        assert_eq!(
            batch_header.blob_versioned_hash, versioned_hash,
            "Expect provided BatchHeader's blob_versioned_hash field to be correct"
        );

        let batch_hash = batch_header.batch_hash();

        log::info!(
            "batch hash {:?}, z {}, y {}, versioned hash {:x}",
            batch_hash,
            hex::encode(point_evaluation_assignments.challenge.to_be_bytes()),
            hex::encode(point_evaluation_assignments.evaluation.to_be_bytes()),
            versioned_hash,
        );

        Self {
            chain_id: padded_chunks[0].chain_id,
            num_valid_chunks,
            padded_chunks: padded_chunks.to_vec(),
            parent_state_root: padded_chunks[0].prev_state_root,
            state_root: padded_chunks[N_SNARKS - 1].post_state_root,
            withdraw_root: padded_chunks[N_SNARKS - 1].withdraw_root,
            batch_hash,
            point_evaluation_assignments,
            versioned_hash,
            batch_header,
            blob_bytes: blob_bytes.to_vec(),
        }
    }

    /// Return the blob polynomial and its evaluation at challenge
    pub fn point_evaluation_assignments(&self) -> PointEvaluationAssignments {
        self.point_evaluation_assignments.clone()
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

        // batchHash =
        //   keccak256(
        //     version ||
        //     batch_index ||
        //     l1_message_popped ||
        //     total_l1_message_popped ||
        //     batch_data_hash ||
        //     versioned_hash ||
        //     parent_batch_hash ||
        //     last_block_timestamp ||
        //     z ||
        //     y
        // )
        let batch_hash_preimage = self.batch_header.batch_hash_preimage();
        res.push(batch_hash_preimage);

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
        for chunk in self.padded_chunks.iter() {
            res.push(chunk.extract_hash_preimage());
        }

        // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
        let batch_data_hash_preimage = self
            .padded_chunks
            .iter()
            .take(self.num_valid_chunks)
            .flat_map(|x| x.data_hash.as_bytes().iter())
            .cloned()
            .collect();
        res.push(batch_data_hash_preimage);

        // This is the end of part where preimages to the keccak hashing function are of known
        // size. We now move to the part where the preimage is dynamic.
        //
        // These include:
        // - preimage for batch metadata
        // - preimage for each chunk's flattened L2 signed tx data
        // - preimage for the challenge digest
        let batch_data = BatchData::from(self);
        let dynamic_preimages = batch_data.preimages(self.versioned_hash);
        for dynamic_preimage in dynamic_preimages {
            res.push(dynamic_preimage);
        }

        res
    }

    /// Compute the public inputs for this circuit:
    /// - parent_state_root (hi, lo)
    /// - parent_batch_hash (hi, lo)
    /// - state_root (hi, lo)
    /// - batch_hash (hi, lo)
    /// - chain_id
    /// - withdraw_hash (hi, lo)
    pub(crate) fn instances_exclude_acc<F: Field>(&self) -> Vec<Vec<F>> {
        let mut res: Vec<F> = [
            self.parent_state_root,
            self.batch_header.parent_batch_hash,
            self.state_root,
            self.batch_hash,
        ]
        .map(|h| {
            let (hi, lo) = split_h256(h);
            vec![hi, lo]
        })
        .concat();

        res.push(F::from(self.chain_id));

        let (withdraw_root_hi, withdraw_root_lo) = split_h256(self.withdraw_root);
        res.extend_from_slice(&[withdraw_root_hi, withdraw_root_lo]);

        vec![res]
    }

    /// Return the batch header.
    pub fn batch_header(&self) -> BatchHeader<N_SNARKS> {
        self.batch_header
    }
}
