//! This module implements related functions that aggregates public inputs of many chunks into a
//! single one.

use eth_types::{ToBigEndian, H256};
use ethers_core::utils::keccak256;
use gadgets::{util::split_h256, Field};
use serde::{Deserialize, Serialize};

use crate::{
    blob::{BatchData, PointEvaluationAssignments},
    chunk::ChunkInfo,
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
    pub fn construct_from_chunks(
        version: u8,
        batch_index: u64,
        l1_message_popped: u64,
        total_l1_message_popped: u64,
        parent_batch_hash: H256,
        last_block_timestamp: u64,
        chunks: &[ChunkInfo],
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
        let point_evaluation_assignments = PointEvaluationAssignments::from(&batch_data);

        Self {
            version,
            batch_index,
            l1_message_popped,
            total_l1_message_popped,
            parent_batch_hash,
            last_block_timestamp,
            data_hash: batch_data_hash.into(),
            blob_versioned_hash: batch_data.get_versioned_hash(),
            blob_data_proof: [
                H256::from_slice(&point_evaluation_assignments.challenge.to_be_bytes()),
                H256::from_slice(&point_evaluation_assignments.evaluation.to_be_bytes()),
            ],
        }
    }

    /// Returns the batch hash as per BatchHeaderV3.
    pub fn batch_hash(&self) -> H256 {
        // the current batch hash is build as
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
        let batch_hash_preimage = [
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
        .concat();
        keccak256(batch_hash_preimage).into()
    }
}

#[derive(Default, Debug, Clone)]
/// A batch is a set of N_SNARKS num of continuous chunks
/// - the first k chunks are from real traces
/// - the last (#N_SNARKS-k) chunks are from empty traces
/// A BatchHash consists of 2 hashes.
/// - batchHash := keccak256(version || batch_index || l1_message_popped || total_l1_message_popped ||
///   batch_data_hash || versioned_hash || parent_batch_hash || last_block_timestamp || z || y)
/// - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
pub struct BatchHash<const N_SNARKS: usize> {
    /// Chain ID of the network.
    pub(crate) chain_id: u64,
    /// chunks with padding.
    /// - the first [0..number_of_valid_chunks) are real ones
    /// - the last [number_of_valid_chunks, N_SNARKS) are padding
    pub(crate) chunks_with_padding: Vec<ChunkInfo>,
    /// the state root of the parent batch
    pub(crate) parent_state_root: H256,
    /// the state root of the current batch
    pub(crate) current_state_root: H256,
    /// the withdraw root of the current batch
    pub(crate) current_withdraw_root: H256,
    /// The batch data hash:
    /// - keccak256([chunk.hash for chunk in batch])
    pub(crate) data_hash: H256,
    /// the current batch hash is calculated as:
    /// - keccak256( version || batch_index || l1_message_popped || total_l1_message_popped ||
    ///   batch_data_hash || versioned_hash || parent_batch_hash || last_block_timestamp ||
    ///   z || y)
    pub(crate) current_batch_hash: H256,
    /// The number of chunks that contain meaningful data, i.e. not padded chunks.
    pub(crate) number_of_valid_chunks: usize,
    /// 4844 point evaluation check related assignments.
    pub(crate) point_evaluation_assignments: PointEvaluationAssignments,
    /// The 4844 versioned hash for the blob.
    pub(crate) versioned_hash: H256,
    /// The context batch header
    pub(crate) batch_header: BatchHeader<N_SNARKS>,
}

impl<const N_SNARKS: usize> BatchHash<N_SNARKS> {
    /// Build Batch hash from an ordered list of chunks. Will pad if needed
    pub fn construct_with_unpadded(
        chunks: &[ChunkInfo],
        batch_header: BatchHeader<N_SNARKS>,
    ) -> Self {
        assert_ne!(chunks.len(), 0);
        assert!(chunks.len() <= N_SNARKS);
        let mut chunks_with_padding = chunks.to_vec();
        if chunks.len() < N_SNARKS {
            log::warn!(
                "chunk len({}) < N_SNARKS({}), padding...",
                chunks.len(),
                N_SNARKS
            );
            let last_chunk = chunks.last().unwrap();
            let mut padding_chunk = last_chunk.clone();
            padding_chunk.is_padding = true;
            chunks_with_padding
                .extend(std::iter::repeat(padding_chunk).take(N_SNARKS - chunks.len()));
        }
        Self::construct(&chunks_with_padding, batch_header)
    }

    /// Build Batch hash from an ordered list of #N_SNARKS of chunks.
    pub fn construct(
        chunks_with_padding: &[ChunkInfo],
        batch_header: BatchHeader<N_SNARKS>,
    ) -> Self {
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
            .flat_map(|chunk_info| chunk_info.data_hash.0.iter())
            .cloned()
            .collect::<Vec<_>>();
        let batch_data_hash = keccak256(preimage);

        assert_eq!(
            batch_header.data_hash,
            H256::from_slice(&batch_data_hash),
            "Expect provided BatchHeader's data_hash field to be correct"
        );

        let batch_data = BatchData::<N_SNARKS>::new(number_of_valid_chunks, chunks_with_padding);
        let point_evaluation_assignments = PointEvaluationAssignments::from(&batch_data);

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

        let versioned_hash = batch_data.get_versioned_hash();

        assert_eq!(
            batch_header.blob_versioned_hash, versioned_hash,
            "Expect provided BatchHeader's blob_versioned_hash field to be correct"
        );

        let current_batch_hash = batch_header.batch_hash();

        log::info!(
            "batch hash {:?}, datahash {}, z {}, y {}, versioned hash {:x}",
            current_batch_hash,
            hex::encode(batch_data_hash),
            hex::encode(point_evaluation_assignments.challenge.to_be_bytes()),
            hex::encode(point_evaluation_assignments.evaluation.to_be_bytes()),
            versioned_hash,
        );

        Self {
            chain_id: chunks_with_padding[0].chain_id,
            chunks_with_padding: chunks_with_padding.to_vec(),
            parent_state_root: chunks_with_padding[0].prev_state_root,
            current_state_root: chunks_with_padding[N_SNARKS - 1].post_state_root,
            current_withdraw_root: chunks_with_padding[N_SNARKS - 1].withdraw_root,
            data_hash: batch_data_hash.into(),
            current_batch_hash,
            number_of_valid_chunks,
            point_evaluation_assignments,
            versioned_hash,
            batch_header,
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
        let batch_hash_preimage = [
            [self.batch_header.version].as_ref(),
            self.batch_header.batch_index.to_be_bytes().as_ref(),
            self.batch_header.l1_message_popped.to_be_bytes().as_ref(),
            self.batch_header
                .total_l1_message_popped
                .to_be_bytes()
                .as_ref(),
            self.data_hash.as_bytes(),
            self.versioned_hash.as_bytes(),
            self.batch_header.parent_batch_hash.as_bytes(),
            self.batch_header
                .last_block_timestamp
                .to_be_bytes()
                .as_ref(),
            self.point_evaluation_assignments
                .challenge
                .to_be_bytes()
                .as_ref(),
            self.point_evaluation_assignments
                .evaluation
                .to_be_bytes()
                .as_ref(),
        ]
        .concat();
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
        // - preimage for batch metadata
        // - preimage for each chunk's flattened L2 signed tx data
        // - preimage for the challenge digest
        let batch_data = BatchData::from(self);
        let dynamic_preimages = batch_data.preimages();
        for dynamic_preimage in dynamic_preimages {
            res.push(dynamic_preimage);
        }

        res
    }

    /// Compute the public inputs for this circuit:
    /// parent_state_root
    /// parent_batch_hash
    /// current_state_root
    /// current_batch_hash
    /// chain_id
    /// current_withdraw_hash
    pub(crate) fn instances_exclude_acc<F: Field>(&self) -> Vec<Vec<F>> {
        let mut res: Vec<F> = [
            self.parent_state_root,
            self.batch_header.parent_batch_hash,
            self.current_state_root,
            self.current_batch_hash,
        ]
        .map(|h| {
            let (hi, lo) = split_h256(h);
            vec![hi, lo]
        })
        .concat();

        res.push(F::from(self.chain_id));
        let (withdraw_hi, withdraw_lo) = split_h256(self.current_withdraw_root);
        res.extend_from_slice(vec![withdraw_hi, withdraw_lo].as_slice());

        vec![res]
    }

    /// ...
    pub fn batch_header(&self) -> BatchHeader<N_SNARKS> {
        self.batch_header
    }
}
