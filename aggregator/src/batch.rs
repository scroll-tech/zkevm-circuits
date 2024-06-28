//! This module implements related functions that aggregates public inputs of many chunks into a
//! single one.

use bitstream_io::Primitive;
use eth_types::{ToBigEndian, H256};
use ethers_core::utils::keccak256;
use gadgets::Field;

use crate::{
    blob::{BatchData, PointEvaluationAssignments, N_BYTES_U256},
    chunk::ChunkInfo,
    util::hi_lo_from_h256,
};

#[derive(Default, Debug, Clone)]
/// Batch header provides additional fields from the context (within recursion)
/// for constructing the preimage of the batch hash.
pub struct BatchHeader {
    /// the batch version
    pub(crate) version: u8,
    /// the index of the batch
    pub(crate) batch_index: u64,
    /// Number of L1 messages popped in the batch
    pub(crate) l1_message_popped: u64,
    /// Number of total L1 messages popped after the batch
    pub(crate) total_l1_message_popped: u64,
    /// The data hash of the batch
    pub(crate) data_hash: H256,
    /// The versioned hash of the blob with this batch's data
    pub(crate) blob_versioned_hash: H256,
    /// The parent batch hash
    pub(crate) parent_batch_hash: H256,
    /// The timestamp of the last block in this batch
    pub(crate) last_block_timestamp: u64,
    /// The blob data proof: z (32), y (32)
    pub(crate) blob_data_proof: [H256; 2],
}

#[derive(Default, Debug, Clone)]
/// A batch is a set of N_SNARKS num of continuous chunks
/// - the first k chunks are from real traces
/// - the last (#N_SNARKS-k) chunks are from empty traces
/// A BatchHash consists of 2 hashes.
/// - batch_pi_hash   := keccak(chain_id || chunk_0.prev_state_root || chunk_k-1.post_state_root ||
///   chunk_k-1.withdraw_root || batch_data_hash || z || y || versioned_hash)
/// 
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
    pub(crate) batch_header: BatchHeader,
}

impl<const N_SNARKS: usize> BatchHash<N_SNARKS> {
    /// Build Batch hash from an ordered list of chunks. Will pad if needed
    pub fn construct_with_unpadded(chunks: &[ChunkInfo], batch_header: BatchHeader) -> Self {
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
    pub fn construct(chunks_with_padding: &[ChunkInfo], batch_header: BatchHeader) -> Self {
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

        // Check against context in batch header
        assert_eq!(batch_data_hash, batch_header.data_hash.as_bytes(), "chunk-derived data hash is the same as field in batch header");

        let batch_data = BatchData::<N_SNARKS>::new(number_of_valid_chunks, chunks_with_padding);
        let point_evaluation_assignments = PointEvaluationAssignments::from(&batch_data);

        // Check against context in batch header
        assert_eq!(
            point_evaluation_assignments.challenge.to_be_bytes(),
            batch_header.blob_data_proof[0].as_bytes(),
            "chunk-derived z is the same as field in batch header"
        );
        assert_eq!(
            point_evaluation_assignments.evaluation.to_be_bytes(),
            batch_header.blob_data_proof[1].as_bytes(),
            "chunk-derived y is the same as field in batch header"
        );

        let versioned_hash = batch_data.get_versioned_hash();

        // Check against context in batch header
        assert_eq!(
            versioned_hash,
            batch_header.blob_versioned_hash,
            "chunk-derived versioned hash is the same as field in batch header"
        );

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
            vec![batch_header.version].as_slice(),
            batch_header.batch_index.to_be_bytes().as_ref(),
            batch_header.l1_message_popped.to_be_bytes().as_ref(),
            batch_header.total_l1_message_popped.to_be_bytes().as_ref(),
            batch_data_hash.as_slice(),
            versioned_hash.as_bytes(),
            batch_header.parent_batch_hash.as_bytes(),
            batch_header.last_block_timestamp.to_be_bytes().as_ref(),
            point_evaluation_assignments
                .challenge
                .to_be_bytes()
                .as_ref(),
            point_evaluation_assignments
                .evaluation
                .to_be_bytes()
                .as_ref(),
        ].concat();
        let current_batch_hash: H256 = keccak256(batch_hash_preimage).into();

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
            batch_header.l1_message_popped.to_be_bytes().as_ref(),
            batch_header.total_l1_message_popped.to_be_bytes().as_ref(),
            self.data_hash.as_bytes(),
            self.versioned_hash.as_bytes(),
            batch_header.parent_batch_hash.as_bytes(),
            batch_header.last_block_timestamp.to_be_bytes().as_ref(),
            point_evaluation_assignments
                .challenge
                .to_be_bytes()
                .as_ref(),
            point_evaluation_assignments
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
        .map(|h| hi_lo_from_h256(h)).concat();
        
        res.push(F::from(self.chain_id as u64));
        res.extend_from_slice(hi_lo_from_h256(self.current_withdraw_root).as_slice());
        
        vec![res]
    }
}
