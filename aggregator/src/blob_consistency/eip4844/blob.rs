use super::{get_coefficients, interpolate, BLS_MODULUS};
use crate::BatchData;
use eth_types::{H256, U256};
use halo2_proofs::halo2curves::bls12_381::Scalar;

/// The number of coefficients (BLS12-381 scalars) to represent the blob polynomial in evaluation
/// form.
pub const BLOB_WIDTH: usize = 4096;

#[derive(Clone, Debug)]
pub struct PointEvaluationAssignments {
    /// The random challenge scalar z.
    pub challenge: U256,
    /// The 32-bytes keccak digest for the challenge. We have the relation:
    /// - challenge := challenge_digest % BLS_MODULUS.
    pub challenge_digest: U256,
    /// The evaluation of the blob polynomial at challenge.
    pub evaluation: U256,
    /// The blob polynomial represented in evaluation form.
    pub coefficients: [U256; BLOB_WIDTH],
}

impl Default for PointEvaluationAssignments {
    fn default() -> Self {
        Self {
            challenge: U256::default(),
            challenge_digest: U256::default(),
            evaluation: U256::default(),
            coefficients: [U256::default(); BLOB_WIDTH],
        }
    }
}

impl PointEvaluationAssignments {
    /// Construct the point evaluation assignments.
    pub fn new<const N_SNARKS: usize>(
        batch_data: &BatchData<N_SNARKS>,
        blob_bytes: &[u8],
        versioned_hash: H256,
    ) -> Self {
        // blob polynomial in evaluation form.
        //
        // also termed P(x)
        let coefficients = get_coefficients(blob_bytes);
        let coefficients_as_scalars = coefficients.map(|coeff| Scalar::from_raw(coeff.0));

        // challenge := challenge_digest % BLS_MODULUS
        //
        // also termed z
        let challenge_digest = batch_data.get_challenge_digest(versioned_hash);
        let (_, challenge) = challenge_digest.div_mod(*BLS_MODULUS);

        // y = P(z)
        let evaluation = U256::from_little_endian(
            &interpolate(Scalar::from_raw(challenge.0), &coefficients_as_scalars).to_bytes(),
        );

        Self {
            challenge,
            challenge_digest,
            evaluation,
            coefficients,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob_consistency::eip4844::{get_blob_bytes, get_versioned_hash},
        BatchHash, ChunkInfo, MAX_AGG_SNARKS,
    };
    use ethers_core::utils::keccak256;
    use std::iter::{once, repeat};

    #[test]
    #[ignore = "only required for logging challenge digest"]
    fn log_challenge() {
        let n_rows_data = BatchData::<MAX_AGG_SNARKS>::n_rows_data();

        for (annotation, tcase) in [
            ("single empty chunk", vec![vec![]]),
            ("single non-empty chunk", vec![vec![1, 2, 3]]),
            ("multiple empty chunks", vec![vec![], vec![]]),
            (
                "multiple non-empty chunks",
                vec![vec![1, 2, 3], vec![7, 8, 9]],
            ),
            (
                "empty chunk followed by non-empty chunk",
                vec![vec![], vec![1, 2, 3]],
            ),
            (
                "non-empty chunk followed by empty chunk",
                vec![vec![7, 8, 9], vec![]],
            ),
            (
                "max number of chunks all empty",
                vec![vec![]; MAX_AGG_SNARKS],
            ),
            (
                "max number of chunks all non-empty",
                (0..MAX_AGG_SNARKS)
                    .map(|i| (10u8..11 + u8::try_from(i).unwrap()).collect())
                    .collect(),
            ),
            ("single chunk blob full", vec![vec![123; n_rows_data]]),
            (
                "multiple chunks blob full",
                vec![vec![123; 1111], vec![231; n_rows_data - 1111]],
            ),
            (
                "max number of chunks only last one non-empty not full blob",
                repeat(vec![])
                    .take(MAX_AGG_SNARKS - 1)
                    .chain(once(vec![132; n_rows_data - 1111]))
                    .collect(),
            ),
            (
                "max number of chunks only last one non-empty full blob",
                repeat(vec![])
                    .take(MAX_AGG_SNARKS - 1)
                    .chain(once(vec![132; n_rows_data]))
                    .collect(),
            ),
            (
                "max number of chunks but last is empty",
                repeat(vec![111; 100])
                    .take(MAX_AGG_SNARKS - 1)
                    .chain(once(vec![]))
                    .collect(),
            ),
        ]
        .iter()
        {
            let batch_header = crate::batch::BatchHeader {
                version: 3,
                batch_index: 6789,
                l1_message_popped: 101,
                total_l1_message_popped: 10101,
                parent_batch_hash: H256::repeat_byte(1),
                last_block_timestamp: 192837,
                ..Default::default()
            };
            let batch_data: BatchData<MAX_AGG_SNARKS> = tcase.into();
            let batch_bytes = batch_data.get_batch_data_bytes();
            let blob_bytes = get_blob_bytes(&batch_bytes);
            let coeffs = get_coefficients(&blob_bytes);
            let versioned_hash = get_versioned_hash(&coeffs);
            let chunks_without_padding = ChunkInfo::mock_chunk_infos(tcase);
            let batch_hash = BatchHash::<MAX_AGG_SNARKS>::construct_with_unpadded(
                &chunks_without_padding,
                batch_header,
                &blob_bytes,
            );
            let point_evaluation_assignments =
                PointEvaluationAssignments::new(&batch_data, &blob_bytes, versioned_hash);
            println!(
                "[[ {:60} ]]\nchallenge (z) = {:0>64x}, evaluation (y) = {:0>64x}, versioned hash = {:0>64x}, batch_hash = {:0>64x}\n\n",
                annotation,
                point_evaluation_assignments.challenge,
                point_evaluation_assignments.evaluation,
                versioned_hash,
                batch_hash.current_batch_hash,
            );
        }
    }

    #[test]
    fn default_batch_data() {
        let mut default_metadata = [0u8; BatchData::<MAX_AGG_SNARKS>::n_rows_metadata()];
        default_metadata[1] = 1;
        let default_metadata_digest = keccak256(default_metadata);
        let default_chunk_digests = [keccak256([]); MAX_AGG_SNARKS];

        let default_batch = BatchData::<MAX_AGG_SNARKS>::default();
        let batch_bytes = default_batch.get_batch_data_bytes();
        let blob_bytes = get_blob_bytes(&batch_bytes);
        let coeffs = get_coefficients(&blob_bytes);
        let versioned_hash = get_versioned_hash(&coeffs);
        let point_evaluation_assignments =
            PointEvaluationAssignments::new(&default_batch, &blob_bytes, versioned_hash);
        let versioned_hash = get_versioned_hash(&point_evaluation_assignments.coefficients);
        assert_eq!(
            default_batch.get_challenge_digest(versioned_hash),
            U256::from(keccak256(
                default_metadata_digest
                    .into_iter()
                    .chain(default_chunk_digests.into_iter().flatten())
                    .chain(versioned_hash.to_fixed_bytes())
                    .collect::<Vec<u8>>()
            )),
        )
    }
}
