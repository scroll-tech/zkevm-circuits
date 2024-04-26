use crate::{
    aggregation::{interpolate, BLS_MODULUS},
    BatchHash, ChunkHash, MAX_AGG_SNARKS,
};

use eth_types::{ToBigEndian, H256, U256};
use ethers_core::{
    k256::sha2::{Digest, Sha256},
    utils::keccak256,
};
use halo2_proofs::{
    circuit::Value,
    halo2curves::{bls12_381::Scalar, bn256::Fr},
};
use itertools::Itertools;
use once_cell::sync::Lazy;
use revm_primitives::VERSIONED_HASH_VERSION_KZG;
use std::{
    iter::{once, repeat},
    sync::Arc,
};
use zkevm_circuits::util::Challenges;

/// The number of coefficients (BLS12-381 scalars) to represent the blob polynomial in evaluation
/// form.
pub const BLOB_WIDTH: usize = 4096;

/// The number of bytes to represent an unsigned 256 bit number.
pub const N_BYTES_U256: usize = 32;

/// The number data bytes we pack each BLS12-381 scalar into. The most-significant byte is 0.
pub const N_DATA_BYTES_PER_COEFFICIENT: usize = 31;

/// The number of rows to encode number of valid chunks (num_valid_snarks) in a batch, in the Blob
/// Data config. Since num_valid_chunks is u16, we use 2 bytes/rows.
pub const N_ROWS_NUM_CHUNKS: usize = 2;

/// The number of rows to encode the size of each chunk in a batch, in the Blob Data config.
/// chunk_size is u32, we use 4 bytes/rows.
pub const N_ROWS_CHUNK_SIZES: usize = MAX_AGG_SNARKS * 4;

/// The number of bytes that we can fit in a blob. Note that each coefficient is represented in 32
/// bytes, however, since those 32 bytes must represent a BLS12-381 scalar in its canonical form,
/// we explicitly set the most-significant byte to 0, effectively utilising only 31 bytes.
pub const N_BLOB_BYTES: usize = BLOB_WIDTH * N_DATA_BYTES_PER_COEFFICIENT;

/// The number of rows in Blob Data config's layout to represent the "blob metadata" section.
pub const N_ROWS_METADATA: usize = N_ROWS_NUM_CHUNKS + N_ROWS_CHUNK_SIZES;

/// The number of rows in Blob Data config's layout to represent the "chunk data" section.
pub const N_ROWS_DATA: usize = N_BLOB_BYTES - N_ROWS_METADATA;

/// The number of rows in Blob Data config's layout to represent the "digest rlc" section.
/// - metadata digest RLC (1 row)
/// - chunk_digests RLC for each chunk (MAX_AGG_SNARKS rows)
/// - blob versioned hash RLC (1 row)
/// - challenge digest RLC (1 row)
pub const N_ROWS_DIGEST_RLC: usize = 1 + MAX_AGG_SNARKS + 1 + 1;

/// The number of rows in Blob Data config's layout to represent the "digest bytes" section.
pub const N_ROWS_DIGEST_BYTES: usize = N_ROWS_DIGEST_RLC * N_BYTES_U256;

/// The total number of rows in "digest rlc" and "digest bytes" sections.
pub const N_ROWS_DIGEST: usize = N_ROWS_DIGEST_RLC + N_ROWS_DIGEST_BYTES;

/// The total number of rows used in Blob Data config's layout.
pub const N_ROWS_BLOB_DATA_CONFIG: usize = N_ROWS_METADATA + N_ROWS_DATA + N_ROWS_DIGEST;

/// KZG trusted setup
pub static KZG_TRUSTED_SETUP: Lazy<Arc<c_kzg::KzgSettings>> = Lazy::new(|| {
    Arc::new(
        c_kzg::KzgSettings::load_trusted_setup(
            &revm_primitives::kzg::G1_POINTS.0,
            &revm_primitives::kzg::G2_POINTS.0,
        )
        .expect("failed to load trusted setup"),
    )
});

/// Helper struct to generate witness for the Blob Data Config.
#[derive(Clone, Debug)]
pub struct BlobData {
    /// The number of valid chunks in the batch. This could be any number between:
    /// [1, MAX_AGG_SNARKS]
    pub num_valid_chunks: u16,
    /// The size of each chunk. The chunk size can be zero if:
    /// - The chunk is a padded chunk (not a valid chunk).
    /// - The chunk has no L2 transactions, but only L1 msg txs.
    pub chunk_sizes: [u32; MAX_AGG_SNARKS],
    /// Flattened L2 signed transaction data, for each chunk.
    ///
    /// Note that in BlobData struct, only `num_valid_chunks` number of chunks' bytes are supposed
    /// to be read (for witness generation). For simplicity, the last valid chunk's bytes are
    /// copied over for the padded chunks. The `chunk_data_digest` for padded chunks is the
    /// `chunk_data_digest` of the last valid chunk (from Aggregation Circuit's perspective).
    pub chunk_data: [Vec<u8>; MAX_AGG_SNARKS],
}

impl From<&BatchHash> for BlobData {
    fn from(batch_hash: &BatchHash) -> Self {
        Self::new(
            batch_hash.number_of_valid_chunks,
            &batch_hash.chunks_with_padding,
        )
    }
}

// If the chunk data is represented as a vector of u8's this implementation converts data from
// dynamic number of chunks into BlobData.
impl From<&Vec<Vec<u8>>> for BlobData {
    fn from(chunks: &Vec<Vec<u8>>) -> Self {
        let num_valid_chunks = chunks.len();
        assert!(num_valid_chunks > 0);
        assert!(num_valid_chunks <= MAX_AGG_SNARKS);

        let chunk_sizes: [u32; MAX_AGG_SNARKS] = chunks
            .iter()
            .map(|chunk| chunk.len() as u32)
            .chain(repeat(0))
            .take(MAX_AGG_SNARKS)
            .collect::<Vec<_>>()
            .try_into()
            .expect("we have MAX_AGG_SNARKS chunks");
        assert!(chunk_sizes.iter().sum::<u32>() <= N_ROWS_DATA as u32);

        let last_chunk_data = chunks.last().expect("last chunk exists");
        let chunk_data = chunks
            .iter()
            .chain(repeat(last_chunk_data))
            .take(MAX_AGG_SNARKS)
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .expect("we have MAX_AGG_SNARKS chunks");

        Self {
            num_valid_chunks: num_valid_chunks as u16,
            chunk_sizes,
            chunk_data,
        }
    }
}

impl Default for BlobData {
    fn default() -> Self {
        // default value corresponds to a batch with 1 chunk with no transactions
        Self::from(&vec![vec![]])
    }
}

fn kzg_to_versioned_hash(commitment: &c_kzg::KzgCommitment) -> H256 {
    let mut res = Sha256::digest(commitment.as_slice());
    res[0] = VERSIONED_HASH_VERSION_KZG;
    H256::from_slice(&res[..])
}

impl BlobData {
    pub(crate) fn new(num_valid_chunks: usize, chunks_with_padding: &[ChunkHash]) -> Self {
        assert!(num_valid_chunks > 0);
        assert!(num_valid_chunks <= MAX_AGG_SNARKS);

        // padded chunk has 0 size, valid chunk's size is the number of bytes consumed by the
        // flattened data from signed L2 transactions.
        let chunk_sizes: [u32; MAX_AGG_SNARKS] = chunks_with_padding
            .iter()
            .map(|chunk| {
                if chunk.is_padding {
                    0
                } else {
                    chunk.tx_bytes.len() as u32
                }
            })
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        assert!(chunk_sizes.iter().sum::<u32>() <= N_ROWS_DATA as u32);

        // chunk data of the "last valid chunk" is repeated over the padded chunks for simplicity
        // in calculating chunk_data_digest for those padded chunks. However, for the "chunk data"
        // section rows (self.to_data_rows()) we only consider `num_valid_chunks` chunks.
        let chunk_data = chunks_with_padding
            .iter()
            .map(|chunk| chunk.tx_bytes.to_vec())
            .collect::<Vec<Vec<u8>>>()
            .try_into()
            .unwrap();

        Self {
            num_valid_chunks: num_valid_chunks as u16,
            chunk_sizes,
            chunk_data,
        }
    }
}

impl BlobData {
    /// Get the versioned hash as per EIP-4844.
    pub(crate) fn get_versioned_hash(&self) -> H256 {
        let coefficients = self.get_coefficients();
        let blob = c_kzg::Blob::from_bytes(
            &coefficients
                .iter()
                .cloned()
                .flat_map(|coeff| coeff.to_be_bytes())
                .collect::<Vec<_>>(),
        )
        .expect("blob-coefficients to 4844 blob should succeed");
        let c = c_kzg::KzgCommitment::blob_to_kzg_commitment(&blob, &KZG_TRUSTED_SETUP)
            .expect("blob to kzg commitment should succeed");
        kzg_to_versioned_hash(&c)
    }

    /// Get the preimage of the challenge digest.
    pub(crate) fn get_challenge_digest_preimage(&self) -> Vec<u8> {
        let metadata_digest = keccak256(self.to_metadata_bytes());
        let chunk_digests = self.chunk_data.iter().map(keccak256);
        let blob_versioned_hash = self.get_versioned_hash();

        // preimage =
        //     metadata_digest ||
        //     chunk[0].chunk_data_digest || ...
        //     chunk[MAX_AGG_SNARKS-1].chunk_data_digest ||
        //     blob_versioned_hash
        //
        // where chunk_data_digest for a padded chunk is set equal to the "last valid chunk"'s
        // chunk_data_digest.
        metadata_digest
            .into_iter()
            .chain(chunk_digests.flatten())
            .chain(blob_versioned_hash.to_fixed_bytes())
            .collect::<Vec<_>>()
    }

    /// Compute the challenge digest from blob bytes.
    pub(crate) fn get_challenge_digest(&self) -> U256 {
        let challenge_digest = keccak256(self.get_challenge_digest_preimage());
        U256::from_big_endian(&challenge_digest)
    }

    /// Get the BLOB_WIDTH number of scalar field elements, as 32-bytes unsigned integers.
    pub(crate) fn get_coefficients(&self) -> [U256; BLOB_WIDTH] {
        let mut coefficients = [[0u8; N_BYTES_U256]; BLOB_WIDTH];

        // We only consider the data from `valid` chunks and ignore the padded chunks.
        let metadata_bytes = self.to_metadata_bytes();
        let blob_bytes = metadata_bytes.iter().chain(
            self.chunk_data
                .iter()
                .take(self.num_valid_chunks as usize)
                .flatten(),
        );

        for (i, &byte) in blob_bytes.enumerate() {
            coefficients[i / 31][1 + (i % 31)] = byte;
        }

        coefficients.map(|coeff| U256::from_big_endian(&coeff))
    }

    /// Get the list of preimages that need to go through the keccak hashing function, and
    /// eventually required to be checked for the consistency of blob's metadata, its chunks' bytes
    /// and the final blob preimage.
    pub fn preimages(&self) -> Vec<Vec<u8>> {
        let mut preimages = Vec::with_capacity(2 + MAX_AGG_SNARKS);

        // metadata
        preimages.push(self.to_metadata_bytes());

        // each valid chunk's data
        for chunk in self.chunk_data.iter().take(self.num_valid_chunks as usize) {
            preimages.push(chunk.to_vec());
        }

        // preimage for challenge digest
        preimages.push(self.get_challenge_digest_preimage());

        preimages
    }
}

impl BlobData {
    /// Get the witness rows for assignment to the BlobDataConfig.
    pub(crate) fn to_rows(&self, challenge: Challenges<Value<Fr>>) -> Vec<BlobDataRow<Fr>> {
        let metadata_rows = self.to_metadata_rows(challenge);
        assert_eq!(metadata_rows.len(), N_ROWS_METADATA);

        let data_rows = self.to_data_rows(challenge);
        assert_eq!(data_rows.len(), N_ROWS_DATA);

        let digest_rows = self.to_digest_rows(challenge);
        assert_eq!(digest_rows.len(), N_ROWS_DIGEST);

        metadata_rows
            .into_iter()
            .chain(data_rows)
            .chain(digest_rows)
            .collect::<Vec<BlobDataRow<Fr>>>()
    }

    /// Get the blob bytes that encode the batch's metadata.
    ///
    /// metadata_bytes =
    ///     be_bytes(num_valid_chunks) ||
    ///     be_bytes(chunks[0].chunk_size) || ...
    ///     be_bytes(chunks[MAX_AGG_SNARKS-1].chunk_size)
    ///
    /// where:
    /// - chunk_size of a padded chunk is 0
    /// - num_valid_chunks is u16
    /// - each chunk_size is u32
    fn to_metadata_bytes(&self) -> Vec<u8> {
        self.num_valid_chunks
            .to_be_bytes()
            .into_iter()
            .chain(
                self.chunk_sizes
                    .iter()
                    .flat_map(|chunk_size| chunk_size.to_be_bytes()),
            )
            .collect()
    }

    /// Get the witness rows for the "metadata" section of Blob data config.
    fn to_metadata_rows(&self, challenge: Challenges<Value<Fr>>) -> Vec<BlobDataRow<Fr>> {
        // metadata bytes.
        let bytes = self.to_metadata_bytes();

        // accumulators represent the runnin linear combination of bytes.
        let accumulators_iter = self
            .num_valid_chunks
            .to_be_bytes()
            .into_iter()
            .scan(0u64, |acc, x| {
                *acc = *acc * 256 + (x as u64);
                Some(*acc)
            })
            .chain(self.chunk_sizes.into_iter().flat_map(|chunk_size| {
                chunk_size.to_be_bytes().into_iter().scan(0u64, |acc, x| {
                    *acc = *acc * 256 + (x as u64);
                    Some(*acc)
                })
            }));

        // digest_rlc is set only for the last row in the "metadata" section, and it denotes the
        // RLC of the metadata_digest bytes.
        let digest_rlc_iter = {
            let digest = keccak256(&bytes);
            let digest_rlc = digest.iter().fold(Value::known(Fr::zero()), |acc, &x| {
                acc * challenge.evm_word() + Value::known(Fr::from(x as u64))
            });
            repeat(Value::known(Fr::zero()))
                .take(N_ROWS_METADATA - 1)
                .chain(once(digest_rlc))
        };

        // preimage_rlc is the running RLC over bytes in the "metadata" section.
        let preimage_rlc_iter = bytes.iter().scan(Value::known(Fr::zero()), |acc, &x| {
            *acc = *acc * challenge.keccak_input() + Value::known(Fr::from(x as u64));
            Some(*acc)
        });

        bytes
            .iter()
            .zip_eq(accumulators_iter)
            .zip_eq(preimage_rlc_iter)
            .zip_eq(digest_rlc_iter)
            .enumerate()
            .map(
                |(i, (((&byte, accumulator), preimage_rlc), digest_rlc))| BlobDataRow {
                    byte,
                    accumulator,
                    preimage_rlc,
                    digest_rlc,
                    // we set boundary on the last row of the "metadata" section to enable a lookup
                    // to the keccak table.
                    is_boundary: i == bytes.len() - 1,
                    ..Default::default()
                },
            )
            .collect()
    }

    /// Get the witness rows for the "chunk data" section of Blob data config.
    fn to_data_rows(&self, challenge: Challenges<Value<Fr>>) -> Vec<BlobDataRow<Fr>> {
        // consider only the `valid` chunks while constructing rows for the "chunk data" section.
        self.chunk_data
            .iter()
            .take(self.num_valid_chunks as usize)
            .enumerate()
            .flat_map(|(i, bytes)| {
                let chunk_idx = (i + 1) as u64;
                let chunk_size = bytes.len();
                let chunk_digest = keccak256(bytes);
                let digest_rlc = chunk_digest
                    .iter()
                    .fold(Value::known(Fr::zero()), |acc, &byte| {
                        acc * challenge.evm_word() + Value::known(Fr::from(byte as u64))
                    });
                bytes.iter().enumerate().scan(
                    (0u64, Value::known(Fr::zero())),
                    move |acc, (j, &byte)| {
                        acc.0 += 1;
                        acc.1 =
                            acc.1 * challenge.keccak_input() + Value::known(Fr::from(byte as u64));
                        Some(BlobDataRow {
                            byte,
                            accumulator: acc.0,
                            chunk_idx,
                            is_boundary: j == chunk_size - 1,
                            is_padding: false,
                            preimage_rlc: acc.1,
                            digest_rlc: if j == chunk_size - 1 {
                                digest_rlc
                            } else {
                                Value::known(Fr::zero())
                            },
                        })
                    },
                )
            })
            .chain(repeat(BlobDataRow::padding_row()))
            .take(N_ROWS_DATA)
            .collect()
    }

    /// Get the witness rows for both "digest rlc" and "digest bytes" sections of Blob data config.
    fn to_digest_rows(&self, challenge: Challenges<Value<Fr>>) -> Vec<BlobDataRow<Fr>> {
        let zero = Value::known(Fr::zero());

        // metadata
        let metadata_bytes = self.to_metadata_bytes();
        let metadata_digest = keccak256(metadata_bytes);
        let metadata_digest_rlc = metadata_digest.iter().fold(zero, |acc, &byte| {
            acc * challenge.evm_word() + Value::known(Fr::from(byte as u64))
        });

        // chunk data
        // Note: here we don't restrict to considering only `valid` chunks, as the
        // `chunk_data_digest` gets repeated for the padded chunks, copying the last valid chunk's
        // `chunk_data_digest`.
        let (chunk_digests, chunk_digest_rlcs): (Vec<[u8; 32]>, Vec<Value<Fr>>) = self
            .chunk_data
            .iter()
            .map(|chunk| {
                let digest = keccak256(chunk);
                let digest_rlc = digest.iter().fold(zero, |acc, &byte| {
                    acc * challenge.evm_word() + Value::known(Fr::from(byte as u64))
                });
                (digest, digest_rlc)
            })
            .unzip();

        // challenge digest
        let challenge_digest_preimage = self.get_challenge_digest_preimage();
        let challenge_digest_preimage_rlc =
            challenge_digest_preimage.iter().fold(zero, |acc, &byte| {
                acc * challenge.keccak_input() + Value::known(Fr::from(byte as u64))
            });
        let challenge_digest = keccak256(&challenge_digest_preimage);
        let challenge_digest_rlc = challenge_digest.iter().fold(zero, |acc, &byte| {
            acc * challenge.evm_word() + Value::known(Fr::from(byte as u64))
        });

        // blob versioned hash
        let versioned_hash = self.get_versioned_hash();
        let versioned_hash_rlc = versioned_hash.as_bytes().iter().fold(zero, |acc, &byte| {
            acc * challenge.evm_word() + Value::known(Fr::from(byte as u64))
        });

        // - metadata digest rlc
        // - chunks[i].chunk_data_digest rlc for each chunk
        // - versioned hash rlc
        // - challenge digest rlc
        // - metadata digest bytes
        // - chunks[i].chunk_data_digest bytes for each chunk
        // - versioned hash bytes
        // - challenge digest bytes
        once(BlobDataRow {
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: metadata_digest_rlc,
            // this is_padding assignment does not matter as we have already crossed the "chunk
            // data" section. This assignment to 1 is simply to allow the custom gate to check:
            // - padding transitions from 0 -> 1 only once.
            is_padding: true,
            ..Default::default()
        })
        .chain(
            chunk_digest_rlcs
                .iter()
                .zip_eq(self.chunk_sizes.iter())
                .enumerate()
                .map(|(i, (&digest_rlc, &chunk_size))| BlobDataRow {
                    preimage_rlc: Value::known(Fr::zero()),
                    digest_rlc,
                    chunk_idx: (i + 1) as u64,
                    accumulator: chunk_size as u64,
                    ..Default::default()
                }),
        )
        // versioned hash RLC
        .chain(once(BlobDataRow {
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: versioned_hash_rlc,
            ..Default::default()
        }))
        .chain(once(BlobDataRow {
            preimage_rlc: challenge_digest_preimage_rlc,
            digest_rlc: challenge_digest_rlc,
            accumulator: 32 * (MAX_AGG_SNARKS + 1 + 1) as u64,
            is_boundary: true,
            ..Default::default()
        }))
        .chain(metadata_digest.iter().map(|&byte| BlobDataRow {
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: Value::known(Fr::zero()),
            byte,
            ..Default::default()
        }))
        .chain(chunk_digests.iter().flat_map(|digest| {
            digest.iter().map(|&byte| BlobDataRow {
                preimage_rlc: Value::known(Fr::zero()),
                digest_rlc: Value::known(Fr::zero()),
                byte,
                ..Default::default()
            })
        }))
        // bytes of versioned hash
        .chain(versioned_hash.as_bytes().iter().map(|&byte| BlobDataRow {
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: Value::known(Fr::zero()),
            byte,
            ..Default::default()
        }))
        .chain(challenge_digest.iter().map(|&byte| BlobDataRow {
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: Value::known(Fr::zero()),
            byte,
            ..Default::default()
        }))
        .collect()
    }
}

#[derive(Clone, Debug)]
pub struct BlobAssignments {
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

impl Default for BlobAssignments {
    fn default() -> Self {
        Self {
            challenge: U256::default(),
            challenge_digest: U256::default(),
            evaluation: U256::default(),
            coefficients: [U256::default(); BLOB_WIDTH],
        }
    }
}

impl From<&BlobData> for BlobAssignments {
    fn from(blob: &BlobData) -> Self {
        // blob polynomial in evaluation form.
        //
        // also termed P(x)
        let coefficients = blob.get_coefficients();
        let coefficients_as_scalars = coefficients.map(|coeff| Scalar::from_raw(coeff.0));

        // challenge := challenge_digest % BLS_MODULUS
        //
        // also termed z
        let challenge_digest = blob.get_challenge_digest();
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

/// Witness row to the Blob Data Config.
#[derive(Clone, Copy, Default, Debug)]
pub struct BlobDataRow<Fr> {
    /// Byte value at this row.
    pub byte: u8,
    /// Multi-purpose accumulator value.
    pub accumulator: u64,
    /// The chunk index we are currently traversing.
    pub chunk_idx: u64,
    /// Whether this marks the end of a chunk.
    pub is_boundary: bool,
    /// Whether the row represents right-padded 0s to the blob data.
    pub is_padding: bool,
    /// A running accumulator of RLC of preimages.
    pub preimage_rlc: Value<Fr>,
    /// RLC of the digest.
    pub digest_rlc: Value<Fr>,
}

impl BlobDataRow<Fr> {
    fn padding_row() -> Self {
        Self {
            is_padding: true,
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: Value::known(Fr::zero()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "only required for logging challenge digest"]
    fn log_challenge() {
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
                "max number of chunkks all non-empty",
                (0..MAX_AGG_SNARKS)
                    .map(|i| (10u8..11 + u8::try_from(i).unwrap()).collect())
                    .collect(),
            ),
            ("single chunk blob full", vec![vec![123; N_ROWS_DATA]]),
            (
                "multiple chunks blob full",
                vec![vec![123; 1111], vec![231; N_ROWS_DATA - 1111]],
            ),
            (
                "max number of chunks only last one non-empty not full blob",
                repeat(vec![])
                    .take(MAX_AGG_SNARKS - 1)
                    .chain(once(vec![132; N_ROWS_DATA - 1111]))
                    .collect(),
            ),
            (
                "max number of chunks only last one non-empty full blob",
                repeat(vec![])
                    .take(MAX_AGG_SNARKS - 1)
                    .chain(once(vec![132; N_ROWS_DATA]))
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
            let blob: BlobData = tcase.into();
            let blob_assignments = BlobAssignments::from(&blob);
            println!(
                "{:60}: challenge (z) = {:0>64x}, evaluation (y) = {:0>64x}",
                annotation, blob_assignments.challenge, blob_assignments.evaluation
            );
        }
    }

    #[test]
    fn default_blob_data() {
        let mut default_metadata = [0u8; N_ROWS_METADATA];
        default_metadata[1] = 1;
        let default_metadata_digest = keccak256(default_metadata);
        let default_chunk_digests = [keccak256([]); MAX_AGG_SNARKS];

        let default_blob = BlobData::default();
        let versioned_hash = default_blob.get_versioned_hash();
        assert_eq!(
            default_blob.get_challenge_digest(),
            U256::from(keccak256(
                default_metadata_digest
                    .into_iter()
                    .chain(default_chunk_digests.into_iter().flatten())
                    .chain(versioned_hash.to_fixed_bytes())
                    .collect::<Vec<u8>>()
            )),
        )
    }

    #[test]
    fn coefficients_endianness() {
        // Check that the blob bytes are being packed into coefficients in big endian order.
        let coefficients = BlobData::default().get_coefficients();

        assert_eq!(coefficients[0], U256::one() << 232);
        assert_eq!(coefficients[1..], vec![U256::zero(); BLOB_WIDTH - 1]);
    }
}
