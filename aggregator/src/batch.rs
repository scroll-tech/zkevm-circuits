//! This module implements related functions that aggregates public inputs of many chunks into a
//! single one.

use eth_types::{Field, ToBigEndian, H256, U256};
use ethers_core::utils::keccak256;
use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};
use itertools::Itertools;

use crate::{
    blob::{Blob, BlobAssignments},
    chunk::ChunkHash,
    constants::MAX_AGG_SNARKS,
};

#[derive(Default, Debug, Clone)]
/// A batch is a set of MAX_AGG_SNARKS num of continuous chunks
/// - the first k chunks are from real traces
/// - the last (#MAX_AGG_SNARKS-k) chunks are from empty traces
/// A BatchHash consists of 2 hashes.
/// - batch_pi_hash   := keccak(chain_id || chunk_0.prev_state_root || chunk_k-1.post_state_root ||
///   chunk_k-1.withdraw_root || batch_data_hash)
/// - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
pub struct BatchHash {
    /// Chain ID of the network.
    pub(crate) chain_id: u64,
    /// chunks with padding.
    /// - the first [0..number_of_valid_chunks) are real ones
    /// - the last [number_of_valid_chunks, MAX_AGG_SNARKS) are padding
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
    pub(crate) blob: BlobAssignments,
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

        let blob = BlobAssignments::from(&Blob::new(chunks_with_padding));

        // public input hash is build as
        // keccak(
        //     chain_id ||
        //     chunk[0].prev_state_root ||
        //     chunk[k-1].post_state_root ||
        //     chunk[k-1].withdraw_root ||
        //     batch_data_hash ||
        //     z ||
        //     y
        // )
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
            // TODO: add z
            // TODO: add y
        ]
        .concat();
        let public_input_hash = keccak256(preimage);

        Self {
            chain_id: chunks_with_padding[0].chain_id,
            chunks_with_padding: chunks_with_padding.to_vec(),
            data_hash: batch_data_hash.into(),
            blob,
            public_input_hash: public_input_hash.into(),
            number_of_valid_chunks,
        }
    }

    /// Convert a batch of chunks to blob data.
    pub(crate) fn to_blob_data(&self) -> BlobData {
        let number_non_empty_chunks = self
            .chunks_with_padding
            .iter()
            .filter(|chunk| !chunk.tx_bytes.is_empty())
            .count() as u16;
        let chunk_sizes = self
            .chunks_with_padding
            .iter()
            .map(|chunk| chunk.tx_bytes.len() as u32)
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        let chunk_bytes = self
            .chunks_with_padding
            .iter()
            .map(|chunk| chunk.tx_bytes.to_vec())
            .collect::<Vec<Vec<u8>>>()
            .try_into()
            .unwrap();
        BlobData {
            number_non_empty_chunks,
            chunk_sizes,
            chunk_bytes,
        }
    }

    /// Extract all the hash inputs that will ever be used.
    /// There are MAX_AGG_SNARKS + 2 hashes.
    ///
    /// orders:
    /// - batch_public_input_hash
    /// - chunk\[i\].piHash for i in \[0, MAX_AGG_SNARKS)
    /// - batch_data_hash_preimage
    /// - chunk\[i\].tx_bytes for i in \[0, MAX_AGG_SNARKS)
    /// - pre-image for z (random challenge point)
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
        //      y )
        // TODO: make BLS_MODULUS into a static variable using lazy_static!()
        let (_, z) = self.blob.challenge_digest.div_mod(
            U256::from_str_radix(
                "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
                16,
            )
            .unwrap(),
        );
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
            &z.to_be_bytes(),
            &self.blob.evaluation.to_be_bytes(),
        ]
        .concat();
        res.push(batch_public_input_hash_preimage);

        // compute piHash for each chunk for i in [0..MAX_AGG_SNARKS)
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

        // flattened RLP-signed tx bytes for all L2 txs in chunk.
        //
        // This is eventually used in the chunk PI hash (defined above).
        for chunk in self.chunks_with_padding.iter() {
            res.push(chunk.tx_bytes.clone());
        }

        // flattened RLP-signed tx bytes for all L2 txs in batch.
        //
        // This is used to compute the random challenge point z, where:
        //
        // z := keccak256(
        //     keccak256(metadata)          ||
        //     keccak256(chunk[0].tx_bytes) ||
        //     ...                          ||
        //     keccak256(chunk[i].tx_bytes) ||
        //     ...                          ||
        //     keccak256(chunk[MAX_AGG_SNARKS-1].tx_bytes)
        // )
        let blob_data = self.to_blob_data();
        res.push(blob_data.to_metadata_bytes());
        res.push(
            std::iter::empty()
                .chain(keccak256(blob_data.to_metadata_bytes()))
                .chain(
                    self.chunks_with_padding
                        .iter()
                        .flat_map(|chunk| keccak256(&chunk.tx_bytes)),
                )
                .collect::<Vec<u8>>(),
        );

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

/// Helper struct to generate witness for the Blob Data Config.
pub struct BlobData {
    /// The number of chunks that have non-empty L2 tx data.
    pub number_non_empty_chunks: u16,
    /// The size of each chunk.
    pub chunk_sizes: [u32; MAX_AGG_SNARKS],
    /// The L2 signed transaction bytes, flattened RLP-encoded, for each chunk.
    pub chunk_bytes: [Vec<u8>; MAX_AGG_SNARKS],
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
            ..Default::default()
        }
    }
}

impl BlobData {
    fn to_metadata_bytes(&self) -> Vec<u8> {
        std::iter::empty()
            .chain(self.number_non_empty_chunks.to_be_bytes())
            .chain(
                self.chunk_sizes
                    .iter()
                    .flat_map(|chunk_size| chunk_size.to_be_bytes()),
            )
            .collect()
    }

    fn to_metadata_rows(&self, challenge: Value<Fr>) -> Vec<BlobDataRow<Fr>> {
        // metadata bytes.
        let bytes = self.to_metadata_bytes();

        // accumulators of linear combination of lengths.
        let accumulators_iter =
            std::iter::empty()
                .chain(self.number_non_empty_chunks.to_be_bytes().into_iter().scan(
                    0u64,
                    |acc, x| {
                        *acc = *acc * 256 + (x as u64);
                        Some(*acc)
                    },
                ))
                .chain(self.chunk_sizes.into_iter().flat_map(|chunk_size| {
                    chunk_size.to_be_bytes().into_iter().scan(0u64, |acc, x| {
                        *acc = *acc * 256 + (x as u64);
                        Some(*acc)
                    })
                }));

        // iterator for digest rlc
        let digest_rlc_iter = {
            let digest = keccak256(&bytes);
            let digest_rlc = digest.iter().fold(Value::known(Fr::zero()), |acc, &x| {
                acc * challenge + Value::known(Fr::from(x as u64))
            });
            std::iter::repeat(Value::known(Fr::zero()))
                .take(61) // 2 (n_chunks) + 15 * 4 (chunk_size) - 1
                .chain(std::iter::once(digest_rlc))
        };

        // iterator for preimage rlc
        let preimage_rlc_iter = bytes.iter().scan(Value::known(Fr::zero()), |acc, &x| {
            *acc = *acc * challenge + Value::known(Fr::from(x as u64));
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
                    is_boundary: i == 61,
                    ..Default::default()
                },
            )
            .collect()
    }

    fn to_data_rows(&self, challenge: Value<Fr>) -> Vec<BlobDataRow<Fr>> {
        self.chunk_bytes
            .iter()
            .enumerate()
            .flat_map(|(i, bytes)| {
                let chunk_idx = (i + 1) as u64;
                let chunk_size = bytes.len();
                let chunk_digest = keccak256(bytes);
                let digest_rlc = chunk_digest
                    .iter()
                    .fold(Value::known(Fr::zero()), |acc, &byte| {
                        acc * challenge + Value::known(Fr::from(byte as u64))
                    });
                bytes.iter().enumerate().scan(
                    (0u64, Value::known(Fr::zero())),
                    move |acc, (j, &byte)| {
                        acc.0 += 1;
                        acc.1 = acc.1 * challenge + Value::known(Fr::from(byte as u64));
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
            .chain(std::iter::repeat(BlobDataRow::padding_row()))
            .take(N_ROWS_DATA)
            .collect()
    }

    fn to_hash_rows(&self, challenge: Value<Fr>) -> Vec<BlobDataRow<Fr>> {
        let zero = Value::known(Fr::zero());

        // metadata
        let metadata_bytes = self.to_metadata_bytes();
        let metadata_digest = keccak256(&metadata_bytes);
        let metadata_digest_rlc = metadata_digest.iter().fold(zero, |acc, &byte| {
            acc * challenge + Value::known(Fr::from(byte as u64))
        });

        // chunk data
        let (chunk_digests, chunk_digest_rlcs): (Vec<[u8; 32]>, Vec<Value<Fr>>) = self
            .chunk_bytes
            .iter()
            .map(|chunk| {
                let digest = keccak256(chunk);
                let digest_rlc = digest.iter().fold(zero, |acc, &byte| {
                    acc * challenge + Value::known(Fr::from(byte as u64))
                });
                (digest, digest_rlc)
            })
            .unzip();

        // blob
        let blob_preimage = std::iter::empty()
            .chain(metadata_bytes.iter())
            .chain(chunk_digests.iter().flatten())
            .cloned()
            .collect::<Vec<u8>>();
        let blob_preimage_rlc = blob_preimage.iter().fold(zero, |acc, &byte| {
            acc * challenge + Value::known(Fr::from(byte as u64))
        });
        let blob_digest = keccak256(&blob_preimage);
        let blob_digest_rlc = blob_digest.iter().fold(zero, |acc, &byte| {
            acc * challenge + Value::known(Fr::from(byte as u64))
        });

        std::iter::empty()
            .chain(std::iter::once(BlobDataRow {
                digest_rlc: metadata_digest_rlc,
                ..Default::default()
            }))
            .chain(chunk_digest_rlcs.iter().map(|&digest_rlc| BlobDataRow {
                digest_rlc,
                ..Default::default()
            }))
            .chain(std::iter::once(BlobDataRow {
                preimage_rlc: blob_preimage_rlc,
                digest_rlc: blob_digest_rlc,
                accumulator: 32 + (MAX_AGG_SNARKS + 1) as u64,
                is_boundary: true,
                ..Default::default()
            }))
            .chain(metadata_digest.iter().map(|&byte| BlobDataRow {
                byte,
                ..Default::default()
            }))
            .chain(chunk_digests.iter().flat_map(|digest| {
                digest.iter().map(|&byte| BlobDataRow {
                    byte,
                    ..Default::default()
                })
            }))
            .chain(blob_digest.iter().map(|&byte| BlobDataRow {
                byte,
                ..Default::default()
            }))
            .collect()
    }

    pub(crate) fn to_rows(&self, challenge: Value<Fr>) -> Vec<BlobDataRow<Fr>> {
        let metadata_rows = self.to_metadata_rows(challenge);
        assert_eq!(metadata_rows.len(), N_ROWS_METADATA);

        let data_rows = self.to_data_rows(challenge);
        assert_eq!(data_rows.len(), N_ROWS_DATA);

        let hash_rows = self.to_hash_rows(challenge);
        assert_eq!(hash_rows.len(), N_ROWS_DIGEST);

        std::iter::empty()
            .chain(metadata_rows)
            .chain(data_rows)
            .chain(hash_rows)
            .collect::<Vec<BlobDataRow<Fr>>>()
    }
}

pub const BLOB_WIDTH: usize = 4096;
pub const N_BYTES_32: usize = 32;
pub const N_BYTES_31: usize = N_BYTES_32 - 1;
pub const N_ROWS_NUM_CHUNKS: usize = 2;
pub const N_ROWS_CHUNK_SIZES: usize = MAX_AGG_SNARKS * 4;
// pub const N_BLOB_BYTES: usize = BLOB_WIDTH * N_BYTES_32;
pub const N_CANONICAL_BLOB_BYTES: usize = BLOB_WIDTH * N_BYTES_31;
pub const N_ROWS_METADATA: usize = N_ROWS_NUM_CHUNKS + N_ROWS_CHUNK_SIZES;
pub const N_ROWS_DATA: usize = N_CANONICAL_BLOB_BYTES - N_ROWS_METADATA;
pub const N_ROWS_DIGEST_RLC: usize = 1 + 1 + MAX_AGG_SNARKS;
pub const N_ROWS_DIGEST_BYTES: usize = N_ROWS_DIGEST_RLC * N_BYTES_32;
pub const N_ROWS_DIGEST: usize = N_ROWS_DIGEST_RLC + N_ROWS_DIGEST_BYTES;
pub const N_ROWS_BLOB_DATA_CONFIG: usize = N_ROWS_METADATA + N_ROWS_DATA + N_ROWS_DIGEST;
