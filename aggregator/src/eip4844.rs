use eth_types::{ToBigEndian, H256, U256};
use ethers_core::k256::sha2::{Digest, Sha256};
use revm_primitives::VERSIONED_HASH_VERSION_KZG;

use crate::blob::{BLOB_WIDTH, KZG_TRUSTED_SETUP, N_BLOB_BYTES, N_BYTES_U256};

/// Get the BLOB_WIDTH number of scalar field elements, as 32-bytes unsigned integers.
pub(crate) fn get_coefficients(blob_bytes: &[u8]) -> [U256; BLOB_WIDTH] {
    let mut coefficients = [[0u8; N_BYTES_U256]; BLOB_WIDTH];

    assert!(
        blob_bytes.len() <= N_BLOB_BYTES,
        "too many bytes in batch data"
    );

    for (i, &byte) in blob_bytes.iter().enumerate() {
        coefficients[i / 31][1 + (i % 31)] = byte;
    }

    coefficients.map(|coeff| U256::from_big_endian(&coeff))
}

/// Get the versioned hash as per EIP-4844.
pub(crate) fn get_versioned_hash(coefficients: &[U256; BLOB_WIDTH]) -> H256 {
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

fn kzg_to_versioned_hash(commitment: &c_kzg::KzgCommitment) -> H256 {
    let mut res = Sha256::digest(commitment.as_slice());
    res[0] = VERSIONED_HASH_VERSION_KZG;
    H256::from_slice(&res[..])
}

#[cfg(test)]
/// Get the blob data bytes that will be populated in BlobDataConfig.
pub(crate) fn get_blob_bytes(batch_bytes: &[u8]) -> Vec<u8> {
    let mut blob_bytes = crate::witgen::zstd_encode(batch_bytes);

    // Whether we encode batch -> blob or not.
    let enable_encoding = blob_bytes.len() < batch_bytes.len();
    if !enable_encoding {
        blob_bytes = batch_bytes.to_vec();
    }
    blob_bytes.insert(0, enable_encoding as u8);

    blob_bytes
}

/// Given the blob's bytes, take into account the first byte, i.e. enable_encoding? and either spit
/// out the raw bytes or zstd decode them.
pub fn decode_blob(blob_bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let enable_encoding = blob_bytes[0].eq(&1);

    // If not encoded, spit out the rest of the bytes, as it is.
    if !enable_encoding {
        return Ok(blob_bytes[1..].to_vec());
    }

    // The bytes following the first byte represent the zstd-encoded bytes.
    let mut encoded_bytes = blob_bytes[1..].to_vec();
    let mut encoded_len = encoded_bytes.len();
    let mut decoded_bytes = Vec::with_capacity(5 * 4096 * 32);
    loop {
        let mut decoder = zstd_encoder::zstd::stream::read::Decoder::new(encoded_bytes.as_slice())?;
        decoder.include_magicbytes(false)?;
        decoder.window_log_max(30)?;

        decoded_bytes.clear();

        if std::io::copy(&mut decoder, &mut decoded_bytes).is_ok() {
            break;
        }

        // The error above means we need to truncate the suffix 0-byte.
        encoded_len -= 1;
        encoded_bytes.truncate(encoded_len);
    }

    Ok(decoded_bytes)
}
