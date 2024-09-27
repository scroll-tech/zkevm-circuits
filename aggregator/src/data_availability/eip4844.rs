/// Config to evaluate blob polynomial at a random challenge.
pub mod barycentric;
pub use barycentric::{
    interpolate, AssignedBarycentricEvaluationConfig, BarycentricEvaluationConfig, BLS_MODULUS,
};

/// blob struct and constants
pub mod blob;
use blob::{BLOB_WIDTH, KZG_TRUSTED_SETUP, N_BLOB_BYTES, N_BYTES_U256};

/// Config to constrain blob data (encoded batch data)
pub mod blob_data;
pub use blob_data::BlobDataConfig;

use eth_types::{ToBigEndian, H256, U256};
use ethers_core::k256::sha2::{Digest, Sha256};
use revm_primitives::VERSIONED_HASH_VERSION_KZG;

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

/// Get the blob data bytes that will be populated in BlobDataConfig.
pub fn get_blob_bytes(batch_bytes: &[u8]) -> Vec<u8> {
    let mut blob_bytes = crate::witgen::zstd_encode(batch_bytes);

    // Whether we encode batch -> blob or not.
    let enable_encoding = blob_bytes.len() < batch_bytes.len();
    if !enable_encoding {
        blob_bytes = batch_bytes.to_vec();
    }
    blob_bytes.insert(0, enable_encoding as u8);

    blob_bytes
}
