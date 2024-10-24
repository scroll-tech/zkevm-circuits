/// Config to evaluate blob polynomial at a random challenge.
mod barycentric;
use barycentric::{
    interpolate, AssignedBarycentricEvaluationConfig, BarycentricEvaluationConfig, BLS_MODULUS,
};

/// blob struct and constants
mod blob;
use blob::PointEvaluationAssignments;

#[cfg(test)]
mod tests;

use super::{AssignedBlobDataExport, BlobDataConfig};
use crate::{
    aggregation::batch_data::N_DATA_BYTES_PER_COEFFICIENT, constants::N_BYTES_U256, BatchData,
    RlcConfig,
};
use eth_types::{ToBigEndian, H256, U256};
use ethers_core::k256::sha2::{Digest, Sha256};
use halo2_base::{gates::range::RangeConfig, Context};
use halo2_ecc::bigint::CRTInteger;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{ConstraintSystem, Error, Expression},
};
use itertools::Itertools;
use once_cell::sync::Lazy;
use revm_primitives::VERSIONED_HASH_VERSION_KZG;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::LIMBS;
use std::sync::Arc;
use zkevm_circuits::{table::U8Table, util::Challenges};

pub const BLOB_WIDTH: usize = 4096;
pub const N_BLOB_BYTES: usize = BLOB_WIDTH * N_DATA_BYTES_PER_COEFFICIENT;

/// Get the BLOB_WIDTH number of scalar field elements, as 32-bytes unsigned integers.
fn get_coefficients(blob_bytes: &[u8]) -> [U256; BLOB_WIDTH] {
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

/// KZG trusted setup
static KZG_TRUSTED_SETUP: Lazy<Arc<c_kzg::KzgSettings>> = Lazy::new(|| {
    Arc::new(
        c_kzg::KzgSettings::load_trusted_setup(
            &revm_primitives::kzg::G1_POINTS.0,
            &revm_primitives::kzg::G2_POINTS.0,
        )
        .expect("failed to load trusted setup"),
    )
});

/// Get the versioned hash as per EIP-4844.
pub fn get_versioned_hash(coefficients: &[U256; BLOB_WIDTH]) -> H256 {
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

#[derive(Debug, Clone)]
pub struct BlobConsistencyConfig<const N_SNARKS: usize> {
    data: BlobDataConfig<N_SNARKS>,
    barycentric_evaluation: BarycentricEvaluationConfig,
}

impl<const N_SNARKS: usize> BlobConsistencyConfig<N_SNARKS> {
    pub fn construct(
        meta: &mut ConstraintSystem<Fr>,
        challenges: &Challenges<Expression<Fr>>,
        u8_table: U8Table,
        range: RangeConfig<Fr>,
    ) -> Self {
        Self {
            data: BlobDataConfig::configure(meta, challenges, u8_table),
            barycentric_evaluation: BarycentricEvaluationConfig::construct(range),
        }
    }

    pub fn assign_barycentric(
        &self,
        ctx: &mut Context<Fr>,
        bytes: &[u8],
        challenge: U256,
    ) -> AssignedBarycentricEvaluationConfig {
        self.barycentric_evaluation.assign(ctx, bytes, challenge)
    }

    pub fn assign_blob_data(
        &self,
        layouter: &mut impl Layouter<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        rlc_config: &RlcConfig,
        blob_bytes: &[u8],
    ) -> Result<AssignedBlobDataExport, Error> {
        self.data
            .assign(layouter, challenge_value, rlc_config, blob_bytes)
    }

    pub fn link(
        layouter: &mut impl Layouter<Fr>,
        blob_crts_limbs: &[[AssignedCell<Fr, Fr>; LIMBS]],
        barycentric_crts: &[CRTInteger<Fr>],
    ) -> Result<(), Error> {
        assert_eq!(blob_crts_limbs.len(), BLOB_WIDTH);

        layouter.assign_region(
            || "constrain barycentric inputs to match blob",
            |mut region| {
                for (blob_crt_limbs, barycentric_crt) in blob_crts_limbs
                    .iter()
                    .zip_eq(barycentric_crts.iter().take(BLOB_WIDTH))
                {
                    for (blob_limb, barycentric_limb) in
                        blob_crt_limbs.iter().zip_eq(barycentric_crt.limbs())
                    {
                        region.constrain_equal(blob_limb.cell(), barycentric_limb.cell())?;
                    }
                }
                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct BlobConsistencyWitness {
    #[serde(rename = "blob_versioned_hash")]
    id: H256,
    blob_data_proof: [H256; 2],
}

impl BlobConsistencyWitness {
    pub fn new<const N_SNARKS: usize>(bytes: &[u8], batch_data: &BatchData<N_SNARKS>) -> Self {
        let coeffs = get_coefficients(bytes);
        let versioned_hash = get_versioned_hash(&coeffs);
        let point_evaluation_assignments =
            PointEvaluationAssignments::new(&batch_data, bytes, versioned_hash);
        let blob_data_proof = [
            point_evaluation_assignments.challenge,
            point_evaluation_assignments.evaluation,
        ]
        .map(|x| H256::from_slice(&x.to_be_bytes()));

        Self {
            id: versioned_hash,
            blob_data_proof,
        }
    }

    pub fn id(&self) -> H256 {
        self.id
    }

    pub fn challenge(&self) -> H256 {
        self.blob_data_proof[0]
    }

    pub fn evaluation(&self) -> H256 {
        self.blob_data_proof[1]
    }
}
