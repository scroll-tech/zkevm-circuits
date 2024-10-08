use crate::{constants::N_BYTES_U256, BatchData, RlcConfig};
use eth_types::{ToBigEndian, H256, U256};
use ethers_core::k256::sha2::{Digest, Sha256};
use halo2_base::{gates::range::RangeConfig, AssignedValue, Context};
use halo2_ecc::bigint::CRTInteger;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{ConstraintSystem, Error, Expression},
};
use serde::{Deserialize, Serialize};
use super::{AssignedBlobDataExport, BlobDataConfig};
use zkevm_circuits::{table::U8Table, util::Challenges};

pub const BLOB_WIDTH: usize = 4096;

pub fn get_coefficients(bytes: &[u8]) -> [U256; BLOB_WIDTH] {
    [U256::zero(); BLOB_WIDTH]
}

#[derive(Debug, Clone)]
pub struct BlobConsistencyConfig<const N_SNARKS: usize> {
    data: BlobDataConfig<N_SNARKS>,
}

impl<const N_SNARKS: usize> BlobConsistencyConfig<N_SNARKS> {
    pub fn construct(
        meta: &mut ConstraintSystem<Fr>,
        challenges: &Challenges<Expression<Fr>>,
        u8_table: U8Table,
        _: RangeConfig<Fr>,
    ) -> Self {
        Self{
        data: BlobDataConfig::configure(meta, challenges, u8_table),
        }
    }

    pub fn assign_barycentric(
        &self,
        ctx: &mut Context<Fr>,
        blob: &[U256; BLOB_WIDTH],
        challenge: U256,
        evaluation: U256,
    ) -> AssignedBarycentricEvaluationConfig {
        Default::default()
    }

    pub fn assign_blob_data(
        &self,
        layouter: &mut impl Layouter<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        rlc_config: &RlcConfig,
        blob_bytes: &[u8],
        barycentric_assignments: &[CRTInteger<Fr>],
    ) -> Result<AssignedBlobDataExport, Error> {
        self.data.assign(
            layouter,
            challenge_value,
            rlc_config,
            blob_bytes,
            barycentric_assignments,
        )
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct BlobConsistencyWitness {
    #[serde(rename = "blob_versioned_hash")] 
    id: H256,
    blob_data_proof: [H256; 2]
}

impl BlobConsistencyWitness {
    pub fn new<const N_SNARKS: usize>(bytes: &[u8], _: &BatchData<N_SNARKS>) -> Self {
        Self {
            id: H256::default(), // should be keccak of bytes
            blob_data_proof: Default::default(),
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

#[derive(Default)]
pub struct AssignedBarycentricEvaluationConfig {
    /// CRTIntegers for the BLOB_WIDTH number of blob polynomial coefficients, followed by a
    /// CRTInteger for the challenge digest.
    pub(crate) barycentric_assignments: Vec<CRTInteger<Fr>>,
    /// 32 Assigned cells representing the LE-bytes of challenge z.
    pub(crate) z_le: Vec<AssignedValue<Fr>>,
    /// 32 Assigned cells representing the LE-bytes of evaluation y.
    pub(crate) y_le: Vec<AssignedValue<Fr>>,
}
