#[cfg(test)]
mod tests;

use super::{AssignedBlobDataExport, BlobDataConfig};
use crate::{BatchData, RlcConfig};
use eth_types::{H256, U256};
use ethers_core::utils::keccak256;
use halo2_base::{gates::range::RangeConfig, AssignedValue, Context};
use halo2_ecc::bigint::CRTInteger;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::{bls12_381::Scalar, bn256::Fr},
    plonk::{ConstraintSystem, Error, Expression},
};
use snark_verifier_sdk::LIMBS;
use zkevm_circuits::{table::U8Table, util::Challenges};

pub const BLOB_WIDTH: usize = 4096;

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
        Self {
            data: BlobDataConfig::configure(meta, challenges, u8_table),
        }
    }

    pub fn assign_barycentric(
        &self,
        _ctx: &mut Context<Fr>,
        _bytes: &[u8],
        _challenge: U256,
    ) -> AssignedBarycentricEvaluationConfig {
        AssignedBarycentricEvaluationConfig::default()
    }

    pub fn assign_blob_data(
        &self,
        layouter: &mut impl Layouter<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        rlc_config: &RlcConfig,
        blob_bytes: &[u8],
    ) -> Result<AssignedBlobDataExport, Error> {
        let export = self
            .data
            .assign(layouter, challenge_value, rlc_config, blob_bytes);

        // rlc_config.lookup_keccak_rlcs(
        //     region: &mut Region<Fr>,
        //     input_rlcs: &AssignedCell<Fr, Fr>,
        //     output_rlcs: &AssignedCell<Fr, Fr>,
        //     data_len: &export.cooked_len,
        //     offset: &mut usize,
        // )

        export

        // region: &mut Region<Fr>,
        // input_rlcs: &AssignedCell<Fr, Fr>,
        // output_rlcs: &AssignedCell<Fr, Fr>,
        // data_len: &AssignedCell<Fr, Fr>,
        // offset: &mut usize,

        // config.rlc_config.mul(
        //     &mut region,
        //     &blob_data_exports.bytes_rlc,
        //     &disable_encoding,
        //     &mut rlc_config_offset,
        // )?,
    }

    pub fn link(
        _layouter: &mut impl Layouter<Fr>,
        _blob_crts_limbs: &[[AssignedCell<Fr, Fr>; LIMBS]],
        _barycentric_crts: &[CRTInteger<Fr>],
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BlobConsistencyWitness {
    blob_versioned_hash: H256,
}

impl BlobConsistencyWitness {
    pub fn new<const N_SNARKS: usize>(bytes: &[u8], _batch_data: &BatchData<N_SNARKS>) -> Self {
        Self {
            blob_versioned_hash: keccak256(bytes).into(),
        }
    }

    pub fn id(&self) -> H256 {
        self.blob_versioned_hash
    }

    pub fn challenge_digest(&self) -> U256 {
        Default::default()
    }

    pub fn challenge(&self) -> Scalar {
        Default::default()
    }

    pub fn evaluation(&self) -> Scalar {
        Default::default()
    }

    pub fn blob_data_proof(&self) -> [H256; 2] {
        Default::default()
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

/// Get the blob data bytes that will be populated in BlobDataConfig.
pub fn get_blob_bytes(_batch_bytes: &[u8]) -> Vec<u8> {
    unimplemented!("trick for linting");
}
