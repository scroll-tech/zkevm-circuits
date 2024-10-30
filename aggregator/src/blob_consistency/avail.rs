use super::AssignedBlobDataExport;
use crate::{BatchData, RlcConfig};
use eth_types::{H256, U256};
use halo2_base::{gates::range::RangeConfig, AssignedValue, Context};
use halo2_ecc::bigint::CRTInteger;
use halo2_proofs::halo2curves::bls12_381::Scalar;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{ConstraintSystem, Error, Expression},
};
use snark_verifier_sdk::LIMBS;
use zkevm_circuits::{table::U8Table, util::Challenges};

pub const BLOB_WIDTH: usize = 4096;

#[derive(Debug, Clone)]
pub struct BlobConsistencyConfig<const N_SNARKS: usize> {}

impl<const N_SNARKS: usize> BlobConsistencyConfig<N_SNARKS> {
    pub fn construct(
        _meta: &mut ConstraintSystem<Fr>,
        _challenges: &Challenges<Expression<Fr>>,
        _u8_table: U8Table,
        _: RangeConfig<Fr>,
    ) -> Self {
        unimplemented!()
    }

    pub fn assign_barycentric(
        &self,
        _ctx: &mut Context<Fr>,
        _bytes: &[u8],
        _challenge: U256,
    ) -> AssignedBarycentricEvaluationConfig {
        unimplemented!()
    }

    pub fn assign_blob_data(
        &self,
        _layouter: &mut impl Layouter<Fr>,
        _challenge_value: Challenges<Value<Fr>>,
        _rlc_config: &RlcConfig,
        _blob_bytes: &[u8],
    ) -> Result<AssignedBlobDataExport, Error> {
        unimplemented!()
    }

    pub fn link(
        _layouter: &mut impl Layouter<Fr>,
        _blob_crts_limbs: &[[AssignedCell<Fr, Fr>; LIMBS]],
        _barycentric_crts: &[CRTInteger<Fr>],
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BlobConsistencyWitness {
    blob_versioned_hash: H256,
    challenge_digest: H256,
    evaluation: Scalar,
}

impl BlobConsistencyWitness {
    pub fn new<const N_SNARKS: usize>(_bytes: &[u8], _batch_data: &BatchData<N_SNARKS>) -> Self {
        unimplemented!()
    }

    pub fn id(&self) -> H256 {
        unimplemented!()
    }

    pub fn challenge_digest(&self) -> U256 {
        unimplemented!()
    }

    pub fn challenge(&self) -> Scalar {
        unimplemented!()
    }

    pub fn evaluation(&self) -> Scalar {
        unimplemented!()
    }

    pub fn blob_data_proof(&self) -> [H256; 2] {
        unimplemented!()
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
