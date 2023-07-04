use eth_types::Field;
use halo2_base::{AssignedValue, QuantumCell};
use halo2_ecc::{
    bigint::CRTInteger,
    ecc::EcPoint,
    fields::{fp::FpConfig, FieldChip},
};
use halo2_proofs::{
    circuit::Value,
    halo2curves::secp256k1::{Fp, Fq},
};

// Hard coded parameters.
// FIXME: allow for a configurable param.
pub(super) const MAX_NUM_SIG: usize = 32;
// Each ecdsa signature requires 534042 cells
// We set CELLS_PER_SIG = 535000 to allows for a few buffer
pub(super) const CELLS_PER_SIG: usize = 535000;
// Total number of rows allocated for ecdsa chip
pub(super) const LOG_TOTAL_NUM_ROWS: usize = 19;
// Max number of columns allowed
pub(super) const COLUMN_NUM_LIMIT: usize = 150;

pub(super) fn calc_required_advices(num_verif: usize) -> usize {
    let mut num_adv = 1;
    let total_cells = num_verif * CELLS_PER_SIG;
    let row_num = 1 << LOG_TOTAL_NUM_ROWS;
    while num_adv < COLUMN_NUM_LIMIT {
        if num_adv * row_num > total_cells {
            log::debug!(
                "ecdsa chip uses {} advice columns for {} signatures",
                num_adv,
                num_verif
            );
            return num_adv;
        }
        num_adv += 1;
    }
    panic!("the required advice columns exceeds {COLUMN_NUM_LIMIT} for {num_verif} signatures");
}

/// Chip to handle overflow integers of ECDSA::Fq, the scalar field
pub(super) type FqChip<F> = FpConfig<F, Fq>;
/// Chip to handle ECDSA::Fp, the base field
pub(super) type FpChip<F> = FpConfig<F, Fp>;

pub(crate) struct AssignedECDSA<F: Field, FC: FieldChip<F>> {
    pub(super) pk: EcPoint<F, FC::FieldPoint>,
    pub(super) msg_hash: CRTInteger<F>,
    pub(super) integer_r: CRTInteger<F>,
    pub(super) integer_s: CRTInteger<F>,
    pub(super) v: AssignedValue<F>,
    pub(super) sig_is_valid: AssignedValue<F>,
}

#[derive(Debug, Clone)]
pub(crate) struct AssignedSignatureVerify<F: Field> {
    pub(crate) address: AssignedValue<F>,
    pub(crate) msg_len: usize,
    pub(crate) msg_rlc: Value<F>,
    pub(crate) msg_hash_rlc: AssignedValue<F>,
    pub(crate) r_rlc: AssignedValue<F>,
    pub(crate) s_rlc: AssignedValue<F>,
    pub(crate) v: AssignedValue<F>,
    pub(crate) sig_is_valid: AssignedValue<F>,
}

pub(super) struct SignDataDecomposed<F: Field> {
    pub(super) pk_hash_cells: Vec<QuantumCell<F>>,
    pub(super) msg_hash_cells: Vec<QuantumCell<F>>,
    pub(super) pk_cells: Vec<QuantumCell<F>>,
    pub(super) address: AssignedValue<F>,
    pub(super) is_address_zero: AssignedValue<F>,
    pub(super) r_cells: Vec<QuantumCell<F>>,
    pub(super) s_cells: Vec<QuantumCell<F>>,
    //v:  AssignedValue<'v, F>, // bool
}

// FIXME: is this correct? not used anywhere?
pub(crate) fn pub_key_hash_to_address<F: Field>(pk_hash: &[u8]) -> F {
    pk_hash[32 - 20..]
        .iter()
        .fold(F::zero(), |acc, b| acc * F::from(256) + F::from(*b as u64))
}
