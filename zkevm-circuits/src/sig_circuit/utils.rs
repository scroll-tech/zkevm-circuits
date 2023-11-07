use std::cell::RefCell;

use eth_types::Field;
use halo2_base::{AssignedValue, QuantumCell, gates::circuit::builder::RangeCircuitBuilder};
use halo2_ecc::{bigint::ProperCrtUint, ecc::EcPoint, fields::FieldChip};
use halo2_proofs::circuit::{Value, AssignedCell, Layouter};

use super::SigCircuitConfig;

// Hard coded parameters.
// FIXME: allow for a configurable param.
pub(super) const MAX_NUM_SIG: usize = 128;
// Each ecdsa signature requires 461174 cells
pub(super) const CELLS_PER_SIG: usize = 461174;
// Each ecdsa signature requires 63276 lookup cells
pub(super) const LOOKUP_CELLS_PER_SIG: usize = 63276;
// Total number of rows allocated for ecdsa chip
pub(super) const LOG_TOTAL_NUM_ROWS: usize = 20;
// Max number of columns allowed
pub(super) const COLUMN_NUM_LIMIT: usize = 58;
// Max number of lookup columns allowed
pub(super) const LOOKUP_COLUMN_NUM_LIMIT: usize = 9;

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

pub(super) fn calc_required_lookup_advices(num_verif: usize) -> usize {
    let mut num_adv = 1;
    let total_cells = num_verif * LOOKUP_CELLS_PER_SIG;
    let row_num = 1 << LOG_TOTAL_NUM_ROWS;
    while num_adv < LOOKUP_COLUMN_NUM_LIMIT {
        if num_adv * row_num > total_cells {
            log::debug!(
                "ecdsa chip uses {} lookup advice columns for {} signatures",
                num_adv,
                num_verif
            );
            return num_adv;
        }
        num_adv += 1;
    }
    panic!("the required lookup advice columns exceeds {LOOKUP_COLUMN_NUM_LIMIT} for {num_verif} signatures");
}

pub(crate) struct AssignedECDSA<F: Field, FC: FieldChip<F>> {
    pub(super) pk: EcPoint<F, FC::FieldPoint>,
    pub(super) pk_is_zero: AssignedValue<F>,
    pub(super) msg_hash: ProperCrtUint<F>,
    pub(super) integer_r: ProperCrtUint<F>,
    pub(super) integer_s: ProperCrtUint<F>,
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

#[derive(Debug, Clone)]
pub(crate) struct TransmutedSignatureVerify<F: Field> {
    pub(crate) address: AssignedCell<F, F>,
    pub(crate) msg_len: usize,
    pub(crate) msg_rlc: Value<F>,
    pub(crate) msg_hash_rlc: AssignedCell<F,F>,
    pub(crate) r_rlc: AssignedCell<F,F>,
    pub(crate) s_rlc: AssignedCell<F,F>,
    pub(crate) v: AssignedCell<F, F>,
    pub(crate) sig_is_valid: AssignedCell<F,F>,
}


impl<F:Field> TransmutedSignatureVerify<F> {

    fn trasmute_from(
        builder:  RefCell<RangeCircuitBuilder<F>>,
        config: &SigCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        assigned_sig_verif: &AssignedSignatureVerify<F>,
    )->Self{
        todo!()
    }
}

pub(super) struct SignDataDecomposed<F: Field> {
    pub(super) pk_hash_cells: Vec<QuantumCell<F>>,
    pub(super) msg_hash_cells: Vec<QuantumCell<F>>,
    pub(super) pk_cells: Vec<QuantumCell<F>>,
    pub(super) address: AssignedValue<F>,
    pub(super) is_address_zero: AssignedValue<F>,
    pub(super) r_cells: Vec<QuantumCell<F>>,
    pub(super) s_cells: Vec<QuantumCell<F>>,
}
