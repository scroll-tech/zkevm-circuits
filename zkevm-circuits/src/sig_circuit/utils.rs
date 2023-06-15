use std::marker::PhantomData;

use eth_types::Field;
use halo2_base::{AssignedValue, QuantumCell};
use halo2_ecc::{
    bigint::CRTInteger,
    ecc::EcPoint,
    fields::{fp::FpConfig, FieldChip},
};
use halo2_proofs::{
    circuit::{Cell, Value},
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
    panic!(
        "the required advice columns exceeds {} for {} signatures",
        COLUMN_NUM_LIMIT, num_verif
    );
}

/// Chip to handle overflow integers of ECDSA::Fq, the scalar field
pub(super) type FqChip<F> = FpConfig<F, Fq>;
/// Chip to handle ECDSA::Fp, the base field
pub(super) type FpChip<F> = FpConfig<F, Fp>;

pub(crate) struct AssignedECDSA<'v, F: Field, FC: FieldChip<F>> {
    pub(super) pk: EcPoint<F, FC::FieldPoint<'v>>,
    pub(super) msg_hash: CRTInteger<'v, F>,
    pub(super) sig_is_valid: AssignedValue<'v, F>,
}

/// Temp struct to hold the intermediate data; removing life timer.
// Issue with life timer:
//
// Suppose we have two piece of codes, that request different regions/contexts from the layouter.
// The first piece of the code will return an `assigned_cell` that is to be used by the second code
// piece. With halo2 we can safely pass this `assigned_cell` around. They are bounded by a life
// timer `'v` which is when the field element is created.
//
// Now in halo2-lib, there is an additional life timer which says an `assigned_cell` cannot outlive
// the `region` for which this cell is created. (is this understanding correct?)
// That means the output cells of the first region cannot be passed to the second region.
//
// To temporary resolve this issue, we create a temp struct without life timer.
// This works with halo2-lib/pse but not halo2-lib/axiom.
// We do not support halo2-lib/axiom.
//
// NOTE: this is a temp issue with halo2-lib v0.2.2.
// with halo2-lib v0.3.0 the timers are already removed.
// So we don't need this temp fix once we sync with halo2-lib audited version.
#[derive(Debug, Clone)]
pub(crate) struct AssignedValueNoTimer<F: Field> {
    pub cell: Cell,
    pub value: Value<F>,
    pub row_offset: usize,
    pub context_id: usize,
}

impl<'v, F: Field> From<AssignedValue<'v, F>> for AssignedValueNoTimer<F> {
    fn from(input: AssignedValue<'v, F>) -> Self {
        Self {
            cell: input.cell(),
            value: input.value,
            row_offset: input.row_offset,
            context_id: input.context_id,
        }
    }
}

impl<'v, F: Field> From<AssignedValueNoTimer<F>> for AssignedValue<'v, F> {
    fn from(input: AssignedValueNoTimer<F>) -> Self {
        Self {
            cell: input.cell,
            value: input.value,
            row_offset: input.row_offset,
            _marker: PhantomData::default(),
            context_id: input.context_id,
        }
    }
}

impl<'v, F: Field> From<&AssignedValueNoTimer<F>> for AssignedValue<'v, F> {
    fn from(input: &AssignedValueNoTimer<F>) -> Self {
        Self {
            cell: input.cell,
            value: input.value,
            row_offset: input.row_offset,
            _marker: PhantomData::default(),
            context_id: input.context_id,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AssignedSignatureVerify<F: Field> {
    pub(crate) address: AssignedValueNoTimer<F>,
    pub(crate) msg_len: usize,
    pub(crate) msg_rlc: Value<F>,
    pub(crate) msg_hash_rlc: AssignedValueNoTimer<F>,
    pub(crate) r_rlc: AssignedValueNoTimer<F>,
    pub(crate) s_rlc: AssignedValueNoTimer<F>,
    pub(crate) sig_is_valid: AssignedValueNoTimer<F>,
}

pub(super) struct SignDataDecomposed<'a: 'v, 'v, F: Field> {
    pub(super) pk_hash_cells: Vec<QuantumCell<'a, 'v, F>>,
    pub(super) msg_hash_cells: Vec<QuantumCell<'a, 'v, F>>,
    pub(super) pk_cells: Vec<QuantumCell<'a, 'v, F>>,
    pub(super) address: AssignedValue<'v, F>,
    pub(super) is_address_zero: AssignedValue<'v, F>,
    pub(super) r_cells: Vec<QuantumCell<'a, 'v, F>>,
    pub(super) s_cells: Vec<QuantumCell<'a, 'v, F>>,
    //v:  AssignedValue<'v, F>, // bool
}

// FIXME: is this correct? not used anywhere?
pub(crate) fn pub_key_hash_to_address<F: Field>(pk_hash: &[u8]) -> F {
    pk_hash[32 - 20..]
        .iter()
        .fold(F::zero(), |acc, b| acc * F::from(256) + F::from(*b as u64))
}
