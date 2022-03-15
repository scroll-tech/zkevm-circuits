use super::params::N_LIMBS_ACCOUNT_ADDRESS;
use crate::evm_circuit::util::constraint_builder::BaseConstraintBuilder;
use crate::evm_circuit::util::math_gadget::generate_lagrange_base_polynomial;
use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        // step::{Preset, Step},
        table::{
            AccountFieldTag, CallContextFieldTag, FixedTableTag, Lookup, RwTableTag,
            TxContextFieldTag,
        },
        util::{Cell, RandomLinearCombination, Word},
    },
    util::Expr,
};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};
use std::convert::TryInto;
use strum::IntoEnumIterator;

// TODO(mason) set these correctly
const MAX_DEGREE: usize = 15;
const LOOKUP_DEGREE: usize = 2;
const WIDTH: usize = 10;

pub(crate) enum Transition<T> {
    Same,
    Delta(T),
    To(T),
}

#[derive(Clone, Debug, Default)]
struct RowUsage {
    next_idx: usize,
    is_byte_lookup_enabled: bool,
}

#[derive(Clone, Debug)]
struct Row<F> {
    pub(crate) qs_byte_lookup: Cell<F>,
    pub(crate) cells: [Cell<F>; WIDTH],
}

// rename this to RWTableRow?
#[derive(Clone, Debug)]
pub(crate) struct Step<F> {
    rows: Vec<Row<F>>,
}

impl<F> Default for Transition<F> {
    fn default() -> Self {
        Self::Same
    }
}

// Rename to QueryBuilder?
pub(crate) struct ConstraintBuilder<F: FieldExt> {
    cb: BaseConstraintBuilder<F>,
    rw_counter: Column<Advice>,
    s_enable: Column<Fixed>,
    is_write: Column<Advice>,
    keys: [Column<Advice>; 5],
    keys_diff_inv: [Column<Advice>; 5],
    key2_limbs: [Column<Advice>; N_LIMBS_ACCOUNT_ADDRESS],
    key4_bytes: [Column<Advice>; N_BYTES_WORD],
    value: Column<Advice>,
    auxs: [Column<Advice>; 2],
    rw_counter_table: Column<Fixed>,
    stack_address_table_zero: Column<Fixed>,
    memory_address_table_zero: Column<Fixed>,
    memory_value_table: Column<Fixed>,
}

impl<'a, F: FieldExt> ConstraintBuilder<F> {
    pub(crate) fn new(meta: &'a mut ConstraintSystem<F>, keys: [Column<Advice>; 5]) -> Self {
        Self {
            cb: BaseConstraintBuilder::new(MAX_DEGREE),
            rw_counter: meta.advice_column(),
            is_write: meta.advice_column(),
            keys,
            keys_diff_inv: [(); 5].map(|_| meta.advice_column()),
            key2_limbs: [(); N_LIMBS_ACCOUNT_ADDRESS].map(|_| meta.advice_column()),
            key4_bytes: [(); N_BYTES_WORD].map(|_| meta.advice_column()),
            auxs: [(); 2].map(|_| meta.advice_column()),
            s_enable: meta.fixed_column(),
            value: meta.advice_column(),
            rw_counter_table: meta.fixed_column(),
            memory_address_table_zero: meta.fixed_column(),
            stack_address_table_zero: meta.fixed_column(),
            memory_value_table: meta.fixed_column(),
        }
    }

    pub(super) fn tag(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[0], Rotation::cur())
    }
    // This is TxId or CallId if applicable. 0 otherwise.
    fn id(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[1], Rotation::cur())
    }
    pub(super) fn account_address(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[2], Rotation::cur())
    }

    pub(super) fn account_address_limbs(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[2], Rotation::cur())
    }

    pub(super) fn address(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[3], Rotation::cur())
    }
    pub(super) fn storage_key(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[4], Rotation::cur())
    }

    pub(super) fn tag_is(&self, meta: &mut VirtualCells<F>, tag: RwTableTag) -> Expression<F> {
        generate_lagrange_base_polynomial(
            self.tag(meta),
            tag as usize,
            RwTableTag::iter().map(|x| x as usize),
        )
    }
}
