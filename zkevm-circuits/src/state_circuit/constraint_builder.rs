use super::params::N_LIMBS_ACCOUNT_ADDRESS;
use crate::evm_circuit::{
    param::N_BYTES_WORD,
    table::RwTableTag,
    util::{
        constraint_builder::BaseConstraintBuilder, math_gadget::generate_lagrange_base_polynomial,
    },
};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use strum::IntoEnumIterator;

// TODO(mason) set these correctly
const MAX_DEGREE: usize = 15;
const LOOKUP_DEGREE: usize = 2;
const WIDTH: usize = 10;

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
    power_of_randomness: [Expression<F>; N_BYTES_WORD - 1],
}

impl<'a, F: FieldExt> ConstraintBuilder<F> {
    pub(crate) fn new(
        meta: &'a mut ConstraintSystem<F>,
        keys: [Column<Advice>; 5],
        key2_limbs: [Column<Advice>; N_LIMBS_ACCOUNT_ADDRESS],
        s_enable: Column<Fixed>,
        key4_bytes: [Column<Advice>; N_BYTES_WORD],
        power_of_randomness: [Expression<F>; N_BYTES_WORD - 1],
    ) -> Self {
        Self {
            cb: BaseConstraintBuilder::new(MAX_DEGREE),
            rw_counter: meta.advice_column(),
            is_write: meta.advice_column(),
            keys,
            keys_diff_inv: [(); 5].map(|_| meta.advice_column()),
            key2_limbs,
            key4_bytes,
            auxs: [(); 2].map(|_| meta.advice_column()),
            s_enable,
            value: meta.advice_column(),
            rw_counter_table: meta.fixed_column(),
            memory_address_table_zero: meta.fixed_column(),
            stack_address_table_zero: meta.fixed_column(),
            memory_value_table: meta.fixed_column(),
            power_of_randomness: power_of_randomness.clone(),
        }
    }

    pub(super) fn tag(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[0], Rotation::cur())
    }
    // This is TxId or CallId if applicable. 0 otherwise.
    pub(super) fn id(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[1], Rotation::cur())
    }
    pub(super) fn account_address(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[2], Rotation::cur())
    }

    pub(super) fn account_address_limbs(
        &self,
        meta: &mut VirtualCells<F>,
    ) -> [Expression<F>; N_LIMBS_ACCOUNT_ADDRESS] {
        self.key2_limbs
            .map(|limb| meta.query_advice(limb, Rotation::cur()))
    }

    pub(super) fn address(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[3], Rotation::cur())
    }
    pub(super) fn storage_key(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[4], Rotation::cur())
    }
    pub(super) fn storage_key_bytes(
        &self,
        meta: &mut VirtualCells<F>,
    ) -> [Expression<F>; N_BYTES_WORD] {
        self.key4_bytes
            .map(|limb| meta.query_advice(limb, Rotation::cur()))
    }

    pub(super) fn power_of_randomness(&self, meta: &mut VirtualCells<F>) -> &[Expression<F>] {
        &self.power_of_randomness
    }

    pub(super) fn tag_is(&self, meta: &mut VirtualCells<F>, tag: RwTableTag) -> Expression<F> {
        generate_lagrange_base_polynomial(
            self.tag(meta),
            tag as usize,
            RwTableTag::iter().map(|x| x as usize),
        )
    }

    pub(super) fn s_enable(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.s_enable, Rotation::cur())
    }
}
