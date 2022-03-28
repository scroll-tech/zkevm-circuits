use super::param::{
    N_BITS_ADDRESS, N_BITS_FIELD_TAG, N_BITS_ID, N_BITS_TAG, N_LIMBS_ACCOUNT_ADDRESS,
};
use crate::evm_circuit::{
    param::N_BYTES_WORD,
    table::RwTableTag,
    util::{
        constraint_builder::BaseConstraintBuilder, math_gadget::generate_lagrange_base_polynomial,
    },
};
use crate::util::Expr;
use eth_types::Address;
use eth_types::{Field, ToScalar};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use strum::IntoEnumIterator;
// use core::cmp::max;
// use core::ops::{Add, Mul};
// use ff::Field;
// use std::ops::{Neg, Sub};

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
        rw_counter: Column<Advice>,
    ) -> Self {
        Self {
            cb: BaseConstraintBuilder::new(MAX_DEGREE),
            rw_counter,
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
            power_of_randomness,
        }
    }

    pub(super) fn tag(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[0], Rotation::cur())
    }

    // tx_id or call_id if applicable. 0 otherwise.
    pub(super) fn id(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[1], Rotation::cur())
    }

    // stack, memory, or account address depending on the row's tag. 0 otherwise.
    pub(super) fn address(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.keys[2], Rotation::cur())
    }

    pub(super) fn address_delta(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        self.address(meta) - meta.query_advice(self.keys[2], Rotation::prev())
    }

    pub(super) fn address_limbs(
        &self,
        meta: &mut VirtualCells<F>,
    ) -> [Expression<F>; N_LIMBS_ACCOUNT_ADDRESS] {
        self.key2_limbs
            .map(|limb| meta.query_advice(limb, Rotation::cur()))
    }

    pub(super) fn address_from_limbs(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        from_digits(&self.address_limbs(meta), (1u64 << 16).expr())
    }

    pub(super) fn field_tag(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
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

    pub(super) fn power_of_randomness(&self, _meta: &mut VirtualCells<F>) -> &[Expression<F>] {
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

    pub(super) fn rw_counter(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.rw_counter, Rotation::cur())
    }

    pub(super) fn rw_counter_delta(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        self.rw_counter(meta) - meta.query_advice(self.rw_counter, Rotation::prev())
    }

    pub(super) fn sort_keys_delta(
        &self,
        meta: &mut VirtualCells<F>,
    ) -> (Expression<F>, Expression<F>) {
        let sort_keys_curr = sort_keys(
            self.tag(meta),
            self.id(meta),
            self.address(meta),
            self.field_tag(meta),
            self.storage_key_bytes(meta),
        );

        let sort_keys_prev = sort_keys(
            meta.query_advice(self.keys[0], Rotation::prev()),
            meta.query_advice(self.keys[1], Rotation::prev()),
            meta.query_advice(self.keys[2], Rotation::prev()),
            meta.query_advice(self.keys[3], Rotation::prev()),
            self.key4_bytes
                .map(|byte| meta.query_advice(byte, Rotation::prev())),
        );

        (
            sort_keys_curr.0 - sort_keys_prev.0,
            sort_keys_curr.1 - sort_keys_prev.1,
        )
    }
}

pub(super) fn sort_key_values<F: Field>(
    tag: RwTableTag,
    id: u64,
    address: Address,
    field_tag: u64,
    storage_key_bytes: [u8; 32],
) -> (F, F) {
    let (a, b) = sort_keys(
        tag.expr(),
        id.expr(),
        Expression::Constant(address.to_scalar().unwrap()),
        field_tag.expr(),
        storage_key_bytes.map(|x| x.expr()),
    );
    (
        evaluate_constant_expression(a),
        evaluate_constant_expression(b),
    )
}

// Pack tag, id, address, field tag, and most significant X bytes of storage key
// into one field element, and the remaining Y bytes of storage key into a
// second field element.
fn sort_keys<F: FieldExt>(
    tag: Expression<F>,
    id: Expression<F>,
    address: Expression<F>,
    field_tag: Expression<F>,
    storage_key_bytes: [Expression<F>; 32],
) -> (Expression<F>, Expression<F>) {
    let n_bits_remaining = F::CAPACITY - N_BITS_TAG - N_BITS_ID - N_BITS_ADDRESS - N_BITS_FIELD_TAG;
    let n_bytes_remaining = (n_bits_remaining / 8) as usize;

    let mut key_0 = tag;
    key_0 = key_0 * (1u64 << N_BITS_ID).expr() + id;
    key_0 = key_0 * (1u64 << N_BITS_ADDRESS / 4).expr().square().square() + address;
    key_0 = key_0 * (1u64 << N_BITS_FIELD_TAG).expr() + field_tag;
    key_0 = key_0 * (1u64 << n_bits_remaining).expr()
        + from_digits(&storage_key_bytes[..n_bytes_remaining], (1u64 << 16).expr());

    let key_1 = from_digits(&storage_key_bytes[n_bytes_remaining..], (1u64 << 16).expr());

    (key_0, key_1)
}

fn from_digits<F: FieldExt>(digits: &[Expression<F>], base: Expression<F>) -> Expression<F> {
    digits
        .iter()
        .fold(Expression::Constant(F::zero()), |result, digit| {
            digit.clone() + result * base.clone()
        })
}

fn evaluate_constant_expression<F: Field>(e: Expression<F>) -> F {
    e.evaluate(
        &|x| x,
        &|_| unreachable!(),
        &|_, _, _| unreachable!(),
        &|_, _, _| unreachable!(),
        &|_, _, _| unreachable!(),
        &F::neg,
        &F::add,
        &F::mul,
        &|_, _| unreachable!(),
    )
}
