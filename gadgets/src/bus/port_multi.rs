use super::{
    batch_assigner::Assigner,
    bus_builder::{BusAssigner, BusBuilder},
    bus_chip::BusTerm,
    bus_codec::{BusCodecExpr, BusCodecVal, BusMessageExpr, BusMessageF},
    bus_port::{BusOpExpr, BusOpF},
    util::from_isize,
    Field,
};
use crate::util::{query_expression, Expr};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Expression, ThirdPhase},
    poly::Rotation,
};
use itertools::Itertools;
use std::{marker::PhantomData, ops::Mul};

/// PortBatchedChip does multiple bus operations per row. It manages its own helper column.
#[derive(Clone, Debug)]
pub struct PortBatchedChip<F> {
    helper: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: Field> PortBatchedChip<F> {
    /// Create a new bus port with multiple operations.
    pub fn connect<M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        enabled: Expression<F>,
        ops: Vec<BusOpExpr<F, M>>,
    ) -> Self {
        let helper = meta.advice_column_in(ThirdPhase);
        let helper_expr = query_expression(meta, |meta| meta.query_advice(helper, Rotation::cur()));

        PortBatched::connect(meta, bus_builder, enabled, ops, helper_expr);

        meta.annotate_lookup_any_column(helper, || "PortBatched_helper");

        Self {
            helper,
            _marker: PhantomData,
        }
    }

    /// Assign an operation.
    pub fn assign<M: BusMessageF<F>>(
        &self,
        bus_assigner: &mut BusAssigner<F, M>,
        offset: usize,
        ops: Vec<BusOpF<M>>,
    ) {
        PortBatched::assign(bus_assigner, offset, ops, self.helper, 0);
    }
}

/// Functions to add multiple operations to the bus, using only one helper cell. However, the degree
/// of input expressions is more limited than with the simple Port.
pub struct PortBatched;

impl PortBatched {
    /// Create a new bus port with multiple operations.
    /// The helper cell can be used for something else when not enabled.
    pub fn connect<F: Field, M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        enabled: Expression<F>,
        ops: Vec<BusOpExpr<F, M>>,
        helper: Expression<F>,
    ) {
        let term = Self::create_term(meta, bus_builder.codec(), enabled, ops, helper);
        bus_builder.add_term(term);
    }

    /// Assign an operation.
    pub fn assign<F: Field, M: BusMessageF<F>>(
        bus_assigner: &mut BusAssigner<F, M>,
        offset: usize,
        ops: Vec<BusOpF<M>>,
        helper: Column<Advice>,
        rotation: isize,
    ) {
        let (numer, denom) = Self::helper_fraction(bus_assigner.codec(), &ops);

        let cmd = Box::new(PortBatchedAssigner {
            offset,
            helper,
            rotation,
            numer,
        });

        for op in &ops {
            bus_assigner.op_counter().track_op(op);
        }
        bus_assigner.batch_assigner().assign_later(cmd, denom);
    }

    /// Return the degree of the constraints given these inputs.
    pub fn degree<F: Field, M: BusMessageExpr<F>>(
        codec: &BusCodecExpr<F, M>,
        enabled: Expression<F>,
        ops: Vec<BusOpExpr<F, M>>,
        helper: Expression<F>,
    ) -> usize {
        let total_term = helper * enabled.clone();
        let [constraint] = Self::constraint(codec, enabled, ops, total_term);
        constraint.degree()
    }

    fn create_term<F: Field, M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        codec: &BusCodecExpr<F, M>,
        enabled: Expression<F>,
        ops: Vec<BusOpExpr<F, M>>,
        helper: Expression<F>,
    ) -> BusTerm<F> {
        // term = helper, or 0 when not enabled.
        let total_term = helper * enabled.clone();

        meta.create_gate("bus access (multi)", |_| {
            Self::constraint(codec, enabled, ops, total_term.clone())
        });

        BusTerm::verified(total_term)
    }

    fn constraint<F: Field, M: BusMessageExpr<F>>(
        codec: &BusCodecExpr<F, M>,
        enabled: Expression<F>,
        ops: Vec<BusOpExpr<F, M>>,
        total_term: Expression<F>,
    ) -> [Expression<F>; 1] {
        // denoms[i] = compress(messages[i])
        let denoms = ops
            .iter()
            .map(|op| codec.compress(op.message()))
            .collect::<Vec<_>>();

        // other_denoms[i] = ∏ denoms[j] for j!=i
        // all_denoms = ∏ denoms[j] for all j
        let (other_denoms, all_denoms) = Self::product_of_others(denoms, 1.expr());

        // counts_times_others = ∑ counts[i] * other_denoms[i]
        let counts_times_others = ops
            .iter()
            .zip_eq(other_denoms.into_iter())
            .map(|(op, other)| op.count() * other)
            .reduce(|acc, term| acc + term)
            .unwrap_or(0.expr());

        // Verify that: term = enabled * ∑ counts[i] / compress(messages[i])
        //
        // With witness: helper = ∑ counts[i] / compress(messages[i])
        //
        // If `enabled = 0`, then `term = 0` by definition. In that case, the helper cell is not
        // constrained, so it can be used for something else.
        [total_term * all_denoms - counts_times_others * enabled]
    }

    /// Return the witness that must be assigned to the helper cell, as (numerator, denominator).
    fn helper_fraction<F: Field, M: BusMessageF<F>>(
        codec: &BusCodecVal<F, M>,
        ops: &[BusOpF<M>],
    ) -> (F, Value<F>) {
        // denoms[i] = compress(messages[i])
        let denoms = {
            let mut denoms = Vec::with_capacity(ops.len());
            for op in ops {
                let denom = codec.compress(op.message());
                if denom.is_none() {
                    return (F::zero(), Value::unknown());
                } else {
                    denom.map(|denom| denoms.push(denom));
                }
            }
            denoms
        };

        // other_denoms[i] = ∏ denoms[j] for j!=i
        // all_denoms = ∏ denoms[j] for all j
        let (other_denoms, all_denoms) = Self::product_of_others(denoms, F::one());

        // helper = ∑ counts[i] / compress(messages[i])
        //        = (∑ counts[i] * other_denoms[i]) / all_denoms
        let numer = ops
            .iter()
            .zip_eq(other_denoms.into_iter())
            .map(|(op, others)| from_isize::<F>(op.count()) * others)
            .reduce(|sum, term| sum + term)
            .unwrap_or(F::zero());

        (numer, Value::known(all_denoms))
    }

    /// Return products such that `others[i] = ∏ values[j] for j!=i`, and the product of all values.
    fn product_of_others<T>(values: Vec<T>, one: T) -> (Vec<T>, T)
    where
        T: Mul<Output = T> + Clone,
    {
        // all_afters[i] contains the product of all values after values[i] (non-inclusive).
        let all_afters = {
            let mut all_after = one.clone();
            let mut all_afters = Vec::with_capacity(values.len());
            for value in values.iter().rev() {
                all_afters.push(all_after.clone());
                all_after = all_after * value.clone();
            }
            all_afters.reverse();
            all_afters
        };

        // all_before at step i contains the product of all values before vals[i] (non-inclusive).
        let mut all_before = one;
        let mut all_others = Vec::with_capacity(values.len());
        for (value, all_after) in values.into_iter().zip(all_afters) {
            all_others.push(all_before.clone() * all_after);
            all_before = all_before * value;
        }

        (all_others, all_before)
    }
}

struct PortBatchedAssigner<F> {
    offset: usize,
    helper: Column<Advice>,
    rotation: isize,
    numer: F,
}

impl<F: Field> Assigner<F> for PortBatchedAssigner<F> {
    fn assign(&self, region: &mut Region<'_, F>, inversed_denom: F) -> (usize, F) {
        let term = self.numer * inversed_denom;

        region
            .assign_advice(
                || "PortBatched_helper",
                self.helper,
                (self.offset as isize + self.rotation) as usize,
                || Value::known(term),
            )
            .unwrap();

        (self.offset, term)
    }
}
