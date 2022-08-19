//! Exponentiation verification circuit.

use eth_types::Field;
use gadgets::{
    mul_add::{MulAddChip, MulAddConfig},
    util::{and, not, Expr},
};
use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Selector},
    poly::Rotation,
};

use crate::{evm_circuit::util::constraint_builder::BaseConstraintBuilder, table::ExpTable};

/// Layout for the Exponentiation circuit.
#[derive(Clone, Debug)]
pub struct ExpCircuit<F> {
    /// Whether the row is a step.
    pub q_step: Selector,
    /// The incremental index in the circuit.
    pub idx: Column<Advice>,
    /// Whether this row is the last row in the circuit.
    pub is_last: Column<Advice>,
    /// The Exponentiation circuit's table.
    pub exp_table: ExpTable,
    /// Multiplication gadget for verification of each step.
    pub mul_gadget: MulAddConfig<F>,
    /// Boolean value to check whether intermediate_exponent is odd or even.
    pub remainder: Column<Advice>,
}

impl<F: Field> ExpCircuit<F> {
    /// Configure the exponentiation circuit.
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let q_step = meta.complex_selector();
        let idx = meta.advice_column();
        let is_last = meta.advice_column();
        let exp_table = ExpTable::construct(meta);
        let mul_gadget = MulAddChip::configure(meta, q_step);
        let remainder = meta.advice_column();

        meta.create_gate("exp circuit", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // base limbs MUST be the same across all steps.
            for i in 0..4 {
                cb.require_equal(
                    "base_limb[i] is the same across all steps",
                    meta.query_advice(exp_table.base_limb, Rotation(i)),
                    meta.query_advice(exp_table.base_limb, Rotation(i + 4)),
                );
            }

            // since we don't use the exp circuit for exponentiation by 0 or 1, the first
            // multiplication MUST equal `base*base == base^2`. Since we populate the
            // multiplication gadget in a reverse order, the first multiplication is
            // assigned to the last row.
            cb.condition(meta.query_advice(is_last, Rotation::cur()), |cb| {
                for (i, mul_gadget_col) in [
                    mul_gadget.col0,
                    mul_gadget.col1,
                    mul_gadget.col2,
                    mul_gadget.col3,
                ]
                .into_iter()
                .enumerate()
                {
                    cb.require_equal(
                        "if is_last is True: exp_table.base_limb[i] == mul_gadget.a[i]",
                        meta.query_advice(exp_table.base_limb, Rotation(i as i32)),
                        meta.query_advice(mul_gadget_col, Rotation(0)),
                    );
                    cb.require_equal(
                        "if is_last is True: exp_table.base_limb[i] == mul_gadget.b[i]",
                        meta.query_advice(exp_table.base_limb, Rotation(i as i32)),
                        meta.query_advice(mul_gadget_col, Rotation(1)),
                    );
                }
            });

            // For every step, the intermediate exponentiation MUST equal the result of
            // the corresponding multiplication.
            cb.require_equal(
                "intermediate exponentiation lo == mul_gadget.d_lo",
                meta.query_advice(exp_table.intermediate_exp_lo_hi, Rotation::cur()),
                meta.query_advice(mul_gadget.col2, Rotation(2)),
            );
            cb.require_equal(
                "intermediate exponentiation hi == mul_gadget.d_hi",
                meta.query_advice(exp_table.intermediate_exp_lo_hi, Rotation::next()),
                meta.query_advice(mul_gadget.col3, Rotation(2)),
            );

            // For every step, the MulAddChip's `c` MUST be 0, considering the equation `a *
            // b + c == d` applied ONLY for multiplication.
            cb.require_zero(
                "mul_gadget.c == 0",
                and::expr([
                    meta.query_advice(mul_gadget.col0, Rotation(2)),
                    meta.query_advice(mul_gadget.col1, Rotation(2)),
                ]),
            );

            // The intermediate exponent starts at the exponent, i.e.
            // intermediate_exponent[0] == exponent.
            // For every intermediate step, the intermediate exponent is reduced:
            // 1. intermediate_exponent::next == intermediate_exponent::cur - 1, if odd.
            // 2. intermediate_exponent::next == intermediate_exponent::cur/2, if even.
            let remainder_expr = meta.query_advice(remainder, Rotation::cur());
            cb.require_boolean("remainder is 0 or 1", remainder_expr.clone());

            // remainder == 1 => odd
            cb.condition(remainder_expr.clone(), |cb| {
                cb.require_equal(
                    "intermediate_exponent::next == intermediate_exponent::cur - 1",
                    meta.query_advice(exp_table.intermediate_exponent, Rotation::next()),
                    meta.query_advice(exp_table.intermediate_exponent, Rotation::cur()) - 1.expr(),
                );
            });
            // remainder == 0 => even
            cb.condition(not::expr(remainder_expr), |cb| {
                cb.require_equal(
                    "intermediate_exponent::next == intermediate_exponent::cur / 2",
                    meta.query_advice(exp_table.intermediate_exponent, Rotation::next()) * 2.expr(),
                    meta.query_advice(exp_table.intermediate_exponent, Rotation::cur()),
                );
            });

            // For the last step, the intermediate_exponent MUST be 2, since we do not cover
            // the case where exponent == 0 or exponent == 1 in exponentiation
            // circuit.
            cb.condition(meta.query_advice(is_last, Rotation::cur()), |cb| {
                cb.require_equal(
                    "if is_last is True: intermediate_exponent == 2",
                    meta.query_advice(exp_table.intermediate_exponent, Rotation::cur()),
                    2.expr(),
                );
            });

            cb.gate(meta.query_selector(q_step))
        });

        Self {
            q_step,
            idx,
            is_last,
            exp_table,
            mul_gadget,
            remainder,
        }
    }
}
