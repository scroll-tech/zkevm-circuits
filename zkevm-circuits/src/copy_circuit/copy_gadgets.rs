use super::{CURRENT, NEXT_ROW, NEXT_STEP};
use eth_types::Field;
use gadgets::util::{not, select, Expr};
use halo2_proofs::plonk::{Advice, Column, Expression, VirtualCells};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};

pub fn constrain_word_index<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_first: Expression<F>,
    is_continue: Expression<F>,
    is_word_end: Expression<F>,
    word_index: Column<Advice>,
) {
    // Initial values derived from the event.
    cb.condition(is_first.expr(), |cb| {
        // Apply the same constraints on the first reader and first writer rows.
        for rot in [CURRENT, NEXT_ROW] {
            cb.require_zero("word_index starts at 0", meta.query_advice(word_index, rot));
        }
    });

    // Update the index into the current or next word.
    cb.condition(is_continue.expr(), |cb| {
        let inc_or_reset = select::expr(
            is_word_end.expr(),
            0.expr(),
            meta.query_advice(word_index, CURRENT) + 1.expr(),
        );
        cb.require_equal(
            "word_index increments or resets to 0",
            inc_or_reset,
            meta.query_advice(word_index, NEXT_STEP),
        );
    });
}

pub fn constrain_word_rlc<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_first: Expression<F>,
    is_continue: Expression<F>,
    is_word_end: Expression<F>,
    word_rlc: Column<Advice>,
    value: Column<Advice>,
    challenge: Expression<F>,
) {
    // Initial values derived from the event.
    cb.condition(is_first.expr(), |cb| {
        // Apply the same constraints on the first reader and first writer rows.
        for rot in [CURRENT, NEXT_ROW] {
            cb.require_equal(
                "word_rlc init to the first value",
                meta.query_advice(word_rlc, rot),
                meta.query_advice(value, rot),
            );
        }
    });

    // Accumulate the next value into the next word_rlc.
    cb.condition(is_continue.expr(), |cb| {
        let current_or_reset = select::expr(
            is_word_end.expr(),
            0.expr(),
            meta.query_advice(word_rlc, CURRENT),
        );
        let value = meta.query_advice(value, NEXT_STEP);
        let accumulated = current_or_reset.expr() * challenge + value;
        cb.require_equal(
            "value_word_rlc(2) == value_word_rlc(0) * r + value(2)",
            accumulated,
            meta.query_advice(word_rlc, NEXT_STEP),
        );
    });
}

pub fn constrain_value_rlc<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_first: Expression<F>,
    is_continue: Expression<F>,
    is_last: Column<Advice>,
    is_pad_next: Expression<F>,
    mask_next: Expression<F>,
    non_pad_non_mask: Column<Advice>,
    value_acc: Column<Advice>,
    value: Column<Advice>,
    challenge: Expression<F>,
) {
    // Initial values derived from the event.
    cb.condition(is_first.expr(), |cb| {
        // Apply the same constraints on the first reader and first writer rows.
        for rot in [CURRENT, NEXT_ROW] {
            cb.require_equal(
                "value_acc init to the first value, or 0 if padded or masked",
                meta.query_advice(value_acc, rot),
                meta.query_advice(value, rot) * meta.query_advice(non_pad_non_mask, rot),
            );
        }
    });

    // Accumulate the next value into the next value_acc.
    cb.condition(is_continue.expr(), |cb| {
        let current = meta.query_advice(value_acc, CURRENT);
        // If source padding, replace the value with 0.
        let value_or_pad = meta.query_advice(value, NEXT_STEP) * not::expr(is_pad_next.expr());
        let accumulated = current.expr() * challenge + value_or_pad;
        // If masked, copy the accumulator forward, otherwise update it.
        let copy_or_acc = select::expr(mask_next, current, accumulated);
        cb.require_equal(
            "value_acc(2) == value_acc(0) * r + value(2), or copy value_acc(0)",
            copy_or_acc,
            meta.query_advice(value_acc, NEXT_STEP),
        );
    });

    // Verify that the reader and writer have found the same value_acc from their non-masked data.
    cb.condition(meta.query_advice(is_last, NEXT_ROW), |cb| {
        cb.require_equal(
            "source value_acc == destination value_acc on the last row",
            meta.query_advice(value_acc, CURRENT),
            meta.query_advice(value_acc, NEXT_ROW),
        );
    });
}
