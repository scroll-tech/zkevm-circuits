use super::{CURRENT, NEXT_ROW, NEXT_STEP};
use eth_types::Field;
use gadgets::util::{select, Expr};
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

    cb.condition(is_continue.expr(), |cb| {
        // Update the index into the current or next word.
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
