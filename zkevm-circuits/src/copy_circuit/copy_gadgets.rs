use super::{CURRENT, NEXT_ROW, NEXT_STEP};
use bus_mapping::circuit_input_builder::CopyDataType;
use eth_types::Field;
use gadgets::{
    binary_number::BinaryNumberConfig,
    util::{and, not, select, sum, Expr},
};
use halo2_proofs::plonk::{Advice, Column, Expression, VirtualCells};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};

/// Copy the parameters of the event through all rows of the event.
pub fn constrain_forward_parameters<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_continue: Expression<F>,
    id: Column<Advice>,
    tag: BinaryNumberConfig<CopyDataType, 4>,
    src_addr_end: Column<Advice>,
) {
    cb.condition(is_continue.expr(), |cb| {
        // Forward other fields to the next step.
        cb.require_equal(
            "rows[0].id == rows[2].id",
            meta.query_advice(id, CURRENT),
            meta.query_advice(id, NEXT_STEP),
        );
        cb.require_equal(
            "rows[0].tag == rows[2].tag",
            tag.value(CURRENT)(meta),
            tag.value(NEXT_STEP)(meta),
        );
        cb.require_equal(
            "rows[0].src_addr_end == rows[2].src_addr_end for non-last step",
            meta.query_advice(src_addr_end, CURRENT),
            meta.query_advice(src_addr_end, NEXT_STEP),
        );
    });
}

/// Update the counter of bytes and verify that all bytes are consumed.
pub fn constrain_bytes_left<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_first: Expression<F>,
    is_continue: Expression<F>,
    mask: Expression<F>,
    bytes_left: Column<Advice>,
) {
    let [current, next_row, next_step] =
        [CURRENT, NEXT_ROW, NEXT_STEP].map(|at| meta.query_advice(bytes_left, at));

    // Initial values derived from the event.
    cb.condition(is_first.expr(), |cb| {
        cb.require_equal("writer initial length", current.expr(), next_row);
    });

    // Decrement real_bytes_left for the next step, on non-masked rows.
    let new_value = current - not::expr(mask);
    // At the end, it must reach 0.
    let update_or_finish = select::expr(is_continue, next_step, 0.expr());
    cb.require_equal(
        "bytes_left[2] == bytes_left[0] - !mask, or 0 at the end",
        new_value,
        update_or_finish,
    );
}

/// Update the address.
pub fn constrain_address<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_continue: Expression<F>,
    front_mask: Expression<F>,
    addr: Column<Advice>,
) {
    cb.condition(is_continue, |cb| {
        // The address is incremented by 1, except in the front mask. There must be the
        // right amount of front mask until the row matches up with the
        // initial address of the event.
        let addr_diff = not::expr(front_mask);
        cb.require_equal(
            "rows[0].addr + !front_mask == rows[2].addr",
            meta.query_advice(addr, CURRENT) + addr_diff,
            meta.query_advice(addr, NEXT_STEP),
        );
    });
}

/// Update the RW counter and verify that all RWs requested by the event are consumed.
pub fn constrain_rw_counter<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    not_last: Expression<F>,
    is_rw_type: Expression<F>,
    is_word_end: Expression<F>,
    rw_counter: Column<Advice>,
    rwc_inc_left: Column<Advice>,
) {
    // Decrement rwc_inc_left for the next row, when an RW operation happens.
    let rwc_diff = is_rw_type.expr() * is_word_end.expr();
    let new_value = meta.query_advice(rwc_inc_left, CURRENT) - rwc_diff;
    // At the end, it must reach 0.
    let update_or_finish = select::expr(
        not_last.expr(),
        meta.query_advice(rwc_inc_left, NEXT_ROW),
        0.expr(),
    );
    cb.require_equal(
        "rwc_inc_left[2] == rwc_inc_left[0] - rwc_diff, or 0 at the end",
        new_value,
        update_or_finish,
    );

    // Maintain rw_counter based on rwc_inc_left. Their sum remains constant in all cases.
    cb.condition(not_last.expr(), |cb| {
        cb.require_equal(
            "rw_counter[0] + rwc_inc_left[0] == rw_counter[1] + rwc_inc_left[1]",
            meta.query_advice(rw_counter, CURRENT) + meta.query_advice(rwc_inc_left, CURRENT),
            meta.query_advice(rw_counter, NEXT_ROW) + meta.query_advice(rwc_inc_left, NEXT_ROW),
        );
    });
}

/// Maintain the index within words, looping between 0 and 31 inclusive.
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

/// Calculate the RLC of data within each word.
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

/// Calculate the RLC of the non-masked data.
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

/// Verify the rlc_acc field of the copy event against the value_acc of the data.
pub fn constrain_event_rlc_acc<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_last: Column<Advice>,
    // The RLCs to compare.
    value_acc: Column<Advice>,
    rlc_acc: Column<Advice>,
    // The flags to determine whether rlc_acc is requested from the event.
    is_precompiled: Column<Advice>,
    is_memory: Column<Advice>,
    is_tx_calldata: Column<Advice>,
    is_bytecode: Column<Advice>,
    tag: BinaryNumberConfig<CopyDataType, 4>,
) {
    // Forward rlc_acc from the event to all rows.
    let not_last = not::expr(meta.query_advice(is_last, CURRENT));
    cb.condition(not_last.expr(), |cb| {
        cb.require_equal(
            "rows[0].rlc_acc == rows[1].rlc_acc",
            meta.query_advice(rlc_acc, CURRENT),
            meta.query_advice(rlc_acc, NEXT_ROW),
        );
    });

    // Check the rlc_acc given in the event if any of:
    // - Precompile => *
    // - * => Precompile
    // - Memory => Bytecode
    // - TxCalldata => Bytecode
    // - * => RlcAcc
    let rlc_acc_cond = sum::expr([
        meta.query_advice(is_precompiled, CURRENT),
        meta.query_advice(is_precompiled, NEXT_ROW),
        and::expr([
            meta.query_advice(is_memory, CURRENT),
            meta.query_advice(is_bytecode, NEXT_ROW),
        ]),
        and::expr([
            meta.query_advice(is_tx_calldata, CURRENT),
            meta.query_advice(is_bytecode, NEXT_ROW),
        ]),
        tag.value_equals(CopyDataType::RlcAcc, NEXT_ROW)(meta),
    ]);

    cb.condition(rlc_acc_cond * meta.query_advice(is_last, NEXT_ROW), |cb| {
        cb.require_equal(
            "value_acc == rlc_acc on the last row",
            meta.query_advice(value_acc, NEXT_ROW),
            meta.query_advice(rlc_acc, NEXT_ROW),
        );
    });
}

/// Return (mask, mask at NEXT_STEP, front_mask).
pub fn constrain_mask<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_first: Expression<F>,
    is_continue: Expression<F>,
    mask: Column<Advice>,
    front_mask: Column<Advice>,
    forbid_front_mask: Expression<F>,
) -> (Expression<F>, Expression<F>, Expression<F>) {
    cb.condition(is_first.expr(), |cb| {
        // Apply the same constraints on the first reader and first writer rows.
        for rot in [CURRENT, NEXT_ROW] {
            let back_mask = meta.query_advice(mask, rot) - meta.query_advice(front_mask, rot);
            cb.require_zero("back_mask starts at 0", back_mask);
        }
    });

    // Split the mask into front and back segments.
    // If front_mask=1, then mask=1 and back_mask=0.
    // If back_mask=1, then mask=1 and front_mask=0.
    // Otherwise, mask=0.
    let mask_next = meta.query_advice(mask, NEXT_STEP);
    let mask = meta.query_advice(mask, CURRENT);
    let front_mask_next = meta.query_advice(front_mask, NEXT_STEP);
    let front_mask = meta.query_advice(front_mask, CURRENT);
    let back_mask_next = mask_next.expr() - front_mask_next.expr();
    let back_mask = mask.expr() - front_mask.expr();
    cb.require_boolean("mask is boolean", mask.expr());
    cb.require_boolean("front_mask is boolean", front_mask.expr());
    cb.require_boolean("back_mask is boolean", back_mask.expr());

    // The front mask comes before the back mask, with at least 1 non-masked byte
    // in-between.
    cb.condition(is_continue.expr(), |cb| {
        cb.require_boolean(
            "front_mask cannot go from 0 back to 1",
            front_mask.expr() - front_mask_next,
        );
        cb.require_boolean(
            "back_mask cannot go from 1 back to 0",
            back_mask_next.expr() - back_mask,
        );
        cb.require_zero(
            "front_mask is not immediately followed by back_mask",
            and::expr([front_mask.expr(), back_mask_next.expr()]),
        );
    });

    cb.condition(forbid_front_mask, |cb| {
        cb.require_zero(
            "front_mask = 0 by the end of the first word",
            front_mask.expr(),
        );
    });

    /* Note: other words may be completely masked, because reader and writer may have different word counts. A fully masked word is a no-op, not contributing to value_acc, and its word_rlc equals word_rlc_prev.
    cb.require_zero(
        "back_mask=0 at the start of the next word",
        and::expr([
            is_word_end.expr(),
            back_mask_next.expr(),
        ]),
    );*/

    (mask, mask_next, front_mask)
}
