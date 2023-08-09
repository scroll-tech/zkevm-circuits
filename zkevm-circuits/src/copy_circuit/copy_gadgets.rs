use super::{CURRENT, NEXT_ROW, NEXT_STEP};
use bus_mapping::{circuit_input_builder::CopyDataType, precompile::PrecompileCalls};
use eth_types::Field;
use gadgets::{
    binary_number::BinaryNumberConfig,
    is_equal::IsEqualConfig,
    util::{and, not, select, sum, Expr},
};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Expression, Fixed, VirtualCells};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};

#[allow(clippy::too_many_arguments)]
pub fn constrain_tag<F: Field>(
    meta: &mut ConstraintSystem<F>,
    q_enable: Column<Fixed>,
    tag: BinaryNumberConfig<CopyDataType, 4>,
    is_precompiled: Column<Advice>,
    is_tx_calldata: Column<Advice>,
    is_bytecode: Column<Advice>,
    is_memory: Column<Advice>,
    is_tx_log: Column<Advice>,
) {
    meta.create_gate("decode tag", |meta| {
        let enabled = meta.query_fixed(q_enable, CURRENT);
        let is_precompile = meta.query_advice(is_precompiled, CURRENT);
        let is_tx_calldata = meta.query_advice(is_tx_calldata, CURRENT);
        let is_bytecode = meta.query_advice(is_bytecode, CURRENT);
        let is_memory = meta.query_advice(is_memory, CURRENT);
        let is_tx_log = meta.query_advice(is_tx_log, CURRENT);
        let precompiles = sum::expr([
            tag.value_equals(
                CopyDataType::Precompile(PrecompileCalls::Ecrecover),
                CURRENT,
            )(meta),
            tag.value_equals(CopyDataType::Precompile(PrecompileCalls::Sha256), CURRENT)(meta),
            tag.value_equals(
                CopyDataType::Precompile(PrecompileCalls::Ripemd160),
                CURRENT,
            )(meta),
            tag.value_equals(CopyDataType::Precompile(PrecompileCalls::Identity), CURRENT)(meta),
            tag.value_equals(CopyDataType::Precompile(PrecompileCalls::Modexp), CURRENT)(meta),
            tag.value_equals(CopyDataType::Precompile(PrecompileCalls::Bn128Add), CURRENT)(meta),
            tag.value_equals(CopyDataType::Precompile(PrecompileCalls::Bn128Mul), CURRENT)(meta),
            tag.value_equals(
                CopyDataType::Precompile(PrecompileCalls::Bn128Pairing),
                CURRENT,
            )(meta),
            tag.value_equals(CopyDataType::Precompile(PrecompileCalls::Blake2F), CURRENT)(meta),
        ]);
        vec![
            // Match boolean indicators to their respective tag values.
            enabled.expr() * (is_precompile - precompiles),
            enabled.expr()
                * (is_tx_calldata - tag.value_equals(CopyDataType::TxCalldata, CURRENT)(meta)),
            enabled.expr()
                * (is_bytecode - tag.value_equals(CopyDataType::Bytecode, CURRENT)(meta)),
            enabled.expr() * (is_memory - tag.value_equals(CopyDataType::Memory, CURRENT)(meta)),
            enabled.expr() * (is_tx_log - tag.value_equals(CopyDataType::TxLog, CURRENT)(meta)),
        ]
    });
}

/// Verify that is_first is on a reader row and is_last is on a write row.
pub fn constrain_first_last<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    is_reader: Expression<F>,
    is_first: Expression<F>,
    is_last: Expression<F>,
) {
    cb.require_boolean("is_first is boolean", is_first.expr());
    cb.require_boolean("is_last is boolean", is_last.expr());
    cb.require_zero(
        "is_first == 0 when q_step == 0",
        and::expr([not::expr(is_reader.expr()), is_first.expr()]),
    );
    cb.require_zero(
        "is_last == 0 when q_step == 1",
        and::expr([is_last.expr(), is_reader.expr()]),
    );
}

/// Verify that is_last goes to 1 at some point.
pub fn constrain_must_terminate<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    q_enable: Column<Fixed>,
    is_last: Expression<F>,
) {
    // Prevent an event from spilling into the rows where constraints are disabled.
    // This also ensures that eventually is_last=1, because eventually q_enable=0.
    cb.require_zero(
        "the next row is enabled",
        and::expr([
            not::expr(is_last),
            not::expr(meta.query_fixed(q_enable, NEXT_ROW)),
        ]),
    );
}

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

/// Verify that when and after the address reaches the limit src_addr_end, zero-padding is enabled.
/// Return (is_pad, is_pad at NEXT_STEP).
#[allow(clippy::too_many_arguments)]
pub fn constrain_is_pad<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_reader: Expression<F>,
    is_first: Expression<F>,
    is_last: Column<Advice>,
    is_pad: Column<Advice>,
    addr: Column<Advice>,
    src_addr_end: Column<Advice>,
    is_src_end: &IsEqualConfig<F>,
) -> (Expression<F>, Expression<F>) {
    let [is_pad, is_pad_writer, is_pad_next] =
        [CURRENT, NEXT_ROW, NEXT_STEP].map(|at| meta.query_advice(is_pad, at));

    cb.require_boolean("is_pad is boolean", is_pad.expr());

    cb.condition(is_reader.expr(), |cb| {
        cb.require_zero("is_pad == 0 on writer rows", is_pad_writer);
    });

    // Detect when addr == src_addr_end
    let [is_src_end, is_src_end_next] = [CURRENT, NEXT_STEP].map(|at| {
        let addr = meta.query_advice(addr, at);
        let src_addr_end = meta.query_advice(src_addr_end, at);
        is_src_end.expr_at(meta, at, addr, src_addr_end)
    });

    cb.condition(is_first, |cb| {
        cb.require_equal(
            "is_pad starts at src_addr == src_addr_end",
            is_pad.expr(),
            is_src_end.expr(),
        );
    });

    let not_last_reader = is_reader * not::expr(meta.query_advice(is_last, NEXT_ROW));
    cb.condition(not_last_reader, |cb| {
        cb.require_equal(
            "is_pad=1 when src_addr == src_addr_end, otherwise it keeps the previous value",
            select::expr(is_src_end_next, 1.expr(), is_pad.expr()),
            is_pad_next.expr(),
        );
    });

    (is_pad, is_pad_next)
}

/// Verify the shape of the mask.
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

/// Verify non_pad_non_mask = !is_pad AND !mask.
pub fn constrain_non_pad_non_mask<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    non_pad_non_mask: Column<Advice>,
    is_pad: Expression<F>,
    mask: Expression<F>,
) {
    cb.require_equal(
        "non_pad_non_mask = !pad AND !mask",
        meta.query_advice(non_pad_non_mask, CURRENT),
        and::expr([not::expr(is_pad), not::expr(mask)]),
    );
}

/// Verify that the mask applies to the value written.
pub fn constrain_masked_value<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    mask: Expression<F>,
    value: Column<Advice>,
    value_prev: Column<Advice>,
) {
    // When a byte is masked, it must not be overwritten, so its value equals its value
    // before the write.
    cb.condition(mask, |cb| {
        cb.require_equal(
            "value == value_prev on masked rows",
            meta.query_advice(value, CURRENT),
            meta.query_advice(value_prev, CURRENT),
        );
    });
}

/// Calculate the RLC of the non-masked data.
#[allow(clippy::too_many_arguments)]
pub fn constrain_value_rlc<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_first: Expression<F>,
    is_continue: Expression<F>,
    is_last: Column<Advice>,
    non_pad_non_mask: Column<Advice>,
    is_pad_next: Expression<F>,
    mask_next: Expression<F>,
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
#[allow(clippy::too_many_arguments)]
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

/// Calculate the RLC of data within each word.
#[allow(clippy::too_many_arguments)]
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
#[allow(clippy::too_many_arguments)]
pub fn constrain_rw_counter<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_last: Expression<F>,      // The last row.
    is_last_step: Expression<F>, // Both the last reader and writer rows.
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
        not::expr(is_last.expr()),
        meta.query_advice(rwc_inc_left, NEXT_ROW),
        0.expr(),
    );
    cb.require_equal(
        "rwc_inc_left[2] == rwc_inc_left[0] - rwc_diff, or 0 at the end",
        new_value,
        update_or_finish,
    );

    // Maintain rw_counter based on rwc_inc_left. Their sum remains constant in all cases.
    cb.condition(not::expr(is_last.expr()), |cb| {
        cb.require_equal(
            "rw_counter[0] + rwc_inc_left[0] == rw_counter[1] + rwc_inc_left[1]",
            meta.query_advice(rw_counter, CURRENT) + meta.query_advice(rwc_inc_left, CURRENT),
            meta.query_advice(rw_counter, NEXT_ROW) + meta.query_advice(rwc_inc_left, NEXT_ROW),
        );
    });

    // Ensure that the word operation completes.
    cb.require_zero(
        "is_last_step requires is_word_end for word-based types",
        and::expr([
            is_last_step.expr(),
            is_rw_type.expr(),
            not::expr(is_word_end.expr()),
        ]),
    );
}
