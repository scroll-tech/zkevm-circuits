use super::{CURRENT, NEXT_ROW, NEXT_STEP};
use crate::{
    evm_circuit::{
        param::N_BYTES_MEMORY_ADDRESS,
        util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    },
    util::word,
};
use bus_mapping::circuit_input_builder::CopyDataType;
use eth_types::Field;
use gadgets::{
    binary_number::BinaryNumberConfig,
    is_equal::IsEqualConfig,
    less_than::LtConfig,
    util::{and, not, or, select, sum, Expr},
};
use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

#[allow(clippy::too_many_arguments)]
pub fn constrain_tag<F: Field>(
    meta: &mut ConstraintSystem<F>,
    q_enable: Column<Fixed>,
    tag: &BinaryNumberConfig<CopyDataType, { CopyDataType::N_BITS }>,
    is_tx_calldata: Column<Advice>,
    is_bytecode: Column<Advice>,
    is_memory: Column<Advice>,
    is_tx_log: Column<Advice>,
    is_access_list_address: Column<Advice>,
    is_access_list_storage_key: Column<Advice>,
) {
    meta.create_gate("decode tag", |meta| {
        let enabled = meta.query_fixed(q_enable, CURRENT);
        let is_tx_calldata = meta.query_advice(is_tx_calldata, CURRENT);
        let is_bytecode = meta.query_advice(is_bytecode, CURRENT);
        let is_memory = meta.query_advice(is_memory, CURRENT);
        let is_tx_log = meta.query_advice(is_tx_log, CURRENT);
        let is_access_list_address = meta.query_advice(is_access_list_address, CURRENT);
        let is_access_list_storage_key = meta.query_advice(is_access_list_storage_key, CURRENT);
        vec![
            // Match boolean indicators to their respective tag values.
            enabled.expr()
                * (is_tx_calldata - tag.value_equals(CopyDataType::TxCalldata, CURRENT)(meta)),
            enabled.expr()
                * (is_bytecode - tag.value_equals(CopyDataType::Bytecode, CURRENT)(meta)),
            enabled.expr() * (is_memory - tag.value_equals(CopyDataType::Memory, CURRENT)(meta)),
            enabled.expr() * (is_tx_log - tag.value_equals(CopyDataType::TxLog, CURRENT)(meta)),
            enabled.expr()
                * (is_access_list_address
                    - tag.value_equals(CopyDataType::AccessListAddresses, CURRENT)(meta)),
            enabled.expr()
                * (is_access_list_storage_key
                    - tag.value_equals(CopyDataType::AccessListStorageKeys, CURRENT)(meta)),
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
    tag: &BinaryNumberConfig<CopyDataType, { CopyDataType::N_BITS }>,
) {
    // If an event has started (tag != Padding on reader and writer rows), require q_enable=1 at the
    // next step. This prevents querying rows where constraints are disabled.
    //
    // The tag is then copied to the next step by constrain_forward_parameters. Eventually,
    // q_enable=0. By that point the tag must have switched to Padding, which is only possible with
    // is_last=1. This guarantees that all the final conditions are checked.
    let is_event = tag.value(CURRENT)(meta) - tag.constant_expr::<F>(CopyDataType::Padding);
    cb.condition(is_event, |cb| {
        cb.require_equal(
            "the next step is enabled",
            meta.query_fixed(q_enable, NEXT_STEP),
            1.expr(),
        );
    });
}

/// Copy the parameters of the event through all rows of the event.
pub fn constrain_forward_parameters<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_continue: Expression<F>,
    id: word::Word<Column<Advice>>,
    tag: BinaryNumberConfig<CopyDataType, { CopyDataType::N_BITS }>,
    src_addr_end: Column<Advice>,
) {
    cb.condition(is_continue.expr(), |cb| {
        // Forward other fields to the next step.
        cb.require_equal_word(
            "rows[0].id == rows[2].id",
            id.map(|limb| meta.query_advice(limb, CURRENT)),
            id.map(|limb| meta.query_advice(limb, NEXT_STEP)),
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

// /// Verify the shape of the mask.
// /// Return (mask, mask at NEXT_STEP, front_mask).
// pub fn constrain_mask<F: Field>(
//     cb: &mut BaseConstraintBuilder<F>,
//     meta: &mut VirtualCells<'_, F>,
//     is_first: Expression<F>,
//     is_continue: Expression<F>,
//     mask: Column<Advice>,
//     front_mask: Column<Advice>,
//     forbid_front_mask: Expression<F>,
// ) -> (Expression<F>, Expression<F>, Expression<F>) {
//     cb.condition(is_first.expr(), |cb| {
//         // Apply the same constraints on the first reader and first writer rows.
//         for rot in [CURRENT, NEXT_ROW] {
//             let back_mask = meta.query_advice(mask, rot) - meta.query_advice(front_mask, rot);
//             cb.require_zero("back_mask starts at 0", back_mask);
//         }
//     });
//
//     // Split the mask into front and back segments.
//     // If front_mask=1, then mask=1 and back_mask=0.
//     // If back_mask=1, then mask=1 and front_mask=0.
//     // Otherwise, mask=0.
//     let mask_next = meta.query_advice(mask, NEXT_STEP);
//     let mask = meta.query_advice(mask, CURRENT);
//     let front_mask_next = meta.query_advice(front_mask, NEXT_STEP);
//     let front_mask = meta.query_advice(front_mask, CURRENT);
//     let back_mask_next = mask_next.expr() - front_mask_next.expr();
//     let back_mask = mask.expr() - front_mask.expr();
//     cb.require_boolean("mask is boolean", mask.expr());
//     cb.require_boolean("front_mask is boolean", front_mask.expr());
//     cb.require_boolean("back_mask is boolean", back_mask.expr());
//
//     // The front mask comes before the back mask, with at least 1 non-masked byte
//     // in-between.
//     cb.condition(is_continue.expr(), |cb| {
//         cb.require_boolean(
//             "front_mask cannot go from 0 back to 1",
//             front_mask.expr() - front_mask_next,
//         );
//         cb.require_boolean(
//             "back_mask cannot go from 1 back to 0",
//             back_mask_next.expr() - back_mask,
//         );
//         cb.require_zero(
//             "front_mask is not immediately followed by back_mask",
//             and::expr([front_mask.expr(), back_mask_next.expr()]),
//         );
//     });
//
//     cb.condition(forbid_front_mask, |cb| {
//         cb.require_zero(
//             "front_mask = 0 by the end of the first word",
//             front_mask.expr(),
//         );
//     });
//
//     /* Note: other words may be completely masked, because reader and writer may have different
// word counts. A fully masked word is a no-op, not contributing to value_acc, and its word_rlc
// equals word_rlc_prev.     cb.require_zero(
//         "back_mask=0 at the start of the next word",
//         and::expr([
//             is_word_end.expr(),
//             back_mask_next.expr(),
//         ]),
//     );*/
//
//     (mask, mask_next, front_mask)
// }

/// Verify non_pad_non_mask = !is_pad AND !mask.
pub fn constrain_non_pad_non_mask<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    non_pad_non_mask: [Column<Advice>; 16],
    is_front_mask: [Expression<F>; 16],
    is_not_back_mask: [Expression<F>; 16],
    is_inbound_read: [Expression<F>; 16],
) {
    non_pad_non_mask
        .into_iter()
        .zip(
            is_front_mask
                .into_iter()
                .zip(is_not_back_mask)
                .zip(is_inbound_read),
        )
        .for_each(
            |(non_pad_non_mask, ((is_front_mask, is_not_back_mask), is_inbound_read))| {
                cb.require_equal(
                    "non_pad_non_mask = !is_pad AND is_not_front_mask AND is_inbound_read",
                    meta.query_advice(non_pad_non_mask, CURRENT),
                    and::expr([not::expr(is_front_mask), is_not_back_mask, is_inbound_read]),
                );
            },
        );
}

// /// Verify that the mask applies to the value written.
// pub fn constrain_masked_value<F: Field>(
//     cb: &mut BaseConstraintBuilder<F>,
//     meta: &mut VirtualCells<'_, F>,
//     mask: Expression<F>,
//     value: Column<Advice>,
//     value_prev: Column<Advice>,
// ) {
//     // When a byte is masked, it must not be overwritten, so its value equals its value
//     // before the write.
//     cb.condition(mask, |cb| {
//         cb.require_equal(
//             "value == value_prev on masked rows",
//             meta.query_advice(value, CURRENT),
//             meta.query_advice(value_prev, CURRENT),
//         );
//     });
// }

/// Calculate the RLC of the non-masked data.
#[allow(clippy::too_many_arguments)]
pub fn constrain_value_rlc<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_first: Expression<F>,
    is_continue: Expression<F>,
    is_last: Column<Advice>,
    non_pad_non_mask: [Column<Advice>; 16],
    is_inbound_read: [LtConfig<F, N_BYTES_MEMORY_ADDRESS>; 16],
    value_acc: Column<Advice>,
    value_limbs: [Column<Advice>; 16],
    challenge: Expression<F>,
) {
    let calc_rlc = |meta: &mut VirtualCells<'_, F>, acc: Expression<F>, rot: Rotation| {
        let value_exprs = value_limbs.map(|limb| meta.query_advice(limb, rot));
        let non_pad_non_mask_exprs = non_pad_non_mask.map(|col| meta.query_advice(col, rot));
        value_exprs
            .into_iter()
            .zip(non_pad_non_mask_exprs)
            .zip(
                is_inbound_read
                    .clone()
                    .map(|chip| chip.is_lt(meta, Some(rot))),
            )
            .fold(acc, |acc, ((limb, non_pad_non_mask), is_inbound_read)| {
                let value = select::expr(is_inbound_read, limb, 0.expr());
                select::expr(
                    non_pad_non_mask,
                    acc.expr() * challenge.clone() + value,
                    acc,
                )
            })
    };

    // Initial values derived from the event.
    cb.condition(is_first.expr(), |cb| {
        // Apply the same constraints on the first reader and first writer rows.
        for rot in [CURRENT, NEXT_ROW] {
            cb.require_equal(
                "value_acc init to the first value, or 0 if padded or masked",
                meta.query_advice(value_acc, rot),
                calc_rlc(meta, 0.expr(), rot),
            );
        }
    });

    // Accumulate the next value into the next value_acc.
    cb.condition(is_continue.expr(), |cb| {
        let current = meta.query_advice(value_acc, CURRENT);
        cb.require_equal(
            "value_acc(2) == value_acc(0) * r + value(2), or copy value_acc(0)",
            calc_rlc(meta, current.expr(), NEXT_STEP),
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
    is_bytecode: Column<Advice>,
    tag: BinaryNumberConfig<CopyDataType, { CopyDataType::N_BITS }>,
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
    // - RlcAcc => *
    // - * => RlcAcc
    // - * => Bytecode
    // See also `CopyEvent::has_rlc()`
    let rlc_acc_cond = sum::expr([
        tag.value_equals(CopyDataType::RlcAcc, CURRENT)(meta),
        tag.value_equals(CopyDataType::RlcAcc, NEXT_ROW)(meta),
        meta.query_advice(is_bytecode, NEXT_ROW),
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

/// Update the address.
pub fn constrain_address<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_continue: Expression<F>,
    addr: Column<Advice>,
) {
    cb.condition(is_continue, |cb| {
        cb.require_equal(
            "rows[0].addr + 16 == rows[2].addr",
            meta.query_advice(addr, CURRENT) + 16.expr(),
            meta.query_advice(addr, NEXT_STEP),
        );
    });
}

/// constrain id(src_id, dest_id). id_hi = 0
pub fn constrain_id<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    //_is_bytecode: Column<Advice>,
    is_tx_log: Column<Advice>,
    is_tx_calldata: Column<Advice>,
    is_memory: Column<Advice>,
    id: word::Word<Column<Advice>>,
    is_pad: Column<Advice>,
) {
    let cond = or::expr([
        //meta.query_advice(is_bytecode, CURRENT),
        meta.query_advice(is_tx_log, CURRENT),
        meta.query_advice(is_tx_calldata, CURRENT),
        meta.query_advice(is_memory, CURRENT),
    ]) * not::expr(meta.query_advice(is_pad, CURRENT));
    cb.condition(cond, |cb| {
        cb.require_zero("id_hi == 0", meta.query_advice(id.hi(), CURRENT))
    });
}

/// Update the RW counter and verify that all RWs requested by the event are consumed.
#[allow(clippy::too_many_arguments)]
pub fn constrain_rw_counter<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    meta: &mut VirtualCells<'_, F>,
    is_last: Expression<F>, // The last row.
    is_rw_type: Expression<F>,
    rw_counter: Column<Advice>,
    rwc_inc_left: Column<Advice>,
) {
    // Decrement rwc_inc_left for the next row, when an RW operation happens.
    let rwc_diff = is_rw_type.expr();
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
}
