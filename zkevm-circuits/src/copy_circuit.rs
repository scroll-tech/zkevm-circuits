//! The Copy circuit implements constraints and lookups for read-write steps for
//! copied bytes while execution opcodes such as CALLDATACOPY, CODECOPY, LOGS,
//! etc.
pub(crate) mod util;

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;
#[cfg(any(feature = "test", test))]
mod test;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub use dev::CopyCircuit as TestCopyCircuit;

use bus_mapping::{
    circuit_input_builder::{CopyDataType, CopyEvent},
    precompile::PrecompileCalls,
};
use eth_types::{Field, Word};

use gadgets::{
    binary_number::BinaryNumberChip,
    is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction},
    less_than::{LtChip, LtConfig, LtInstruction},
    util::{and, not, select, sum, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use std::{collections::BTreeMap, marker::PhantomData};

#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{
        BytecodeFieldTag, BytecodeTable, CopyTable, LookupTable, RwTable, RwTableTag,
        TxContextFieldTag, TxTable,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
    witness::{Bytecode, RwMap, Transaction},
};

/// The rw table shared between evm circuit and state circuit
#[derive(Clone, Debug)]
pub struct CopyCircuitConfig<F> {
    /// Whether this row denotes a step. A read row is a step and a write row is
    /// not.
    pub q_step: Selector,
    /// Whether the row is the last read-write pair for a copy event.
    pub is_last: Column<Advice>,
    /// The value copied in this copy step.
    pub value: Column<Advice>,
    /// The value before the write.
    pub value_prev: Column<Advice>,
    /// The word value for memory lookup.
    pub value_word_rlc: Column<Advice>,
    /// The word value for memory lookup, before the write.
    pub value_word_rlc_prev: Column<Advice>,
    /// The index of the current byte within a word [0..31].
    pub word_index: Column<Advice>,
    /// mask indicates when a row is not part of the copy, but it is needed to complete the front
    /// or the back of the first or last memory word.
    pub mask: Column<Advice>,
    /// Whether the row is part of the front mask, before the copy data.
    pub front_mask: Column<Advice>,
    /// Random linear combination accumulator of the non-masked copied data.
    pub value_acc: Column<Advice>,
    /// Whether the row is padding for out-of-bound reads when source address >= src_addr_end.
    pub is_pad: Column<Advice>,
    /// In case of a bytecode tag, this denotes whether or not the copied byte
    /// is an opcode or push data byte.
    pub is_code: Column<Advice>,
    /// Whether this row is part of an event (versus filler rows).
    pub is_event: Column<Advice>,
    /// Indicates whether or not the copy event copies bytes to a precompiled call or copies bytes
    /// from a precompiled call back to caller.
    pub is_precompiled: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_tx_calldata: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_bytecode: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_memory: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_tx_log: Column<Advice>,
    /// Whether the row is enabled or not.
    pub q_enable: Column<Fixed>,
    /// The Copy Table contains the columns that are exposed via the lookup
    /// expressions
    pub copy_table: CopyTable,
    /// Lt chip to check: src_addr < src_addr_end.
    /// Since `src_addr` and `src_addr_end` are u64, 8 bytes are sufficient for
    /// the Lt chip.
    pub addr_lt_addr_end: LtConfig<F, 8>,
    /// Whether this is the end of a word (last byte).
    pub is_word_end: IsEqualConfig<F>,
    /// non pad and non mask witness to reduce the degree of lookups.
    pub non_pad_non_mask: Column<Advice>,
    // External tables
    /// TxTable
    pub tx_table: TxTable,
    /// RwTable
    pub rw_table: RwTable,
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
}

/// Circuit configuration arguments
pub struct CopyCircuitConfigArgs<F: Field> {
    /// TxTable
    pub tx_table: TxTable,
    /// RwTable
    pub rw_table: RwTable,
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
    /// CopyTable
    pub copy_table: CopyTable,
    /// q_enable
    pub q_enable: Column<Fixed>,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for CopyCircuitConfig<F> {
    type ConfigArgs = CopyCircuitConfigArgs<F>;

    /// Configure the Copy Circuit constraining read-write steps and doing
    /// appropriate lookups to the Tx Table, RW Table and Bytecode Table.
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            tx_table,
            rw_table,
            bytecode_table,
            copy_table,
            q_enable,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_step = meta.complex_selector();
        let is_last = meta.advice_column();
        let value = meta.advice_column();
        let value_prev = meta.advice_column();

        // RLC accumulators in the second phase.
        let value_word_rlc = meta.advice_column_in(SecondPhase);
        let value_word_rlc_prev = meta.advice_column_in(SecondPhase);
        let value_acc = meta.advice_column_in(SecondPhase);

        let is_code = meta.advice_column();
        let (is_event, is_precompiled, is_tx_calldata, is_bytecode, is_memory, is_tx_log) = (
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        );
        let is_pad = meta.advice_column();
        let is_first = copy_table.is_first;
        let id = copy_table.id;
        let addr = copy_table.addr;
        let src_addr_end = copy_table.src_addr_end;
        let real_bytes_left = copy_table.real_bytes_left;
        let word_index = meta.advice_column();
        let mask = meta.advice_column();
        let front_mask = meta.advice_column();

        let rlc_acc = copy_table.rlc_acc;
        let rw_counter = copy_table.rw_counter;
        let rwc_inc_left = copy_table.rwc_inc_left;
        let tag = copy_table.tag;

        // annotate table columns
        tx_table.annotate_columns(meta);
        rw_table.annotate_columns(meta);
        bytecode_table.annotate_columns(meta);
        copy_table.annotate_columns(meta);

        let addr_lt_addr_end = LtChip::configure(
            meta,
            |meta| meta.query_selector(q_step),
            |meta| meta.query_advice(addr, Rotation::cur()),
            |meta| meta.query_advice(src_addr_end, Rotation::cur()),
        );

        let is_word_end = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enable, Rotation::cur()),
            |meta| meta.query_advice(word_index, Rotation::cur()),
            |_meta| 31.expr(),
        );

        let non_pad_non_mask = meta.advice_column();

        meta.create_gate("decode tag", |meta| {
            let enabled = meta.query_fixed(q_enable, Rotation::cur());
            let is_event = meta.query_advice(is_event, Rotation::cur());
            let is_precompile = meta.query_advice(is_precompiled, Rotation::cur());
            let is_tx_calldata = meta.query_advice(is_tx_calldata, Rotation::cur());
            let is_bytecode = meta.query_advice(is_bytecode, Rotation::cur());
            let is_memory = meta.query_advice(is_memory, Rotation::cur());
            let is_tx_log = meta.query_advice(is_tx_log, Rotation::cur());
            let precompiles = sum::expr([
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Ecrecover),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Sha256),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Ripemd160),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Identity),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Modexp),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Bn128Add),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Bn128Mul),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Bn128Pairing),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Blake2F),
                    Rotation::cur(),
                )(meta),
            ]);
            vec![
                // If a row is anything but padding (filler of the table), it is in an event.
                enabled.expr()
                    * ((1.expr() - is_event.expr())
                        - tag.value_equals(CopyDataType::Padding, Rotation::cur())(meta)),
                // Match boolean indicators to their respective tag values.
                enabled.expr() * (is_precompile - precompiles),
                enabled.expr()
                    * (is_tx_calldata
                        - tag.value_equals(CopyDataType::TxCalldata, Rotation::cur())(meta)),
                enabled.expr()
                    * (is_bytecode
                        - tag.value_equals(CopyDataType::Bytecode, Rotation::cur())(meta)),
                enabled.expr()
                    * (is_memory - tag.value_equals(CopyDataType::Memory, Rotation::cur())(meta)),
                enabled.expr()
                    * (is_tx_log - tag.value_equals(CopyDataType::TxLog, Rotation::cur())(meta)),
            ]
        });

        meta.create_gate("verify row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_first = meta.query_advice(is_first, Rotation::cur());
            cb.require_boolean(
                "is_first is boolean",
                is_first.expr(),
            );
            cb.require_boolean(
                "is_last is boolean",
                meta.query_advice(is_last, Rotation::cur()),
            );
            cb.require_zero(
                "is_first == 0 when q_step == 0",
                and::expr([
                    not::expr(meta.query_selector(q_step)),
                    is_first.expr(),
                ]),
            );
            cb.require_zero(
                "is_last == 0 when q_step == 1",
                and::expr([
                    meta.query_advice(is_last, Rotation::cur()),
                    meta.query_selector(q_step),
                ]),
            );
            cb.require_equal(
                "non_pad_non_mask = !pad AND !mask",
                meta.query_advice(non_pad_non_mask, Rotation::cur()),
                and::expr([
                    not::expr(meta.query_advice(is_pad, Rotation::cur())),
                    not::expr(meta.query_advice(mask, Rotation::cur())),
                ]),
            );
            // On a masked row, the value is the value_prev.
            cb.condition(
                meta.query_advice(mask, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "value == value_prev on masked rows",
                        meta.query_advice(value, Rotation::cur()),
                        meta.query_advice(value_prev, Rotation::cur()),
                    );
                },
            );

            // Whether this row is part of an event.
            let is_event = meta.query_advice(is_event, Rotation::cur());

            let is_last_step = meta.query_advice(is_last, Rotation::cur())
                + meta.query_advice(is_last, Rotation::next());

            // Whether this row is part of an event but not the last step. When true, the next step is derived from the current step.
            let is_continue = is_event.expr() - is_last_step.expr();

            // Prevent an event from spilling into the disabled rows. This also ensures that eventually is_last=1.
            cb.require_zero("the next row is enabled", is_continue.expr() * not::expr(meta.query_fixed(q_enable, Rotation::next())));

            let is_word_end = is_word_end.is_equal_expression.expr();

            // Apply the same constraints for the RLCs of words before and after the write.
            let word_rlc_both = [
                (value_word_rlc, value),
                (value_word_rlc_prev, value_prev),
            ];

            // Initial values derived from the event.
            cb.condition(is_first.expr(),
                |cb| {
                    // Apply the same constraints on the first reader and first writer rows.
                    for rot in [Rotation::cur(), Rotation::next()] {
                        cb.require_zero("word_index starts at 0", meta.query_advice(word_index, rot));

                        let back_mask = meta.query_advice(mask, rot) - meta.query_advice(front_mask, rot);
                        cb.require_zero("back_mask starts at 0", back_mask);

                        cb.require_equal(
                            "value_acc init to the first value, or 0 if padded or masked",
                            meta.query_advice(value_acc, rot),
                            meta.query_advice(value, rot) * meta.query_advice(non_pad_non_mask, rot),
                        );

                        for (word_rlc, value) in word_rlc_both {
                            cb.require_equal(
                                "word_rlc init to the first value",
                                meta.query_advice(word_rlc, rot),
                                meta.query_advice(value, rot),
                            );
                        }
                    }
                },
            );

            cb.condition(is_continue.expr(),
                |cb| {

                    // Update the index into the current or next word.
                    let inc_or_reset = select::expr(
                      is_word_end.expr(),
                        0.expr(),
                        meta.query_advice(word_index, Rotation::cur()) + 1.expr(),
                    );
                    cb.require_equal(
                        "word_index increments or resets to 0",
                        inc_or_reset,
                        meta.query_advice(word_index, Rotation(2)),
                    );

                    // Accumulate the next value into the next word_rlc.
                    for (word_rlc, value) in word_rlc_both {
                        let current_or_reset = select::expr(is_word_end.expr(),
                            0.expr(),
                            meta.query_advice(word_rlc, Rotation::cur()),
                        );
                        let value = meta.query_advice(value, Rotation(2));
                        let accumulated = current_or_reset.expr() * challenges.evm_word() + value;
                        cb.require_equal(
                            "value_word_rlc(2) == value_word_rlc(0) * r + value(2)",
                            accumulated,
                            meta.query_advice(word_rlc, Rotation(2)),
                        );
                    }
                },
            );

            // Split the mask into front and back segments.
            // If front_mask=1, then mask=1 and back_mask=0.
            // If back_mask=1, then mask=1 and front_mask=0.
            // Otherwise, mask=0.
            let mask_next = meta.query_advice(mask, Rotation(2));
            let mask = meta.query_advice(mask, Rotation::cur());
            let front_mask_next = meta.query_advice(front_mask, Rotation(2));
            let front_mask = meta.query_advice(front_mask, Rotation::cur());
            let back_mask_next = mask_next.expr() - front_mask_next.expr();
            let back_mask = mask.expr() - front_mask.expr();
            cb.require_boolean("mask is boolean", mask.expr());
            cb.require_boolean("front_mask is boolean", front_mask.expr());
            cb.require_boolean("back_mask is boolean", back_mask.expr());

            // The front mask comes before the back mask, with at least 1 non-masked byte in-between.
            cb.condition(is_continue.expr(),
                |cb| {
                    cb.require_boolean("front_mask cannot go from 0 back to 1", front_mask.expr() - front_mask_next);
                    cb.require_boolean("back_mask cannot go from 1 back to 0", back_mask_next.expr() - back_mask);
                    cb.require_zero("front_mask is not immediately followed by back_mask",
                        and::expr([
                            front_mask.expr(),
                            back_mask_next.expr(),
                        ]),
                    );
            });

            // The first word must not be completely masked.
            // LOG has no front mask at all.
            let is_tx_log = meta.query_advice(is_tx_log, Rotation::cur());
            cb.condition(is_word_end.expr() + is_tx_log.expr(), |cb| {
                // The first 31 bytes may be front_mask, but not the last byte of the first word.
                cb.require_zero("front_mask = 0 by the end of the first word", front_mask.expr());
            });

            /* Note: other words may be completely masked, because reader and writer may have different word counts. A fully masked word is a no-op, not contributing to value_acc, and its word_rlc equals word_rlc_prev.
            cb.require_zero(
                "back_mask=0 at the start of the next word",
                and::expr([
                    is_word_end.expr(),
                    back_mask_next.expr(),
                ]),
            );*/

            // Decrement real_bytes_left for the next step, on non-masked rows. At the end, it must reach 0.
            {
                let next_value = meta.query_advice(real_bytes_left, Rotation::cur()) - not::expr(mask.expr());
                let update_or_finish = select::expr(is_continue.expr(), meta.query_advice(real_bytes_left, Rotation(2)), 0.expr());
                cb.require_equal(
                    "real_bytes_left[2] == real_bytes_left[0] - !mask, or 0 at the end",
                    next_value,
                    update_or_finish,
                );
            }

            // Decrement rwc_inc_left for the next row, when an RW operation happens. At the end, it must reach 0.
            let is_rw_type = meta.query_advice(is_memory, Rotation::cur()) + is_tx_log.expr();
            {
                let rwc_diff = is_rw_type.expr() * is_word_end.expr();
                let next_value = meta.query_advice(rwc_inc_left, Rotation::cur()) - rwc_diff;
                let update_or_finish = select::expr(
                    meta.query_advice(is_last, Rotation::cur()),
                    0.expr(),
                    meta.query_advice(rwc_inc_left, Rotation::next()),
                );
                cb.require_equal(
                    "rwc_inc_left[2] == rwc_inc_left[0] - rwc_diff, or 0 at the end",
                    next_value,
                    update_or_finish,
                );
            }

            // Maintain rw_counter based on rwc_inc_left. Their sum remains constant in all cases.
            cb.condition(
                not::expr(meta.query_advice(is_last, Rotation::cur())),
                |cb| {
                    cb.require_equal(
                        "rows[0].rw_counter + rows[0].rwc_inc_left == rows[1].rw_counter + rows[1].rwc_inc_left",
                        meta.query_advice(rw_counter, Rotation::cur()) + meta.query_advice(rwc_inc_left, Rotation::cur()),
                        meta.query_advice(rw_counter, Rotation::next()) + meta.query_advice(rwc_inc_left, Rotation::next()),
                    );
                }
            );

            // Ensure that the word operation completes.
            cb.require_zero("is_last_step requires is_word_end for word-based types",
                and::expr([
                    is_last_step.expr(),
                    is_rw_type.expr(),
                    not::expr(is_word_end.expr()),
                ]),
            );

            // Derive the next step from the current step.
            cb.condition(is_continue.expr(),
            |cb| {

                    // The address is incremented by 1, except in the front mask. There must be the right amount
                    // of front mask until the row matches up with the initial address of the event.
                    let addr_diff = not::expr(front_mask.expr());
                    cb.require_equal(
                        "rows[0].addr + !front_mask == rows[2].addr",
                        meta.query_advice(addr, Rotation::cur()) + addr_diff,
                        meta.query_advice(addr, Rotation(2)),
                    );

                    // Forward other fields to the next step.
                    cb.require_equal(
                        "rows[0].id == rows[2].id",
                        meta.query_advice(id, Rotation::cur()),
                        meta.query_advice(id, Rotation(2)),
                    );
                    cb.require_equal(
                        "rows[0].tag == rows[2].tag",
                        tag.value(Rotation::cur())(meta),
                        tag.value(Rotation(2))(meta),
                    );
                    cb.require_equal(
                        "rows[0].src_addr_end == rows[2].src_addr_end for non-last step",
                        meta.query_advice(src_addr_end, Rotation::cur()),
                        meta.query_advice(src_addr_end, Rotation(2)),
                    );

                    // Accumulate the next value into the next value_acc.
                    {
                        let current = meta.query_advice(value_acc, Rotation::cur());
                        // If source padding, replace the value with 0.
                        let value_or_pad = meta.query_advice(value, Rotation(2)) * not::expr(meta.query_advice(is_pad, Rotation(2)));
                        let accumulated = current.expr() * challenges.keccak_input() + value_or_pad;
                        // If masked, copy the accumulator forward, otherwise update it.
                        let copy_or_acc = select::expr(mask_next, current, accumulated);
                        cb.require_equal(
                            "value_acc(2) == value_acc(0) * r + value(2), or copy value_acc(0)",
                            copy_or_acc,
                            meta.query_advice(value_acc, Rotation(2)),
                        );
                    }
                },
            );

            // Forward rlc_acc from the event to all rows.
            cb.condition(
                not::expr(meta.query_advice(is_last, Rotation::cur())),
                |cb| {
                    cb.require_equal(
                        "rows[0].rlc_acc == rows[1].rlc_acc",
                        meta.query_advice(rlc_acc, Rotation::cur()),
                        meta.query_advice(rlc_acc, Rotation::next()),
                    );
                },
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("Last Step", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "source value_acc == destination value_acc on the last row",
                meta.query_advice(value_acc, Rotation::cur()),
                meta.query_advice(value_acc, Rotation::next()),
            );

            // Check the rlc_acc given in the event if any of:
            // - Precompile => *
            // - * => Precompile
            // - Memory => Bytecode
            // - TxCalldata => Bytecode
            // - * => RlcAcc
            let rlc_acc_cond = sum::expr([
                meta.query_advice(is_precompiled, Rotation::cur()),
                meta.query_advice(is_precompiled, Rotation::next()),
                and::expr([
                    meta.query_advice(is_memory, Rotation::cur()),
                    meta.query_advice(is_bytecode, Rotation::next()),
                ]),
                and::expr([
                    meta.query_advice(is_tx_calldata, Rotation::cur()),
                    meta.query_advice(is_bytecode, Rotation::next()),
                ]),
                tag.value_equals(CopyDataType::RlcAcc, Rotation::next())(meta),
            ]);
            cb.condition(rlc_acc_cond, |cb| {
                cb.require_equal(
                    "value_acc == rlc_acc on the last row",
                    meta.query_advice(value_acc, Rotation::next()),
                    meta.query_advice(rlc_acc, Rotation::next()),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_last, Rotation::next()),
            ]))
        });

        meta.create_gate("verify step (q_step == 1)", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_pad == 1 - (src_addr < src_addr_end) for read row",
                1.expr() - addr_lt_addr_end.is_lt(meta, None),
                meta.query_advice(is_pad, Rotation::cur()),
            );
            cb.require_zero(
                "is_pad == 0 for write row",
                meta.query_advice(is_pad, Rotation::next()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_selector(q_step),
            ]))
        });

        // memory word lookup
        meta.lookup_any("Memory word lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * meta.query_advice(is_memory, Rotation::cur())
                * is_word_end.is_equal_expression.expr();

            let addr_slot = meta.query_advice(addr, Rotation::cur()) - 31.expr();

            vec![
                1.expr(),
                meta.query_advice(rw_counter, Rotation::cur()),
                not::expr(meta.query_selector(q_step)),
                RwTableTag::Memory.expr(),
                meta.query_advice(id, Rotation::cur()), // call_id
                addr_slot,
                0.expr(),
                0.expr(),
                meta.query_advice(value_word_rlc, Rotation::cur()),
                meta.query_advice(value_word_rlc_prev, Rotation::cur()),
                0.expr(),
                0.expr(),
            ]
            .into_iter()
            .zip(rw_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("TxLog word lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * meta.query_advice(is_tx_log, Rotation::cur())
                * is_word_end.is_equal_expression.expr();

            let addr_slot = meta.query_advice(addr, Rotation::cur()) - 31.expr();

            vec![
                1.expr(),
                meta.query_advice(rw_counter, Rotation::cur()),
                1.expr(),
                RwTableTag::TxLog.expr(),
                meta.query_advice(id, Rotation::cur()), // tx_id
                addr_slot,                              // byte_index || field_tag || log_id
                0.expr(),
                0.expr(),
                meta.query_advice(value_word_rlc, Rotation::cur()),
                0.expr(),
                0.expr(),
                0.expr(),
            ]
            .into_iter()
            .zip(rw_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("Bytecode lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * meta.query_advice(is_bytecode, Rotation::cur())
                * meta.query_advice(non_pad_non_mask, Rotation::cur());

            vec![
                1.expr(),
                meta.query_advice(id, Rotation::cur()),
                BytecodeFieldTag::Byte.expr(),
                meta.query_advice(addr, Rotation::cur()),
                meta.query_advice(is_code, Rotation::cur()),
                meta.query_advice(value, Rotation::cur()),
            ]
            .into_iter()
            .zip_eq(bytecode_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("Tx calldata lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * meta.query_advice(is_tx_calldata, Rotation::cur())
                * meta.query_advice(non_pad_non_mask, Rotation::cur());

            vec![
                1.expr(),
                meta.query_advice(id, Rotation::cur()),
                TxContextFieldTag::CallData.expr(),
                meta.query_advice(addr, Rotation::cur()),
                meta.query_advice(value, Rotation::cur()),
            ]
            .into_iter()
            .zip(tx_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        Self {
            q_step,
            is_last,
            value,
            value_prev,
            value_word_rlc,
            value_word_rlc_prev,
            word_index,
            mask,
            front_mask,
            value_acc,
            is_pad,
            is_code,
            is_event,
            is_precompiled,
            is_tx_calldata,
            is_bytecode,
            is_memory,
            is_tx_log,
            q_enable,
            addr_lt_addr_end,
            is_word_end,
            non_pad_non_mask,
            copy_table,
            tx_table,
            rw_table,
            bytecode_table,
        }
    }
}

impl<F: Field> CopyCircuitConfig<F> {
    /// Assign an individual copy event to the Copy Circuit.
    #[allow(clippy::too_many_arguments)]
    pub fn assign_copy_event(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        tag_chip: &BinaryNumberChip<F, CopyDataType, 4>,
        lt_chip: &LtChip<F, 8>,
        lt_word_end_chip: &IsEqualChip<F>,
        challenges: Challenges<Value<F>>,
        copy_event: &CopyEvent,
    ) -> Result<(), Error> {
        for (step_idx, (tag, table_row, circuit_row)) in
            CopyTable::assignments(copy_event, challenges)
                .iter()
                .enumerate()
        {
            let is_read = step_idx % 2 == 0;

            // Copy table assignments
            for (&column, &(value, label)) in
                <CopyTable as LookupTable<F>>::advice_columns(&self.copy_table)
                    .iter()
                    .zip_eq(table_row)
            {
                region.assign_advice(
                    || format!("{label} at row: {offset}"),
                    column,
                    *offset,
                    || value,
                )?;
            }

            // q_step
            if is_read {
                self.q_step.enable(region, *offset)?;
            }
            // q_enable
            region.assign_fixed(
                || "q_enable",
                self.q_enable,
                *offset,
                || Value::known(F::one()),
            )?;
            // is_event = true
            region.assign_advice(
                || format!("is_event at row: {}", *offset),
                self.is_event,
                *offset,
                || Value::known(F::one()),
            )?;

            // is_last, value, is_pad, is_code
            for (column, &(value, label)) in [
                self.is_last,
                self.value,
                self.value_prev,
                self.value_word_rlc,
                self.value_word_rlc_prev,
                self.value_acc,
                self.is_pad,
                self.is_code,
                self.mask,
                self.front_mask,
                self.word_index,
            ]
            .iter()
            .zip_eq(circuit_row)
            {
                region.assign_advice(
                    || format!("{} at row: {}", label, *offset),
                    *column,
                    *offset,
                    || value,
                )?;
            }

            // tag
            tag_chip.assign(region, *offset, tag)?;

            // lt chip
            if is_read {
                let addr = unwrap_value(table_row[2].0);
                lt_chip.assign(region, *offset, addr, F::from(copy_event.src_addr_end))?;
            }

            lt_word_end_chip.assign(
                region,
                *offset,
                Value::known(F::from((step_idx as u64 / 2) % 32)), // word index
                Value::known(F::from(31u64)),
            )?;

            let pad = unwrap_value(circuit_row[6].0);
            let mask = unwrap_value(circuit_row[8].0);
            let non_pad_non_mask = pad.is_zero_vartime() && mask.is_zero_vartime();
            region.assign_advice(
                || format!("non_pad_non_mask at row: {offset}"),
                self.non_pad_non_mask,
                *offset,
                || Value::known(F::from(non_pad_non_mask)),
            )?;

            // if the memory copy operation is related to precompile calls.
            let is_precompiled = CopyDataType::precompile_types().contains(tag);
            region.assign_advice(
                || format!("is_precompiled at row: {}", *offset),
                self.is_precompiled,
                *offset,
                || Value::known(F::from(is_precompiled)),
            )?;
            region.assign_advice(
                || format!("is_tx_calldata at row: {}", *offset),
                self.is_tx_calldata,
                *offset,
                || Value::known(F::from(tag.eq(&CopyDataType::TxCalldata))),
            )?;
            region.assign_advice(
                || format!("is_bytecode at row: {}", *offset),
                self.is_bytecode,
                *offset,
                || Value::known(F::from(tag.eq(&CopyDataType::Bytecode))),
            )?;
            region.assign_advice(
                || format!("is_memory at row: {}", *offset),
                self.is_memory,
                *offset,
                || Value::known(F::from(tag.eq(&CopyDataType::Memory))),
            )?;
            region.assign_advice(
                || format!("is_tx_log at row: {}", *offset),
                self.is_tx_log,
                *offset,
                || Value::known(F::from(tag.eq(&CopyDataType::TxLog))),
            )?;

            *offset += 1;
        }

        Ok(())
    }

    /// Assign vec of copy events
    pub fn assign_copy_events(
        &self,
        layouter: &mut impl Layouter<F>,
        copy_events: &[CopyEvent],
        max_copy_rows: usize,
        challenges: Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let copy_rows_needed = copy_events
            .iter()
            .map(|c| c.copy_bytes.bytes.len() * 2)
            .sum::<usize>();

        // The `+ 2` is used to take into account the two extra empty copy rows needed
        // to satisfy the queries at `Rotation(2)`.
        assert!(
            copy_rows_needed + 2 <= max_copy_rows,
            "copy rows not enough {copy_rows_needed} vs {max_copy_rows}"
        );

        let tag_chip = BinaryNumberChip::construct(self.copy_table.tag);
        let lt_chip = LtChip::construct(self.addr_lt_addr_end);
        let lt_word_end_chip = IsEqualChip::construct(self.is_word_end.clone());

        layouter.assign_region(
            || "assign copy table",
            |mut region| {
                region.name_column(|| "is_last", self.is_last);
                region.name_column(|| "value", self.value);
                region.name_column(|| "value_prev", self.value_prev);
                region.name_column(|| "value_word_rlc", self.value_word_rlc);
                region.name_column(|| "value_word_rlc_prev", self.value_word_rlc_prev);
                region.name_column(|| "word_index", self.word_index);
                region.name_column(|| "mask", self.mask);
                region.name_column(|| "front_mask", self.front_mask);
                region.name_column(|| "is_code", self.is_code);
                region.name_column(|| "is_pad", self.is_pad);
                region.name_column(|| "non_pad_non_mask", self.non_pad_non_mask);
                region.name_column(|| "is_event", self.is_event);

                let mut offset = 0;
                for (ev_idx, copy_event) in copy_events.iter().enumerate() {
                    log::trace!(
                        "offset is {} before {}th copy event(bytes len: {}): {:?}",
                        offset,
                        ev_idx,
                        copy_event.copy_bytes.bytes.len(),
                        {
                            let mut copy_event = copy_event.clone();
                            copy_event.copy_bytes.bytes.clear();
                            copy_event
                        }
                    );
                    self.assign_copy_event(
                        &mut region,
                        &mut offset,
                        &tag_chip,
                        &lt_chip,
                        &lt_word_end_chip,
                        challenges,
                        copy_event,
                    )?;
                    log::trace!("offset after {}th copy event: {}", ev_idx, offset);
                }

                for _ in 0..max_copy_rows - copy_rows_needed - 2 {
                    self.assign_padding_row(
                        &mut region,
                        &mut offset,
                        false,
                        &tag_chip,
                        &lt_chip,
                        &lt_word_end_chip,
                    )?;
                }

                self.assign_padding_row(
                    &mut region,
                    &mut offset,
                    true,
                    &tag_chip,
                    &lt_chip,
                    &lt_word_end_chip,
                )?;
                self.assign_padding_row(
                    &mut region,
                    &mut offset,
                    true,
                    &tag_chip,
                    &lt_chip,
                    &lt_word_end_chip,
                )?;

                Ok(())
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_padding_row(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        is_last_two: bool,
        tag_chip: &BinaryNumberChip<F, CopyDataType, 4>,
        lt_chip: &LtChip<F, 8>,
        lt_word_end_chip: &IsEqualChip<F>,
    ) -> Result<(), Error> {
        // q_enable
        region.assign_fixed(
            || "q_enable",
            self.q_enable,
            *offset,
            || Value::known(F::from(!is_last_two)),
        )?;
        if !is_last_two {
            // q_step
            if *offset % 2 == 0 {
                self.q_step.enable(region, *offset)?;
            }
        }

        // is_event = false
        region.assign_advice(
            || format!("is_event at row: {}", *offset),
            self.is_event,
            *offset,
            || Value::known(F::zero()),
        )?;
        // is_first
        region.assign_advice(
            || format!("assign is_first {}", *offset),
            self.copy_table.is_first,
            *offset,
            || Value::known(F::zero()),
        )?;
        // is_last
        region.assign_advice(
            || format!("assign is_last {}", *offset),
            self.is_last,
            *offset,
            || Value::known(F::zero()),
        )?;
        // id
        region.assign_advice(
            || format!("assign id {}", *offset),
            self.copy_table.id,
            *offset,
            || Value::known(F::zero()),
        )?;
        // addr
        region.assign_advice(
            || format!("assign addr {}", *offset),
            self.copy_table.addr,
            *offset,
            || Value::known(F::zero()),
        )?;
        // src_addr_end
        region.assign_advice(
            || format!("assign src_addr_end {}", *offset),
            self.copy_table.src_addr_end,
            *offset,
            || Value::known(F::one()),
        )?;
        // real_bytes_left
        region.assign_advice(
            || format!("assign bytes_left {}", *offset),
            self.copy_table.real_bytes_left,
            *offset,
            || Value::known(F::zero()),
        )?;
        // value
        region.assign_advice(
            || format!("assign value {}", *offset),
            self.value,
            *offset,
            || Value::known(F::zero()),
        )?;
        // value_prev
        region.assign_advice(
            || format!("assign value_prev {}", *offset),
            self.value_prev,
            *offset,
            || Value::known(F::zero()),
        )?;
        // value_word_rlc
        region.assign_advice(
            || format!("assign value_word_rlc {}", *offset),
            self.value_word_rlc,
            *offset,
            || Value::known(F::zero()),
        )?;
        // value_word_rlc_prev
        region.assign_advice(
            || format!("assign value_word_rlc_prev {}", *offset),
            self.value_word_rlc_prev,
            *offset,
            || Value::known(F::zero()),
        )?;
        // word_index
        region.assign_advice(
            || format!("assign word_index {}", *offset),
            self.word_index,
            *offset,
            || Value::known(F::zero()),
        )?;
        // mask
        region.assign_advice(
            || format!("assign mask {}", *offset),
            self.mask,
            *offset,
            || Value::known(F::one()),
        )?;
        // front mask
        region.assign_advice(
            || format!("assign front mask {}", *offset),
            self.front_mask,
            *offset,
            || Value::known(F::one()),
        )?;

        // value_acc
        region.assign_advice(
            || format!("assign value_acc {}", *offset),
            self.value_acc,
            *offset,
            || Value::known(F::zero()),
        )?;
        // rlc_acc
        region.assign_advice(
            || format!("assign rlc_acc {}", *offset),
            self.copy_table.rlc_acc,
            *offset,
            || Value::known(F::zero()),
        )?;
        // is_code
        region.assign_advice(
            || format!("assign is_code {}", *offset),
            self.is_code,
            *offset,
            || Value::known(F::zero()),
        )?;
        // is_pad
        region.assign_advice(
            || format!("assign is_pad {}", *offset),
            self.is_pad,
            *offset,
            || Value::known(F::zero()),
        )?;
        // rw_counter
        region.assign_advice(
            || format!("assign rw_counter {}", *offset),
            self.copy_table.rw_counter,
            *offset,
            || Value::known(F::zero()),
        )?;

        // rwc_inc_left
        region.assign_advice(
            || format!("assign rwc_inc_left {}", *offset),
            self.copy_table.rwc_inc_left,
            *offset,
            || Value::known(F::zero()),
        )?;
        // tag
        tag_chip.assign(region, *offset, &CopyDataType::Padding)?;
        // Assign LT gadget
        lt_chip.assign(region, *offset, F::zero(), F::one())?;
        lt_word_end_chip.assign(
            region,
            *offset,
            Value::known(F::zero()),
            Value::known(F::from(31u64)),
        )?;
        region.assign_advice(
            || format!("non_pad_non_mask at row: {offset}"),
            self.non_pad_non_mask,
            *offset,
            || Value::known(F::zero()),
        )?;

        for column in [
            self.is_precompiled,
            self.is_tx_calldata,
            self.is_bytecode,
            self.is_memory,
            self.is_tx_log,
        ] {
            region.assign_advice(
                || format!("assigning padding row: {}", *offset),
                column,
                *offset,
                || Value::known(F::zero()),
            )?;
        }

        *offset += 1;

        Ok(())
    }
}

/// Struct for external data, specifies values for related lookup tables
#[derive(Clone, Debug, Default)]
pub struct ExternalData {
    /// TxCircuit -> max_txs
    pub max_txs: usize,
    /// TxCircuit -> max_calldata
    pub max_calldata: usize,
    /// TxCircuit -> txs
    pub txs: Vec<Transaction>,
    /// StateCircuit -> max_rws
    pub max_rws: usize,
    /// StateCircuit -> rws
    pub rws: RwMap,
    /// BytecodeCircuit -> bytecodes
    pub bytecodes: BTreeMap<Word, Bytecode>,
}

/// Copy Circuit
#[derive(Clone, Debug, Default)]
pub struct CopyCircuit<F: Field> {
    /// Copy events
    pub copy_events: Vec<CopyEvent>,
    /// Max number of rows in copy circuit
    pub max_copy_rows: usize,
    _marker: PhantomData<F>,
    /// Data for external lookup tables
    pub external_data: ExternalData,
}

impl<F: Field> CopyCircuit<F> {
    /// Return a new CopyCircuit
    pub fn new(copy_events: Vec<CopyEvent>, max_copy_rows: usize) -> Self {
        Self {
            copy_events,
            max_copy_rows,
            _marker: PhantomData::default(),
            external_data: ExternalData::default(),
        }
    }

    /// Return a new CopyCircuit with external data
    pub fn new_with_external_data(
        copy_events: Vec<CopyEvent>,
        max_copy_rows: usize,
        external_data: ExternalData,
    ) -> Self {
        Self {
            copy_events,
            max_copy_rows,
            _marker: PhantomData::default(),
            external_data,
        }
    }

    /// Return a new CopyCircuit from a block without the external data required
    /// to assign lookup tables.  This constructor is only suitable to be
    /// used by the SuperCircuit, which already assigns the external lookup
    /// tables.
    pub fn new_from_block_no_external(block: &witness::Block<F>) -> Self {
        Self::new(
            block.copy_events.clone(),
            block.circuits_params.max_copy_rows,
        )
    }
}

impl<F: Field> SubCircuit<F> for CopyCircuit<F> {
    type Config = CopyCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // No column queried at more than 3 distinct rotations, so returns 6 as
        // minimum unusable rows.
        6
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new_with_external_data(
            block.copy_events.clone(),
            block.circuits_params.max_copy_rows,
            ExternalData {
                max_txs: block.circuits_params.max_txs,
                max_calldata: block.circuits_params.max_calldata,
                txs: block.txs.clone(),
                max_rws: block.circuits_params.max_rws,
                rws: block.rws.clone(),
                bytecodes: block.bytecodes.clone(),
            },
        )
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        (
            block
                .copy_events
                .iter()
                .map(|c| c.copy_bytes.bytes.len() * 2)
                .sum::<usize>()
                + 2,
            block.circuits_params.max_copy_rows,
        )
    }

    /// Make the assignments to the CopyCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign_copy_events(layouter, &self.copy_events, self.max_copy_rows, *challenges)
    }
}

fn unwrap_value<F: Field>(value: Value<F>) -> F {
    let mut f = F::zero();
    value.map(|v| f = v);
    f
}

#[cfg(test)]
mod copy_circuit_stats {
    use crate::{
        evm_circuit::step::ExecutionState,
        stats::{bytecode_prefix_op_big_rws, print_circuit_stats_by_states},
    };

    /// Prints the stats of Copy circuit per execution state.  See
    /// `print_circuit_stats_by_states` for more details.
    ///
    /// Run with:
    /// `cargo test -p zkevm-circuits --release --all-features
    /// get_evm_states_stats -- --nocapture --ignored`
    #[ignore]
    #[test]
    fn get_copy_states_stats() {
        print_circuit_stats_by_states(
            |state| {
                // TODO: Enable CREATE/CREATE2 once they are supported
                matches!(
                    state,
                    ExecutionState::RETURNDATACOPY
                        | ExecutionState::CODECOPY
                        | ExecutionState::LOG
                        | ExecutionState::CALLDATACOPY
                        | ExecutionState::EXTCODECOPY
                        | ExecutionState::RETURN_REVERT
                )
            },
            bytecode_prefix_op_big_rws,
            |block, _, _| {
                assert!(block.copy_events.len() <= 1);
                block
                    .copy_events
                    .iter()
                    .map(|c| c.copy_bytes.bytes.len() * 2)
                    .sum::<usize>()
            },
        );
    }
}
