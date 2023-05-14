//! Circuit implementation for verifying assignments to the RLP finite state machine.

use std::marker::PhantomData;

use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig, ComparatorInstruction},
    is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction},
    util::{and, not, select, sum, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase,
        VirtualCells,
    },
    poly::Rotation,
};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, RlpFsmDataTable, RlpFsmRlpTable, RlpFsmRomTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{
        Block, RlpFsmWitnessGen, RlpFsmWitnessRow, RlpTag, State, State::DecodeTagStart, Tag,
    },
};

/// Fixed table to check if a value is a byte, i.e. 0 <= value < 256.
pub struct Range256Table(Column<Fixed>);

impl<F: Field> LookupTable<F> for Range256Table {
    fn columns(&self) -> Vec<Column<halo2_proofs::plonk::Any>> {
        vec![self.0.into()]
    }

    fn annotations(&self) -> Vec<String> {
        vec![String::from("byte_value")]
    }
}

impl Range256Table {
    pub(crate) fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self(meta.fixed_column())
    }
}

/// The RLP Circuit is implemented as a finite state machine. Refer the
/// [design doc][doclink] for design decisions and specification details.
///
/// [doclink]: https://hackmd.io/VMjQdO0SRu2azN6bR_aOrQ?view
#[derive(Clone, Debug)]
pub struct RlpCircuitConfig<F> {
    /// Whether the row is enabled.
    q_enabled: Column<Fixed>,
    /// Whether we should do a lookup to the data table or not.
    q_lookup_data: Column<Advice>,
    /// The state of RLP verifier at the current row.
    state: Column<Advice>,
    /// A utility gadget to compare/query what state we are at.
    state_bits: BinaryNumberConfig<State, 3>,
    /// The Rlp table which can be accessed by other circuits.
    rlp_table: RlpFsmRlpTable,
    /// The tag, i.e. what field is being decoded at the current row.
    tag: Column<Advice>,
    /// A utility gadget to compare/query what tag we are at.
    tag_bits: BinaryNumberConfig<Tag, 4>,
    /// The tag that will be decoded next after the current tag is done decoding.
    tag_next: Column<Advice>,
    /// The incremental index of this specific byte in the RLP-encoded bytes.
    byte_idx: Column<Advice>,
    /// The reverse index for the above index.
    byte_rev_idx: Column<Advice>,
    /// The byte value at this index in the RLP encoded data.
    byte_value: Column<Advice>,
    /// The RLC accumulator of all the bytes of this RLP instance.
    bytes_rlc: Column<Advice>,
    /// When the tag occupies several bytes, this index denotes the
    /// incremental index of the byte within this tag instance.
    tag_idx: Column<Advice>,
    /// The length of bytes that hold this tag's value.
    tag_length: Column<Advice>,
    /// Boolean check whether or not the current tag represents a list or not.
    is_list: Column<Advice>,
    /// The maximum length, in terms of number of bytes that this tag can occupy.
    max_length: Column<Advice>,
    /// The depth at this row. Since RLP encoded data can be nested, we use
    /// the depth to go a level deeper and eventually leave that depth level.
    /// At depth == 0 we know that we are at the outermost level.
    depth: Column<Advice>,

    /// Check tx_id == 0 to know if it is meant to be padding row or not.
    padding: IsEqualConfig<F>,

    /// Check equality between tx_id' and tx_id in the data table.
    tx_id_check: IsEqualConfig<F>,
    /// Check equality between format' and format in the data table.
    format_check: IsEqualConfig<F>,

    /// Booleans to reduce the circuit's degree as tag_bits's degree is 4.
    is_tag_end: Column<Advice>,
    is_tag_begin: Column<Advice>,

    /// Check for byte_value <= 0x80
    byte_value_lte_0x80: ComparatorConfig<F, 1>,
    /// Check for byte_value >= 0x80
    byte_value_gte_0x80: ComparatorConfig<F, 1>,
    /// Check for byte_value <= 0xb8
    byte_value_lte_0xb8: ComparatorConfig<F, 1>,
    /// Check for byte_value >= 0xb8
    byte_value_gte_0xb8: ComparatorConfig<F, 1>,
    /// Check for byte_value <= 0xc0
    byte_value_lte_0xc0: ComparatorConfig<F, 1>,
    /// Check for byte_value >= 0xc0
    byte_value_gte_0xc0: ComparatorConfig<F, 1>,
    /// Check for byte_value <= 0xf8
    byte_value_lte_0xf8: ComparatorConfig<F, 1>,
    /// Check for byte_value >= 0xf8
    byte_value_gte_0xf8: ComparatorConfig<F, 1>,
    /// Check for tag_idx <= tag_length
    /// TODO(rohit): 4 bytes is not sufficient, since len(tx.data) < 2^24.
    tidx_lte_tlength: ComparatorConfig<F, 4>,
    /// Check for tag_length <= 32
    tlength_lte_0x20: ComparatorConfig<F, 1>,
    /// Check for depth == 0
    depth_check: IsEqualConfig<F>,
    /// Check for depth == 1
    depth_eq_one: IsEqualConfig<F>,
}

impl<F: Field> RlpCircuitConfig<F> {
    /// Configure the RLP circuit.
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        rom_table: &RlpFsmRomTable,
        data_table: &RlpFsmDataTable,
        rlp_table: &RlpFsmRlpTable,
        range256_table: &Range256Table,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let (tx_id, format) = (rlp_table.tx_id, rlp_table.format);
        let (
            q_enabled,
            q_lookup_data,
            state,
            byte_idx,
            byte_rev_idx,
            byte_value,
            tag,
            tag_next,
            tag_idx,
            tag_length,
            is_list,
            max_length,
            depth,
            bytes_rlc,
            is_tag_begin,
            is_tag_end,
        ) = (
            meta.fixed_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column_in(SecondPhase),
            meta.advice_column(),
            meta.advice_column(),
        );
        let padding = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enabled, Rotation::cur()),
            |meta| meta.query_advice(tx_id, Rotation::cur()),
            |_meta| 0.expr(),
        );
        let (is_padding, is_not_padding) = (
            padding.is_equal_expression.expr(),
            not::expr(padding.is_equal_expression.expr()),
        );
        let state_bits = BinaryNumberChip::configure(meta, q_enabled, Some(state.into()));
        let tag_bits = BinaryNumberChip::configure(meta, q_enabled, Some(tag.into()));

        // data table checks.
        let tx_id_check = IsEqualChip::configure(
            meta,
            |meta| {
                and::expr([
                    meta.query_fixed(q_enabled, Rotation::cur()),
                    is_not_padding.expr(),
                ])
            },
            |meta| meta.query_advice(data_table.tx_id, Rotation::cur()),
            |meta| meta.query_advice(data_table.tx_id, Rotation::next()),
        );
        let format_check = IsEqualChip::configure(
            meta,
            |meta| {
                and::expr([
                    meta.query_fixed(q_enabled, Rotation::cur()),
                    is_not_padding.expr(),
                ])
            },
            |meta| meta.query_advice(data_table.format, Rotation::cur()),
            |meta| meta.query_advice(data_table.format, Rotation::next()),
        );

        // randomness values.
        let evm_word_rand = challenges.evm_word();
        let keccak_input_rand = challenges.keccak_input();

        meta.create_gate("data table checks", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // if tx_id' == tx_id and format' == format then:
            cb.condition(
                and::expr([
                    tx_id_check.is_equal_expression.expr(),
                    format_check.is_equal_expression.expr(),
                ]),
                |cb| {
                    // byte_idx' == byte_idx + 1
                    cb.require_equal(
                        "byte_idx increments",
                        meta.query_advice(data_table.byte_idx, Rotation::next()),
                        meta.query_advice(data_table.byte_idx, Rotation::cur()) + 1.expr(),
                    );
                    // byte_rev_idx' + 1 == byte_rev_idx
                    cb.require_equal(
                        "byte_rev_idx decrements",
                        meta.query_advice(data_table.byte_rev_idx, Rotation::next()) + 1.expr(),
                        meta.query_advice(data_table.byte_rev_idx, Rotation::cur()),
                    );
                    // bytes_rlc' == bytes_rlc * r + byte_value'
                    cb.require_equal(
                        "correct random linear combination of byte value",
                        meta.query_advice(data_table.bytes_rlc, Rotation::next()),
                        meta.query_advice(data_table.bytes_rlc, Rotation::cur())
                            * keccak_input_rand.expr()
                            + meta.query_advice(data_table.byte_value, Rotation::next()),
                    );
                },
            );

            // if tx_id' != tx_id then:
            cb.condition(not::expr(tx_id_check.is_equal_expression.expr()), |cb| {
                // tx_id' == tx_id + 1
                cb.require_equal(
                    "tx_id increments",
                    meta.query_advice(data_table.tx_id, Rotation::cur()),
                    meta.query_advice(data_table.tx_id, Rotation::next()),
                );
                // byte_idx' == 1
                cb.require_equal(
                    "byte_idx starts at 1 for new tx",
                    meta.query_advice(data_table.byte_idx, Rotation::next()),
                    1.expr(),
                );
                // bytes_rlc' == byte_value'
                cb.require_equal(
                    "byte_value and bytes_rlc are equal at the first index",
                    meta.query_advice(data_table.bytes_rlc, Rotation::next()),
                    meta.query_advice(data_table.byte_value, Rotation::next()),
                );
            });

            // if tx_id' == tx_id then:
            cb.condition(tx_id_check.is_equal_expression.expr(), |cb| {
                let (format_cur, format_next) = (
                    meta.query_advice(data_table.format, Rotation::cur()),
                    meta.query_advice(data_table.format, Rotation::next()),
                );
                // format' == format or format' == format + 1
                cb.require_zero(
                    "format unchanged or increments",
                    and::expr([
                        format_next.expr() - format_cur.expr(),
                        format_next.expr() - format_cur.expr() - 1.expr(),
                    ]),
                );
            });

            // if tx_id' == tx_id and format' != format then:
            cb.condition(
                not::expr(and::expr([
                    tx_id_check.is_equal_expression.expr(),
                    format_check.is_equal_expression.expr(),
                ])),
                |cb| {
                    // byte_rev_idx == 1
                    cb.require_equal(
                        "byte_rev_idx is 1 at the last index",
                        meta.query_advice(data_table.byte_rev_idx, Rotation::cur()),
                        1.expr(),
                    );
                    // byte_idx' == 1
                    cb.require_equal(
                        "byte_idx resets to 1 for new format",
                        meta.query_advice(data_table.byte_idx, Rotation::next()),
                        1.expr(),
                    );
                    // bytes_rlc' == byte_value'
                    cb.require_equal(
                        "bytes_value and bytes_rlc are equal at the first index",
                        meta.query_advice(data_table.byte_value, Rotation::next()),
                        meta.query_advice(data_table.bytes_rlc, Rotation::next()),
                    );
                },
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
            ]))
        });

        meta.lookup_any("byte value check", |meta| {
            let cond = and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
            ]);
            vec![meta.query_advice(data_table.byte_value, Rotation::cur())]
                .into_iter()
                .zip(range256_table.table_exprs(meta).into_iter())
                .map(|(arg, table)| (cond.expr() * arg, table))
                .collect()
        });

        meta.create_gate("padding checks", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // if the current row is padding, the next row is also padding.
            cb.require_zero(
                "if tx_id == 0 then tx_id' == 0",
                meta.query_advice(tx_id, Rotation::next()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_padding.expr(),
            ]))
        });

        meta.lookup_any("data table lookup", |meta| {
            let cond = meta.query_advice(q_lookup_data, Rotation::cur());
            vec![
                meta.query_advice(tx_id, Rotation::cur()),
                meta.query_advice(format, Rotation::cur()),
                meta.query_advice(byte_idx, Rotation::cur()),
                meta.query_advice(byte_rev_idx, Rotation::cur()),
                meta.query_advice(byte_value, Rotation::cur()),
            ]
            .into_iter()
            .zip(data_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.expr() * arg, table))
            .collect()
        });

        meta.lookup_any("ROM table lookup", |meta| {
            let cond = and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                not::expr(state_bits.value_equals(State::End, Rotation::cur())(meta)),
            ]);
            vec![
                meta.query_advice(tag, Rotation::cur()),
                meta.query_advice(tag_next, Rotation::cur()),
                meta.query_advice(max_length, Rotation::cur()),
                meta.query_advice(is_list, Rotation::cur()),
                meta.query_advice(format, Rotation::cur()),
            ]
            .into_iter()
            .zip(rom_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.expr() * arg, table))
            .collect()
        });

        macro_rules! is_state {
            ($var:ident, $state_variant:ident) => {
                let $var = |meta: &mut VirtualCells<F>| {
                    state_bits.value_equals(State::$state_variant, Rotation::cur())(meta)
                };
            };
        }
        // macro_rules! is_state_next {
        //     ($var:ident, $state_variant:ident) => {
        //         let $var = |meta: &mut VirtualCells<F>| {
        //             state_bits.value_equals(State::$state_variant, Rotation::next())(meta)
        //         };
        //     };
        // }
        is_state!(is_decode_tag_start, DecodeTagStart);
        is_state!(is_bytes, Bytes);
        is_state!(is_long_bytes, LongBytes);
        is_state!(is_long_list, LongList);
        is_state!(is_end, End);
        // is_state_next!(is_next_decode_tag_start, DecodeTagStart);
        // is_state_next!(is_next_bytes, Bytes);
        // is_state_next!(is_next_long_bytes, LongBytes);
        // is_state_next!(is_next_long_list, LongList);
        // is_state_next!(is_next_end, End);

        macro_rules! is_tag {
            ($var:ident, $tag_variant:ident) => {
                let $var = |meta: &mut VirtualCells<F>| {
                    tag_bits.value_equals(Tag::$tag_variant, Rotation::cur())(meta)
                };
            };
        }
        is_tag!(is_tag_begin_list, BeginList);
        is_tag!(is_tag_begin_vector, BeginVector);
        is_tag!(is_tag_end_list, EndList);
        is_tag!(is_tag_end_vector, EndVector);

        meta.create_gate("is_tag_end", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // use sum instead of or because is_tag_* cannot be true at the same time
            cb.require_equal(
                "is_tag_end = is_tag_end_list || is_tag_end_vector",
                meta.query_advice(is_tag_end, Rotation::cur()),
                sum::expr([is_tag_end_list(meta), is_tag_end_vector(meta)]),
            );
            cb.require_equal(
                "is_tag_begin = is_tag_begin_list || is_tag_begin_vector",
                meta.query_advice(is_tag_begin, Rotation::cur()),
                sum::expr([is_tag_begin_list(meta), is_tag_begin_vector(meta)]),
            );

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        // construct the comparators.
        let cmp_enabled = |meta: &mut VirtualCells<F>| meta.query_fixed(q_enabled, Rotation::cur());
        macro_rules! byte_value_lte {
            ($var:ident, $value:expr) => {
                let $var = ComparatorChip::configure(
                    meta,
                    cmp_enabled,
                    |meta| meta.query_advice(byte_value, Rotation::cur()),
                    |_| $value.expr(),
                );
            };
        }
        macro_rules! byte_value_gte {
            ($var:ident, $value:expr) => {
                let $var = ComparatorChip::configure(
                    meta,
                    cmp_enabled,
                    |_| $value.expr(),
                    |meta| meta.query_advice(byte_value, Rotation::cur()),
                );
            };
        }

        byte_value_lte!(byte_value_lte_0x80, 0x80);
        byte_value_gte!(byte_value_gte_0x80, 0x80);
        byte_value_lte!(byte_value_lte_0xb8, 0xb8);
        byte_value_gte!(byte_value_gte_0xb8, 0xb8);
        byte_value_lte!(byte_value_lte_0xc0, 0xc0);
        byte_value_gte!(byte_value_gte_0xc0, 0xc0);
        byte_value_lte!(byte_value_lte_0xf8, 0xf8);
        byte_value_gte!(byte_value_gte_0xf8, 0xf8);

        let tidx_lte_tlength = ComparatorChip::configure(
            meta,
            cmp_enabled,
            |meta| meta.query_advice(tag_idx, Rotation::cur()),
            |meta| meta.query_advice(tag_length, Rotation::cur()),
        );
        let tlength_lte_0x20 = ComparatorChip::configure(
            meta,
            cmp_enabled,
            |meta| meta.query_advice(tag_length, Rotation::cur()),
            |_meta| 0x20.expr(),
        );
        let depth_check = IsEqualChip::configure(
            meta,
            cmp_enabled,
            |meta| meta.query_advice(depth, Rotation::cur()),
            |_meta| 0.expr(),
        );
        let depth_eq_one = IsEqualChip::configure(
            meta,
            cmp_enabled,
            |meta| meta.query_advice(depth, Rotation::cur()),
            |_| 1.expr(),
        );

        macro_rules! constrain_unchanged_fields {
            ( $meta:ident, $cb:ident; $($field:expr),+ ) => {
                $(
                    $cb.require_equal(
                        "equate fields",
                        $meta.query_advice($field, Rotation::cur()),
                        $meta.query_advice($field, Rotation::next()),
                    );
                )+
            };
        }

        macro_rules! constrain_fields {
            ( $meta:ident, $cb:ident, $value:expr; $($field:ident),+ ) => {
                $(
                    $cb.require_equal(
                        "field constrained (by default)",
                        $meta.query_advice($field, Rotation::cur()),
                        $value.expr(),
                    );
                ),+
            }
        }

        macro_rules! constrain_eq {
            ( $meta:ident, $cb:ident, $field:expr, $value:expr ) => {
                $cb.require_equal(
                    "field constrained to equal",
                    $meta.query_advice($field, Rotation::cur()),
                    $value.expr(),
                );
            };
        }

        macro_rules! read_data {
            ( $meta:ident, $cb:ident) => {
                $cb.require_equal(
                    "q_lookup_data = true",
                    $meta.query_advice(q_lookup_data, Rotation::cur()),
                    true.expr(),
                );
            };
        }

        macro_rules! do_not_read_data {
            ( $meta:ident, $cb:ident) => {
                $cb.require_equal(
                    "q_lookup_data = false",
                    $meta.query_advice(q_lookup_data, Rotation::cur()),
                    false.expr(),
                );
            };
        }

        macro_rules! emit_rlp_tag {
            ( $meta:ident, $cb:ident, $tag:expr, $is_none:expr) => {
                $cb.require_equal(
                    "is_output = true",
                    $meta.query_advice(rlp_table.is_output, Rotation::cur()),
                    true.expr(),
                );
                $cb.require_equal(
                    "rlp_tag = tag",
                    $meta.query_advice(rlp_table.rlp_tag, Rotation::cur()),
                    $tag.expr(),
                );
                $cb.require_equal(
                    "is_none",
                    $meta.query_advice(rlp_table.is_none, Rotation::cur()),
                    $is_none.expr(),
                );
            };
        }

        macro_rules! do_not_emit {
            ( $meta:ident, $cb: ident ) => {
                $cb.require_equal(
                    "is_output = false",
                    $meta.query_advice(rlp_table.is_output, Rotation::cur()),
                    false.expr(),
                );
            };
        }

        macro_rules! update_state {
            ( $meta:ident, $cb:ident, $tag:expr, $to: expr) => {
                $cb.require_equal(
                    "$tag' = $to",
                    $meta.query_advice($tag, Rotation::next()),
                    $to.expr(),
                );
            };
        }

        let tag_expr = |meta: &mut VirtualCells<F>| meta.query_advice(tag, Rotation::cur());
        let tag_next_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(tag_next, Rotation::cur());
        let depth_expr = |meta: &mut VirtualCells<F>| meta.query_advice(depth, Rotation::cur());
        let byte_idx_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(byte_idx, Rotation::cur());
        let byte_rev_idx_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(byte_rev_idx, Rotation::cur());
        let byte_value_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(byte_value, Rotation::cur());
        let byte_value_next_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(byte_value, Rotation::next());
        let bytes_rlc_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(bytes_rlc, Rotation::cur());
        let tag_idx_expr = |meta: &mut VirtualCells<F>| meta.query_advice(tag_idx, Rotation::cur());
        let tag_length_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(tag_length, Rotation::cur());
        let tag_value_acc_expr = |meta: &mut VirtualCells<F>| {
            meta.query_advice(rlp_table.tag_value_acc, Rotation::cur())
        };
        let is_tag_begin_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(is_tag_begin, Rotation::cur());
        let is_tag_end_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(is_tag_end, Rotation::cur());

        meta.create_gate("state == End if is_padding = true", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(is_padding.expr(), |cb| {
                constrain_eq!(meta, cb, state, State::End);
            });

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        // DecodeTagStart => DecodeTagStart
        meta.create_gate(
            "state transition: DecodeTagStart => DecodeTagStart",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();
                let tag_expr = tag_expr(meta);
                let byte_value_expr = byte_value_expr(meta);

                let (bv_lt_0x80, bv_eq_0x80) = byte_value_lte_0x80.expr(meta, None);
                let (bv_gt_0xc0, bv_eq_0xc0) = byte_value_gte_0xc0.expr(meta, None);
                let (bv_lt_0xf8, bv_eq_0xf8) = byte_value_lte_0xf8.expr(meta, None);

                // case 1: 0x00 <= byte_value < 0x80
                let case_1 = and::expr([bv_lt_0x80, not::expr(is_tag_end_expr(meta))]);
                cb.condition(case_1.expr(), |cb| {
                    // assertions.
                    emit_rlp_tag!(meta, cb, tag_expr, false);
                    read_data!(meta, cb);

                    // is_list = false, tag_value_acc = byte_value
                    constrain_eq!(meta, cb, is_list, false);
                    constrain_eq!(meta, cb, rlp_table.tag_value_acc, byte_value_expr);

                    // state transitions.
                    update_state!(meta, cb, tag, tag_next_expr(meta));
                    update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                    update_state!(meta, cb, state, DecodeTagStart);

                    constrain_unchanged_fields!(meta, cb; depth, rlp_table.tx_id, rlp_table.format);
                });

                // case 2: byte_value == 0x80
                let case_2 = and::expr([bv_eq_0x80, not::expr(is_tag_end_expr(meta))]);
                cb.condition(case_2.expr(), |cb| {
                    // assertions.
                    emit_rlp_tag!(meta, cb, tag_expr, true);
                    read_data!(meta, cb);

                    constrain_eq!(meta, cb, is_list, false);
                    constrain_eq!(meta, cb, rlp_table.tag_value_acc, 0);

                    // state transitions.
                    update_state!(meta, cb, tag, tag_next_expr(meta));
                    update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                    update_state!(meta, cb, state, DecodeTagStart);

                    constrain_unchanged_fields!(meta, cb; depth, rlp_table.tx_id, rlp_table.format);
                });

                // case 3: 0xc0 <= byte_value < 0xf8
                let case_3 = and::expr([
                    sum::expr([bv_gt_0xc0, bv_eq_0xc0]),
                    bv_lt_0xf8,
                    not::expr(is_tag_end_expr(meta)),
                ]);
                cb.condition(case_3.expr(), |cb| {
                    // assertions
                    read_data!(meta, cb);
                    constrain_eq!(meta, cb, is_list, true);

                    // state transitions.
                    update_state!(meta, cb, tag, tag_next_expr(meta));
                    update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                    update_state!(meta, cb, depth, depth_expr(meta) + 1.expr());
                    update_state!(meta, cb, state, DecodeTagStart);

                    constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format);
                });
                cb.condition(
                    and::expr([case_3.expr(), depth_check.is_equal_expression.expr()]),
                    |cb| {
                        emit_rlp_tag!(meta, cb, RlpTag::Len, false);
                        constrain_eq!(
                            meta,
                            cb,
                            rlp_table.tag_value_acc,
                            byte_idx_expr(meta) + byte_value_expr.expr() - 0xc0.expr()
                        );
                        constrain_eq!(
                            meta,
                            cb,
                            byte_rev_idx,
                            byte_value_expr.expr() - 0xc0.expr() + 1.expr()
                        );
                    },
                );
                cb.condition(
                    and::expr([
                        case_3.expr(),
                        not::expr(depth_check.is_equal_expression.expr()),
                    ]),
                    |cb| {
                        do_not_emit!(meta, cb);
                    },
                );

                // case 4: tag in [EndList, EndVector]
                let case_4 = is_tag_end_expr(meta);
                cb.condition(case_4.expr(), |cb| {
                    // assertions
                    do_not_read_data!(meta, cb);

                    // state transitions
                    update_state!(meta, cb, depth, depth_expr(meta) - 1.expr());
                });
                cb.condition(
                    and::expr([case_4.expr(), depth_eq_one.is_equal_expression.expr()]),
                    |cb| {
                        // assertions.
                        emit_rlp_tag!(meta, cb, RlpTag::RLC, false);
                        constrain_eq!(meta, cb, rlp_table.tag_value_acc, bytes_rlc_expr(meta));
                        constrain_eq!(meta, cb, byte_rev_idx, 1);

                        // state transition.
                        // TODO(rohit): do this only if the next state is not State::End.
                        cb.require_equal(
                            "byte_idx' == 1",
                            meta.query_advice(byte_idx, Rotation::next()),
                            1.expr(),
                        );
                    },
                );
                cb.condition(
                    and::expr([
                        case_4.expr(),
                        not::expr(depth_eq_one.is_equal_expression.expr()),
                    ]),
                    |cb| {
                        // TODO(kunxian): check if this is complete.
                        constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format);
                    },
                );

                // one of the cases is true, and only one case is true.
                cb.require_equal(
                    "cover all cases for state transition",
                    sum::expr([case_1, case_2, case_3, case_4]),
                    1.expr(),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enabled, Rotation::cur()),
                    is_decode_tag_start(meta),
                ]))
            },
        );

        // DecodeTagStart => Bytes
        meta.create_gate("state transition: DecodeTagStart => Bytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (bv_gt_0x80, bv_eq_0x80) = byte_value_gte_0x80.expr(meta, None);
            let (bv_lt_0xb8, bv_eq_0xb8) = byte_value_lte_0xb8.expr(meta, None);

            // condition.
            cb.condition(and::expr([bv_gt_0x80, bv_lt_0xb8]),
                |cb| {
                    // assertions
                    read_data!(meta, cb);
                    do_not_emit!(meta, cb);
                    constrain_eq!(meta, cb, is_list, false);

                    // state transitions
                    update_state!(meta, cb, tag_idx, 1);
                    update_state!(meta, cb, tag_length, byte_value_expr(meta) - 0x80.expr());
                    update_state!(meta, cb, rlp_table.tag_value_acc, byte_value_next_expr(meta));
                    update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                    update_state!(meta, cb, state, State::Bytes);

                    // depth is unchanged.
                    constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format, depth, tag, tag_next);
                },
            );
            // otherwise, we get an invalid rlp error.
            // TODO(kunxian): add error handling

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_decode_tag_start(meta),
            ]))
        });

        // Bytes => Bytes
        // Bytes => DecodeTagStart
        meta.create_gate("state transition: Bytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (tidx_lt_tlen, tidx_eq_tlen) = tidx_lte_tlength.expr(meta, None);
            let (tlen_lt_0x20, tlen_eq_0x20) = tlength_lte_0x20.expr(meta, None);

            let b = select::expr(
                tlen_lt_0x20,
                256.expr(),
                select::expr(tlen_eq_0x20, evm_word_rand, keccak_input_rand),
            );

            // Bytes => Bytes
            cb.condition(tidx_lt_tlen, |cb| {
                // assertions
                do_not_emit!(meta, cb);
                read_data!(meta, cb);

                // state transitions
                update_state!(meta, cb, tag_idx, tag_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, rlp_table.tag_value_acc,
                    tag_value_acc_expr(meta) * b.expr() + byte_value_expr(meta));
                update_state!(meta, cb, state, State::Bytes);

                // depth, tag_length unchanged.
                constrain_unchanged_fields!(meta, cb; depth, tag, tag_next, tag_length, rlp_table.tx_id, rlp_table.format);
            });

            // Bytes => DecodeTagStart
            cb.condition(tidx_eq_tlen, |cb| {
                // assertions
                read_data!(meta, cb);
                emit_rlp_tag!(meta, cb, tag_expr(meta), false);

                // state transitions.
                update_state!(meta, cb, tag, tag_next_expr(meta));
                update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, state, State::DecodeTagStart);

                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format, depth);
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_bytes(meta),
            ]))
        });

        // DecodeTagStart => LongBytes
        meta.create_gate("state transition: DecodeTagStart => LongBytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (bv_gt_0xb8, bv_eq_0xb8) = byte_value_gte_0xb8.expr(meta, None);
            let (bv_lt_0xc0, bv_eq_0xc0) = byte_value_lte_0xc0.expr(meta, None);

            // condition: "0xb8 <= byte_value < 0xc0"
            cb.condition(and::expr([
                sum::expr([bv_gt_0xb8, bv_eq_0xb8]),
                bv_lt_0xc0
            ]), |cb| {
                // assertions.
                do_not_emit!(meta, cb);
                read_data!(meta, cb);
                constrain_eq!(meta, cb, is_list, false);

                // state transitions
                update_state!(meta, cb, tag_length, byte_value_expr(meta) - 0xb7.expr());
                update_state!(meta, cb, tag_idx, 1);
                update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, rlp_table.tag_value_acc, byte_value_next_expr(meta));
                update_state!(meta, cb, state, State::LongBytes);

                // depth is unchanged.
                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format, tag, tag_next, depth);
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_decode_tag_start(meta),
            ]))
        });

        // LongBytes => LongBytes
        // LongBytes => Bytes
        meta.create_gate("state transition: LongBytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (tidx_lt_tlen, tidx_eq_tlen) = tidx_lte_tlength.expr(meta, None);

            // LongBytes => LongBytes
            cb.condition(tidx_lt_tlen, |cb| {
                // assertions.
                read_data!(meta, cb);
                do_not_emit!(meta, cb);

                // state transitions
                update_state!(meta, cb, tag_idx, tag_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, rlp_table.tag_value_acc,
                    tag_value_acc_expr(meta) * 256.expr() + byte_value_next_expr(meta)
                );
                update_state!(meta, cb, state, State::LongBytes);

                // depth, tag_length are unchanged.
                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format, tag, tag_next, depth, tag_length);
            });

            // LongBytes => Bytes
            cb.condition(tidx_eq_tlen, |cb| {
                // assertions.
                do_not_emit!(meta, cb);
                read_data!(meta, cb);

                // state transition.
                update_state!(meta, cb, tag_length, tag_value_acc_expr(meta));
                update_state!(meta, cb, tag_idx, 1);
                update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, state, State::Bytes);

                // depth is unchanged.
                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format, tag, tag_next, depth);
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_long_bytes(meta),
            ]))
        });

        // DecodeTagStart => LongList
        meta.create_gate("state transition: DecodeTagStart => LongList", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (bv_gt_0xf8, bv_eq_0xf8) = byte_value_gte_0xf8.expr(meta, None);

            let cond = sum::expr([bv_gt_0xf8, bv_eq_0xf8]);
            cb.condition(cond.expr(), |cb| {
                // assertions.
                read_data!(meta, cb);
                constrain_eq!(meta, cb, is_tag_begin, true);

                // state transitions
                update_state!(meta, cb, tag_length, byte_value_expr(meta) - 0xf7.expr());
                update_state!(meta, cb, tag_idx, 1);
                update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, rlp_table.tag_value_acc, byte_value_next_expr(meta));
                update_state!(meta, cb, depth, depth_expr(meta) + 1.expr());
                update_state!(meta, cb, state, State::LongList);

                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format, tag, tag_next);
            });

            // depth == 0
            cb.condition(and::expr([
                cond.expr(),
                depth_check.is_equal_expression.expr(),
            ]), |cb| {
                emit_rlp_tag!(meta, cb, RlpTag::Len, false);
                constrain_eq!(meta, cb, rlp_table.tag_value_acc,
                    byte_idx_expr(meta) + byte_rev_idx_expr(meta) - 1.expr());
            });

            // depth != 0
            cb.condition(and::expr([
                cond.expr(),
                not::expr(depth_check.is_equal_expression.expr()),
            ]), |cb| {
                do_not_emit!(meta, cb);
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_decode_tag_start(meta),
            ]))
        });

        // LongList => LongList
        // LongList => DecodeTagStart
        meta.create_gate("state transition: LongList", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (tidx_lt_tlen, tidx_eq_tlen) = tidx_lte_tlength.expr(meta, None);

            // LongList => LongList
            cb.condition(tidx_lt_tlen, |cb| {
                // assertions
                read_data!(meta, cb);
                do_not_emit!(meta, cb);

                // state transitions
                update_state!(meta, cb, tag_idx, tag_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                update_state!(
                    meta,
                    cb,
                    rlp_table.tag_value_acc,
                    tag_value_acc_expr(meta) * 256.expr() + byte_value_next_expr(meta)
                );
                update_state!(meta, cb, state, State::LongList);

                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format,
                    tag, tag_next, depth, tag_length);
            });

            // LongList => DecodeTagStart
            cb.condition(tidx_eq_tlen.expr(), |cb| {
                // assertions
                read_data!(meta, cb);
                do_not_emit!(meta, cb);

                // state transitions
                update_state!(meta, cb, tag, tag_next_expr(meta));
                update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, state, State::DecodeTagStart);

                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format, depth);
            });
            cb.condition(
                and::expr([tidx_eq_tlen, depth_check.is_equal_expression.expr()]),
                |cb| {
                    // assertions (depth == 0)

                    // byte_rev_idx ends with 1.
                    constrain_eq!(
                        meta,
                        cb,
                        rlp_table.tag_value_acc,
                        byte_rev_idx_expr(meta) - 1.expr()
                    );
                },
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_long_list(meta),
            ]))
        });

        // DecodeTagStart => End
        meta.create_gate("state transition: DecodeTagStart => End", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(1.expr(), |cb| {
                // assertions
                do_not_read_data!(meta, cb);
                do_not_emit!(meta, cb);

                // state transitions
                update_state!(meta, cb, state, State::End);
            });

            // condition.
            cb.require_equal(
                "depth == 0",
                depth_check.is_equal_expression.expr(),
                true.expr(),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_decode_tag_start(meta),
            ]))
        });

        // End => End
        meta.create_gate("state transition: End", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // assertions
            do_not_emit!(meta, cb);
            do_not_read_data!(meta, cb);
            constrain_eq!(meta, cb, tx_id, 0);

            // state transitions
            update_state!(meta, cb, state, State::End);

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_end(meta),
            ]))
        });

        Self {
            q_enabled,
            q_lookup_data,
            state,
            state_bits,
            rlp_table: rlp_table.clone(),
            tag,
            tag_bits,
            tag_next,
            byte_idx,
            byte_rev_idx,
            byte_value,
            bytes_rlc,
            tag_idx,
            tag_length,
            is_list,
            max_length,
            depth,
            padding,

            // data table checks.
            tx_id_check,
            format_check,

            is_tag_begin,
            is_tag_end,

            // comparators
            byte_value_lte_0x80,
            byte_value_gte_0x80,
            byte_value_lte_0xb8,
            byte_value_gte_0xb8,
            byte_value_lte_0xc0,
            byte_value_gte_0xc0,
            byte_value_lte_0xf8,
            byte_value_gte_0xf8,
            tidx_lte_tlength,
            tlength_lte_0x20,
            depth_check,
            depth_eq_one,
        }
    }

    fn assign_sm_row(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        witness: &RlpFsmWitnessRow<F>,
    ) -> Result<(), Error> {
        // assign to selector
        region.assign_fixed(
            || "q_enabled",
            self.q_enabled,
            row,
            || Value::known(F::one()),
        )?;
        // assign to rlp_table
        region.assign_advice(
            || "rlp_table.tx_id",
            self.rlp_table.tx_id,
            row,
            || Value::known(F::from(witness.rlp_table.tx_id)),
        )?;
        region.assign_advice(
            || "rlp_table.format",
            self.rlp_table.format,
            row,
            || Value::known(F::from(witness.rlp_table.format as u64)),
        )?;
        region.assign_advice(
            || "rlp_table.rlp_tag",
            self.rlp_table.rlp_tag,
            row,
            || {
                Value::known(F::from(
                    <RlpTag as Into<usize>>::into(witness.rlp_table.rlp_tag) as u64,
                ))
            },
        )?;
        region.assign_advice(
            || "rlp_table.tag_value_acc",
            self.rlp_table.tag_value_acc,
            row,
            || witness.rlp_table.tag_value_acc,
        )?;
        region.assign_advice(
            || "rlp_table.is_output",
            self.rlp_table.is_output,
            row,
            || Value::known(F::from(witness.rlp_table.is_output as u64)),
        )?;
        region.assign_advice(
            || "rlp_table.is_none",
            self.rlp_table.is_none,
            row,
            || Value::known(F::from(witness.rlp_table.is_none as u64)),
        )?;

        // assign to sm
        region.assign_advice(
            || "sm.state",
            self.state,
            row,
            || Value::known(F::from(witness.state_machine.state as u64)),
        )?;
        region.assign_advice(
            || "sm.tag",
            self.tag,
            row,
            || Value::known(F::from(witness.state_machine.tag as u64)),
        )?;
        region.assign_advice(
            || "sm.tag_next",
            self.tag_next,
            row,
            || Value::known(F::from(witness.state_machine.tag_next as u64)),
        )?;
        region.assign_advice(
            || "sm.tag_idx",
            self.tag_idx,
            row,
            || Value::known(F::from(witness.state_machine.tag_idx as u64)),
        )?;
        region.assign_advice(
            || "sm.tag_length",
            self.tag_length,
            row,
            || Value::known(F::from(witness.state_machine.tag_length as u64)),
        )?;
        region.assign_advice(
            || "sm.depth",
            self.depth,
            row,
            || Value::known(F::from(witness.state_machine.depth as u64)),
        )?;
        // region.assign_advice(
        //     || "sm.q_lookup_data",
        //     self.q_lookup_data,
        //     row,
        //     || Value::known(F::from(witness.state_machine)),
        // )?;
        region.assign_advice(
            || "sm.byte_idx",
            self.byte_idx,
            row,
            || Value::known(F::from(witness.state_machine.byte_idx as u64)),
        )?;
        region.assign_advice(
            || "byte_rev_idx",
            self.byte_rev_idx,
            row,
            || Value::known(F::from(witness.state_machine.byte_rev_idx as u64)),
        )?;
        region.assign_advice(
            || "byte_value",
            self.byte_value,
            row,
            || Value::known(F::from(witness.state_machine.byte_value as u64)),
        )?;
        region.assign_advice(
            || "bytes_rlc",
            self.bytes_rlc,
            row,
            || witness.state_machine.bytes_rlc,
        )?;

        // assign to intermediates
        // TODO: assign to max_length
        region.assign_advice(
            || "is_list",
            self.is_list,
            row,
            || Value::known(F::from(witness.state_machine.tag.is_list() as u64)),
        )?;
        region.assign_advice(
            || "is_tag_begin",
            self.is_tag_begin,
            row,
            || Value::known(F::from(witness.state_machine.tag.is_begin() as u64)),
        )?;
        region.assign_advice(
            || "is_tag_end",
            self.is_tag_end,
            row,
            || Value::known(F::from(witness.state_machine.tag.is_end() as u64)),
        )?;

        let padding_chip = IsEqualChip::construct(self.padding.clone());
        padding_chip.assign(
            region,
            row,
            Value::known(F::from(witness.rlp_table.tx_id as u64)),
            Value::known(F::zero()),
        )?;

        let tag_chip = BinaryNumberChip::construct(self.tag_bits.clone());
        tag_chip.assign(region, row, &witness.state_machine.tag)?;

        let state_chip = BinaryNumberChip::construct(self.state_bits.clone());
        state_chip.assign(region, row, &witness.state_machine.state)?;

        let byte_value = F::from(witness.state_machine.byte_value as u64);
        let byte_0x80 = F::from(0x80_u64);
        let byte_0xb8 = F::from(0xb8_u64);
        let byte_0xc0 = F::from(0xc0_u64);
        let byte_0xf8 = F::from(0xf8_u64);
        let byte_value_lte_0x80 = ComparatorChip::construct(self.byte_value_lte_0xf8.clone());
        let byte_value_gte_0x80 = ComparatorChip::construct(self.byte_value_gte_0x80.clone());
        let byte_value_lte_0xb8 = ComparatorChip::construct(self.byte_value_lte_0xb8.clone());
        let byte_value_gte_0xb8 = ComparatorChip::construct(self.byte_value_gte_0xb8.clone());
        let byte_value_lte_0xc0 = ComparatorChip::construct(self.byte_value_lte_0xc0.clone());
        let byte_value_gte_0xc0 = ComparatorChip::construct(self.byte_value_gte_0xc0.clone());
        let byte_value_lte_0xf8 = ComparatorChip::construct(self.byte_value_lte_0xf8.clone());
        let byte_value_gte_0xf8 = ComparatorChip::construct(self.byte_value_gte_0xf8.clone());
        let byte_value_checks = vec![
            (byte_value_lte_0x80, byte_value, byte_0x80),
            (byte_value_gte_0x80, byte_0x80, byte_value),
            (byte_value_lte_0xb8, byte_value, byte_0xb8),
            (byte_value_gte_0xb8, byte_0xb8, byte_value),
            (byte_value_lte_0xc0, byte_value, byte_0xc0),
            (byte_value_gte_0xc0, byte_0xc0, byte_value),
            (byte_value_lte_0xf8, byte_value, byte_0xf8),
            (byte_value_gte_0xf8, byte_0xf8, byte_value),
        ];
        for (chip, lhs, rhs) in byte_value_checks {
            chip.assign(region, row, lhs, rhs)?;
        }

        Ok(())
    }

    /// Assign witness to the RLP circuit.
    pub(crate) fn assign<RLP: RlpFsmWitnessGen<F>>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: &[RLP],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let sm_rows = inputs
            .iter()
            .flat_map(|input| input.gen_sm_witness(&challenges))
            .collect::<Vec<_>>();

        layouter.assign_region(
            || "RLP sm region",
            |mut region| {
                for (i, sm_row) in sm_rows.iter().enumerate() {
                    self.assign_sm_row(&mut region, i, sm_row)?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

/// Arguments to configure the RLP circuit.
pub struct RlpCircuitConfigArgs<F: Field> {
    /// Read-only memory table.
    pub rom_table: RlpFsmRomTable,
    /// Data table that holds byte indices and values of instances being assigned to the RLP
    /// circuit.
    pub data_table: RlpFsmDataTable,
    /// RLP table.
    pub rlp_table: RlpFsmRlpTable,
    /// Fixed table to verify that the value is a single byte.
    pub range256_table: Range256Table,
    /// Challenge API.
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for RlpCircuitConfig<F> {
    type ConfigArgs = RlpCircuitConfigArgs<F>;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        Self::configure(
            meta,
            &args.rom_table,
            &args.data_table,
            &args.rlp_table,
            &args.range256_table,
            &args.challenges,
        )
    }
}

/// RLP finite state machine circuit.
#[derive(Clone, Debug)]
pub struct RlpCircuit<F, RLP> {
    /// Inputs to the RLP circuit.
    pub txs: Vec<RLP>,
    /// Maximum number of txs supported.
    pub max_txs: usize,
    /// Size of the RLP circuit.
    pub size: usize,
    _marker: PhantomData<F>,
}

impl<F: Field, RLP> Default for RlpCircuit<F, RLP> {
    fn default() -> Self {
        Self {
            txs: vec![],
            max_txs: 0,
            size: 0,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, RLP: RlpFsmWitnessGen<F>> SubCircuit<F> for RlpCircuit<F, RLP> {
    type Config = RlpCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        let max_txs = block.circuits_params.max_txs;
        debug_assert!(block.txs.len() <= max_txs);

        todo!("RlpCircuit::new_from_block")
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign(layouter, &self.txs, challenges)
    }

    fn min_num_rows_block(block: &crate::witness::Block<F>) -> (usize, usize) {
        unimplemented!("RlpCircuit::min_num_rows_block")
    }
}

impl<F: Field, RLP: RlpFsmWitnessGen<F>> Circuit<F> for RlpCircuit<F, RLP> {
    type Config = (RlpCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let data_table = RlpFsmDataTable::construct(meta);
        let rlp_table = RlpFsmRlpTable::construct(meta);
        let rom_table = RlpFsmRomTable::construct(meta);
        let u8_table = Range256Table::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        let config = RlpCircuitConfig::configure(
            meta,
            &rom_table,
            &data_table,
            &rlp_table,
            &u8_table,
            &challenge_exprs,
        );

        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = &config.1.values(&mut layouter);

        self.synthesize_sub(&config.0, challenges, &mut layouter)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        rlp_circuit_fsm::RlpCircuit,
        witness::{SignedTransaction, Transaction},
    };
    use eth_types::{geth_types::TxTypes, word, Address, H256, U64};
    use ethers_core::{
        types::{transaction::eip2718::TypedTransaction, TransactionRequest},
        utils::keccak256,
    };
    use ethers_signers::Wallet;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use mock::eth;
    use rand::rngs::OsRng;

    #[test]
    fn test_eip_155_tx() {}

    #[test]
    fn test_pre_eip155_tx() {
        let rng = &mut OsRng;
        let from = Wallet::new(rng);
        let tx = TransactionRequest::new()
            .to(Address::random())
            .value(eth(10))
            .data(Vec::new())
            .gas_price(word!("0x4321"))
            .gas(word!("0x77320"))
            .nonce(word!("0x7f"));
        let unsigned_bytes = tx.rlp_unsigned().to_vec();
        let tx: TypedTransaction = tx.into();
        let sig = from.sign_transaction_sync(&tx);

        let tx = Transaction::new_from_rlp_bytes(
            TxTypes::PreEip155,
            tx.rlp_signed(&sig).to_vec(),
            unsigned_bytes,
        );
        let rlp_circuit = RlpCircuit::<Fr, Transaction> {
            txs: vec![tx],
            max_txs: 10,
            size: 0,
            _marker: Default::default(),
        };
        let mock_prover = MockProver::run(16, &rlp_circuit, vec![]);
        assert_eq!(mock_prover.is_ok(), true);
    }
}
