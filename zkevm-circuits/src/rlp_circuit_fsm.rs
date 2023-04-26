use std::marker::PhantomData;

use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig},
    is_equal::{IsEqualChip, IsEqualConfig},
    util::{and, not, or, select, sum, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase,
        VirtualCells,
    },
    poly::Rotation,
};
use halo2_proofs::plonk::VirtualCell;

use crate::{
    evm_circuit::{param::N_BYTES_U64, util::constraint_builder::BaseConstraintBuilder},
    table::{LookupTable, RlpFsmDataTable, RlpFsmRlpTable, RlpFsmRomTable, RlpTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{Block, GenericSignedTransaction, RlpFsmWitnessGen, RlpTag, State, Tag},
};
use crate::witness::State::DecodeTagStart;

struct Range256Table(Column<Fixed>);

impl<F: Field> LookupTable<F> for Range256Table {
    fn columns(&self) -> Vec<Column<halo2_proofs::plonk::Any>> {
        vec![self.0.into()]
    }

    fn annotations(&self) -> Vec<String> {
        vec![String::from("byte_value")]
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
}

impl<F: Field> RlpCircuitConfig<F> {
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
        macro_rules! is_state_next {
            ($var:ident, $state_variant:ident) => {
                let $var = |meta: &mut VirtualCells<F>| {
                    state_bits.value_equals(State::$state_variant, Rotation::next())(meta)
                };
            };
        }
        is_state!(is_decode_tag_start, DecodeTagStart);
        is_state!(is_bytes, Bytes);
        is_state!(is_long_bytes, LongBytes);
        is_state!(is_long_list, LongList);
        is_state!(is_end, End);
        is_state_next!(is_next_decode_tag_start, DecodeTagStart);
        is_state_next!(is_next_bytes, Bytes);
        is_state_next!(is_next_long_bytes, LongBytes);
        is_state_next!(is_next_long_list, LongList);
        is_state_next!(is_next_end, End);

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
        let cmp_enabled = |meta: &mut VirtualCells<F>| {
            and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
            ])
        };
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
            }
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
            }
        }

        macro_rules! update_state {
            ( $meta:ident, $cb:ident, $tag:expr, $to: expr) => {
                $cb.require_equal(
                    "$tag' = $to",
                    $meta.query_advice($tag, Rotation::next()),
                    $to.expr(),
                );
            }
        }

        let tag_expr = |meta: &mut VirtualCells<F>| meta.query_advice(tag, Rotation::cur());
        let tag_next_expr = |meta: &mut VirtualCells<F>| meta.query_advice(tag_next, Rotation::cur());
        let depth_expr = |meta: &mut VirtualCells<F>| meta.query_advice(depth, Rotation::cur());
        let byte_idx_expr = |meta: &mut VirtualCells<F>| meta.query_advice(byte_idx, Rotation::cur());
        let byte_rev_idx_expr = |meta: &mut VirtualCells<F>| meta.query_advice(byte_rev_idx, Rotation::cur());
        let byte_value_expr = |meta: &mut VirtualCells<F>| meta.query_advice(byte_value, Rotation::cur());
        let bytes_rlc_expr = |meta: &mut VirtualCells<F>| meta.query_advice(bytes_rlc, Rotation::cur());
        let is_tag_begin_expr = |meta: &mut VirtualCells<F>| meta.query_advice(is_tag_begin, Rotation::cur());
        let is_tag_end_expr = |meta: &mut VirtualCells<F>| meta.query_advice(is_tag_end, Rotation::cur());

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
                let case_1 = and::expr([
                    bv_lt_0x80,
                    not::expr(is_tag_end_expr(meta)),
                ]);
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
                let case_2 = and::expr([
                    bv_eq_0x80,
                    not::expr(is_tag_end_expr(meta)),
                ]);
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
                        constrain_eq!(meta, cb, rlp_table.tag_value_acc,
                            byte_idx_expr(meta) + byte_value_expr.expr() - 0xc0.expr());
                        constrain_eq!(meta, cb, byte_rev_idx,
                            byte_value_expr.expr() - 0xc0.expr() + 1.expr());
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
                    and::expr([case_4.expr(), depth_check.is_equal_expression.expr()]),
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
                    and::expr([case_4.expr(), not::expr(depth_check.is_equal_expression.expr())]),
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
                    is_not_padding.expr(),
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
            cb.require_equal(
                "0x80 < byte_value < 0xb8",
                and::expr([
                    bv_gt_0x80,
                    not::expr(bv_eq_0x80),
                    bv_lt_0xb8,
                    not::expr(bv_eq_0xb8),
                ]),
                1.expr(),
            );

            // assertions.
            cb.require_equal(
                "is_output == false",
                meta.query_advice(rlp_table.is_output, Rotation::cur()),
                false.expr(),
            );
            cb.require_equal(
                "q_lookup_data == true",
                meta.query_advice(q_lookup_data, Rotation::cur()),
                true.expr(),
            );
            cb.require_equal(
                "is_list == false",
                meta.query_advice(is_list, Rotation::cur()),
                false.expr(),
            );

            // state transitions.
            cb.require_equal(
                "tag_idx' == 1",
                meta.query_advice(tag_idx, Rotation::cur()),
                1.expr(),
            );
            cb.require_equal(
                "tag_length' == byte_value - 0x80",
                meta.query_advice(tag_length, Rotation::next()) + 0x80.expr(),
                meta.query_advice(byte_value, Rotation::cur()),
            );
            cb.require_equal(
                "byte_idx' == byte_idx + 1",
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
            );
            cb.require_equal(
                "tag_value_acc' == byte_value'",
                meta.query_advice(rlp_table.tag_value_acc, Rotation::next()),
                meta.query_advice(byte_value, Rotation::next()),
            );

            // depth is unchanged.
            constrain_unchanged_fields!(meta, cb; depth);

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                is_decode_tag_start(meta),
                is_next_bytes(meta),
            ]))
        });

        // Bytes => Bytes
        meta.create_gate("state transition: Bytes => Bytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (tidx_lt_tlen, tidx_eq_tlen) = tidx_lte_tlength.expr(meta, None);
            let (tlen_lt_0x20, tlen_eq_0x20) = tlength_lte_0x20.expr(meta, None);

            // condition.
            cb.require_equal(
                "tag_idx < tag_length",
                and::expr([tidx_lt_tlen, not::expr(tidx_eq_tlen)]),
                1.expr(),
            );

            // assertions.
            cb.require_equal(
                "is_output == false",
                meta.query_advice(rlp_table.is_output, Rotation::cur()),
                false.expr(),
            );
            cb.require_equal(
                "q_lookup_data == true",
                meta.query_advice(q_lookup_data, Rotation::cur()),
                true.expr(),
            );

            // state transitions.
            cb.require_equal(
                "tag_idx' == tag_idx + 1",
                meta.query_advice(tag_idx, Rotation::next()),
                meta.query_advice(tag_idx, Rotation::cur()) + 1.expr(),
            );
            cb.require_equal(
                "byte_idx' == byte_idx + 1",
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
            );
            let b = select::expr(
                tlen_lt_0x20,
                256.expr(),
                select::expr(tlen_eq_0x20, evm_word_rand, keccak_input_rand),
            );
            cb.require_equal(
                "tag_value_acc' == tag_value_acc * b + byte_value'",
                meta.query_advice(rlp_table.tag_value_acc, Rotation::next()),
                meta.query_advice(rlp_table.tag_value_acc, Rotation::cur()) * b
                    + meta.query_advice(byte_value, Rotation::next()),
            );

            // depth, tag_length unchanged.
            constrain_unchanged_fields!(meta, cb; depth, tag_length);

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                is_bytes(meta),
                is_next_bytes(meta),
            ]))
        });

        // Bytes => DecodeTagStart
        meta.create_gate("state transition: Bytes => DecodeTagStart", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (_, tidx_eq_tlen) = tidx_lte_tlength.expr(meta, None);

            // condition.
            cb.require_equal(
                "tag_idx == tag_length",
                meta.query_advice(tag_idx, Rotation::cur()),
                meta.query_advice(tag_length, Rotation::cur()),
            );

            // assertions.
            cb.require_equal(
                "is_output == true",
                meta.query_advice(rlp_table.is_output, Rotation::cur()),
                true.expr(),
            );
            cb.require_equal(
                "q_lookup_data == true",
                meta.query_advice(q_lookup_data, Rotation::cur()),
                true.expr(),
            );

            // state transition.
            cb.require_equal(
                "tag' == tag_next",
                meta.query_advice(tag, Rotation::next()),
                meta.query_advice(tag_next, Rotation::cur()),
            );
            cb.require_equal(
                "byte_idx' == byte_idx + 1",
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
            );

            // depth is unchanged.
            constrain_unchanged_fields!(meta, cb; depth);

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                is_bytes(meta),
                is_next_decode_tag_start(meta),
            ]))
        });

        // DecodeTagStart => LongBytes
        meta.create_gate("state transition: DecodeTagStart => LongBytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (bv_gt_0xb8, bv_eq_0xb8) = byte_value_gte_0xb8.expr(meta, None);
            let (bv_lt_0xc0, bv_eq_0xc0) = byte_value_lte_0xc0.expr(meta, None);

            // condition.
            cb.require_equal(
                "0xb8 <= byte_value < 0xc0",
                and::expr([
                    or::expr([bv_gt_0xb8, bv_eq_0xb8]),
                    bv_lt_0xc0,
                    not::expr(bv_eq_0xc0),
                ]),
                1.expr(),
            );

            // assertions.
            cb.require_equal(
                "is_output == false",
                meta.query_advice(rlp_table.is_output, Rotation::cur()),
                false.expr(),
            );
            cb.require_equal(
                "q_lookup_data == true",
                meta.query_advice(q_lookup_data, Rotation::cur()),
                true.expr(),
            );
            cb.require_equal(
                "is_list == false",
                meta.query_advice(is_list, Rotation::cur()),
                false.expr(),
            );

            // state transition.
            cb.require_equal(
                "tag_length' == byte_value - 0xb7",
                meta.query_advice(tag_length, Rotation::next()) + 0xb7.expr(),
                meta.query_advice(byte_value, Rotation::cur()),
            );
            cb.require_equal(
                "tag_idx' == 1",
                meta.query_advice(tag_idx, Rotation::next()),
                1.expr(),
            );
            cb.require_equal(
                "tag_value_acc' == byte_value'",
                meta.query_advice(rlp_table.tag_value_acc, Rotation::next()),
                meta.query_advice(byte_value, Rotation::next()),
            );
            cb.require_equal(
                "byte_idx' == byte_idx + 1",
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
            );

            // depth is unchanged.
            constrain_unchanged_fields!(meta, cb; depth);

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                is_decode_tag_start(meta),
                is_next_long_bytes(meta),
            ]))
        });

        // LongBytes => LongBytes
        meta.create_gate("state transition: LongBytes => LongBytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (tidx_lt_tlen, _) = tidx_lte_tlength.expr(meta, None);

            // condition.
            cb.require_equal("tag_idx < tag_length", tidx_lt_tlen, true.expr());

            // assertions.
            cb.require_equal(
                "is_output = false",
                meta.query_advice(rlp_table.is_output, Rotation::cur()),
                false.expr(),
            );
            cb.require_equal(
                "q_lookup_data == true",
                meta.query_advice(q_lookup_data, Rotation::cur()),
                true.expr(),
            );

            // state transition.
            cb.require_equal(
                "tag_idx' == tag_idx + 1",
                meta.query_advice(tag_idx, Rotation::next()),
                meta.query_advice(tag_idx, Rotation::cur()) + 1.expr(),
            );
            cb.require_equal(
                "tag_value_acc' == tag_value_acc * 256 + byte_value'",
                meta.query_advice(rlp_table.tag_value_acc, Rotation::next()),
                meta.query_advice(rlp_table.tag_value_acc, Rotation::cur()) * 256.expr()
                    + meta.query_advice(byte_value, Rotation::next()),
            );
            cb.require_equal(
                "byte_idx' == byte_idx + 1",
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
            );

            // depth, tag_length are unchanged.
            constrain_unchanged_fields!(meta, cb; depth, tag_length);

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                is_long_bytes(meta),
                is_next_long_bytes(meta),
            ]))
        });

        // LongBytes => Bytes
        meta.create_gate("state transition: LongBytes => Bytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (_, tidx_eq_tlen) = tidx_lte_tlength.expr(meta, None);

            // condition.
            cb.require_equal("tag_idx == tag_length", tidx_eq_tlen, true.expr());

            // assertions.
            cb.require_equal(
                "is_output == false",
                meta.query_advice(rlp_table.is_output, Rotation::cur()),
                false.expr(),
            );
            cb.require_equal(
                "q_lookup_data == true",
                meta.query_advice(q_lookup_data, Rotation::cur()),
                true.expr(),
            );

            // state transition.
            cb.require_equal(
                "tag_length' == tag_value_acc",
                meta.query_advice(tag_length, Rotation::next()),
                meta.query_advice(rlp_table.tag_value_acc, Rotation::cur()),
            );
            cb.require_equal(
                "tag_idx' == 1",
                meta.query_advice(tag_idx, Rotation::next()),
                1.expr(),
            );
            cb.require_equal(
                "byte_idx' == byte_idx + 1",
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
            );

            // depth is unchanged.
            constrain_unchanged_fields!(meta, cb; depth);

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                is_long_bytes(meta),
                is_next_bytes(meta),
            ]))
        });

        // DecodeTagStart => LongList
        meta.create_gate("state transition: DecodeTagStart => LongList", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (bv_gt_0xf8, bv_eq_0xf8) = byte_value_gte_0xf8.expr(meta, None);

            // condition.
            cb.require_equal(
                "byte_value >= 0xf8",
                or::expr([bv_gt_0xf8, bv_eq_0xf8]),
                true.expr(),
            );

            // assertions.
            cb.require_equal(
                "tag in [BeginList, BeginVector]",
                or::expr([is_tag_begin_list(meta), is_tag_begin_vector(meta)]),
                true.expr(),
            );
            cb.require_equal(
                "q_lookup_data == true",
                meta.query_advice(q_lookup_data, Rotation::cur()),
                true.expr(),
            );
            // if depth == 0:
            cb.condition(depth_check.is_equal_expression.expr(), |cb| {
                cb.require_equal(
                    "is_output == false",
                    meta.query_advice(rlp_table.is_output, Rotation::cur()),
                    false.expr(),
                );
                cb.require_equal(
                    "rlp_tag == RlpTag::Len",
                    meta.query_advice(rlp_table.rlp_tag, Rotation::cur()),
                    RlpTag::Len.expr(),
                );
                cb.require_equal(
                    "tag_value_acc == byte_idx + byte_rev_idx",
                    meta.query_advice(rlp_table.tag_value_acc, Rotation::cur()),
                    meta.query_advice(byte_idx, Rotation::cur())
                        + meta.query_advice(byte_rev_idx, Rotation::cur()),
                );
            });

            // state transition.
            cb.require_equal(
                "tag_length' == byte_value - 0xf7",
                meta.query_advice(tag_length, Rotation::next()) + 0xf7.expr(),
                meta.query_advice(byte_value, Rotation::cur()),
            );
            cb.require_equal(
                "tag_idx == 1",
                meta.query_advice(tag_idx, Rotation::next()),
                1.expr(),
            );
            cb.require_equal(
                "byte_idx' == byte_idx + 1",
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
            );
            cb.condition(is_tag_begin_vector(meta), |cb| {
                cb.require_equal(
                    "depth' == depth + 1",
                    meta.query_advice(depth, Rotation::next()),
                    meta.query_advice(depth, Rotation::cur()) + 1.expr(),
                );
            });
            // depth is unchanged if tag != BeginVector.
            cb.condition(not::expr(is_tag_begin_vector(meta)), |cb| {
                constrain_unchanged_fields!(meta, cb; depth);
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                is_decode_tag_start(meta),
                is_next_long_list(meta),
            ]))
        });

        // LongList => LongList
        meta.create_gate("state transition: LongList => LongList", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (tidx_lt_tlen, tidx_eq_tlen) = tidx_lte_tlength.expr(meta, None);

            // condition.
            cb.require_equal(
                "tag_idx < tag_length",
                and::expr([tidx_lt_tlen, not::expr(tidx_eq_tlen)]),
                true.expr(),
            );

            // assertions.
            cb.require_equal(
                "is_output == false",
                meta.query_advice(rlp_table.is_output, Rotation::cur()),
                false.expr(),
            );
            cb.require_equal(
                "q_lookup_data == true",
                meta.query_advice(q_lookup_data, Rotation::cur()),
                true.expr(),
            );

            // state transition.
            cb.require_equal(
                "tag_idx' == tag_idx + 1",
                meta.query_advice(tag_idx, Rotation::next()),
                meta.query_advice(tag_idx, Rotation::cur()) + 1.expr(),
            );
            cb.require_equal(
                "byte_idx' == byte_idx + 1",
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
            );
            cb.require_equal(
                "tag_value_acc' == tag_value_acc * 256 + byte_value'",
                meta.query_advice(rlp_table.tag_value_acc, Rotation::next()),
                meta.query_advice(rlp_table.tag_value_acc, Rotation::cur()) * 256.expr()
                    + meta.query_advice(byte_value, Rotation::next()),
            );

            // depth, tag_length are unchanged.
            constrain_unchanged_fields!(meta, cb; depth, tag_length);

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                is_long_list(meta),
                is_next_long_list(meta),
            ]))
        });

        // LongList => DecodeTagStart
        meta.create_gate("state transition: LongList => DecodeTagStart", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (_, tidx_eq_tlen) = tidx_lte_tlength.expr(meta, None);

            // condition.
            cb.require_equal(
                "tag_idx == tag_length",
                meta.query_advice(tag_idx, Rotation::cur()),
                meta.query_advice(tag_length, Rotation::cur()),
            );

            // assertions.
            cb.condition(depth_check.is_equal_expression.expr(), |cb| {
                // if depth == 0:
                // tag_value_acc == byte_rev_idx - 1
                cb.require_equal(
                    "byte_rev_idx ends at 1",
                    meta.query_advice(rlp_table.tag_value_acc, Rotation::cur()) + 1.expr(),
                    meta.query_advice(byte_rev_idx, Rotation::cur()),
                );
            });

            // state transition.
            cb.require_equal(
                "tag' == tag_next",
                meta.query_advice(tag, Rotation::next()),
                meta.query_advice(tag_next, Rotation::cur()),
            );
            cb.require_equal(
                "byte_idx' == byte_idx + 1",
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                is_long_list(meta),
                is_next_decode_tag_start(meta),
            ]))
        });

        // DecodeTagStart => End
        meta.create_gate("state transition: DecodeTagStart => End", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // condition.
            cb.require_equal(
                "depth == 0",
                depth_check.is_equal_expression.expr(),
                true.expr(),
            );
            cb.require_equal(
                "tx_id' == 0",
                meta.query_advice(tx_id, Rotation::next()),
                0.expr(),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_not_padding.expr(),
                is_decode_tag_start(meta),
                is_next_end(meta),
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
        }
    }

    pub(crate) fn assign<RLP: RlpFsmWitnessGen<F>>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: Vec<RLP>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        unimplemented!("RlpCircuitConfig::assign")
    }
}

pub struct RlpCircuitConfigArgs<F: Field> {
    pub rom_table: RlpFsmRomTable,
    pub data_table: RlpFsmDataTable,
    pub rlp_table: RlpFsmRlpTable,
    pub range256_table: Range256Table,
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

#[derive(Clone, Debug)]
pub struct RlpCircuit<F, RLP> {
    pub inputs: Vec<RLP>,
    pub max_txs: usize,
    pub size: usize,
    _marker: PhantomData<F>,
}

impl<F: Field, RLP> Default for RlpCircuit<F, RLP> {
    fn default() -> Self {
        Self {
            inputs: vec![],
            max_txs: 0,
            size: 0,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> SubCircuit<F> for RlpCircuit<F, GenericSignedTransaction> {
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
        unimplemented!("RlpCircuit::synthesize_sub")
    }

    fn min_num_rows_block(block: &crate::witness::Block<F>) -> (usize, usize) {
        unimplemented!("RlpCircuit::min_num_rows_block")
    }
}

impl<F: Field> Circuit<F> for RlpCircuit<F, GenericSignedTransaction> {
    type Config = (RlpCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        unimplemented!("RlpCircuit::configure")
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        unimplemented!("RlpCircuit::synthesize")
    }
}

#[cfg(test)]
mod tests {}
