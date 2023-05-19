//! Circuit implementation for verifying assignments to the RLP finite state machine.

use std::marker::PhantomData;

use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig, ComparatorInstruction},
    is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction},
    is_zero::{IsZeroChip as IsZeroGadgetChip, IsZeroConfig as IsZeroGadgetConfig},
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
        Block, DataTable, RlpFsmWitnessGen, RlpFsmWitnessRow, RlpTag, State, State::DecodeTagStart,
        Tag, Transaction,
    },
};

/// Fixed table to check if a value is a byte, i.e. 0 <= value < 256.
#[derive(Clone, Debug)]
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

    pub(crate) fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "RLP Range256 table",
            |mut region| {
                for row in 0..256 {
                    region.assign_fixed(
                        || "RLP range256",
                        self.0,
                        row,
                        || Value::known(F::from(row as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug)]
struct IsZeroConfig<F> {
    value: Column<Advice>,
    config: IsZeroGadgetConfig<F>,
}

impl<F: Field> IsZeroConfig<F> {
    /// Returns  is_zero expression
    fn expr(&self, rotation: Rotation) -> impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F> {
        let (value, value_inv) = (self.value, self.config.value_inv);
        move |meta: &mut VirtualCells<'_, F>| {
            1.expr() - meta.query_advice(value, rotation) * meta.query_advice(value_inv, rotation)
        }
    }
}

/// This chip is a wrapper of IsZeroChip in gadgets.
/// It gives us the ability to access is_zero expression at any Rotation.
#[derive(Clone, Debug)]
struct IsZeroChip<F> {
    config: IsZeroConfig<F>,
}

#[rustfmt::skip]
impl<F: Field> IsZeroChip<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value: Column<Advice>,
    ) -> IsZeroConfig<F> {
        let value_inv = meta.advice_column();
        let config = IsZeroGadgetChip::configure(
            meta,
            q_enable,
            |meta| meta.query_advice(value, Rotation::cur()),
            value_inv,
        );

        IsZeroConfig::<F> {
            value,
            config,
        }
    }

    /// Given an `IsZeroConfig`, construct the chip.
    fn construct(config: IsZeroConfig<F>) -> Self {
        IsZeroChip { config }
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<(), Error> {
        let config = &self.config.config;
        // postpone the invert to prover which has batch_invert function to
        // amortize among all is_zero_chip assignments.
        let value_invert = value.into_field().invert();
        region.assign_advice(
            || "witness inverse of value",
            config.value_inv,
            offset,
            || value_invert,
        )?;

        Ok(())
    }
}

/// The RLP Circuit is implemented as a finite state machine. Refer the
/// [design doc][doclink] for design decisions and specification details.
///
/// [doclink]: https://hackmd.io/VMjQdO0SRu2azN6bR_aOrQ?view
#[derive(Clone, Debug)]
pub struct RlpCircuitConfig<F> {
    /// Whether the row is the first row.
    q_first: Column<Fixed>,
    /// Whether the row is enabled.
    q_enabled: Column<Fixed>,
    /// The state of RLP verifier at the current row.
    state: Column<Advice>,
    /// A utility gadget to compare/query what state we are at.
    state_bits: BinaryNumberConfig<State, 3>,
    /// The Rlp table which can be accessed by other circuits.
    rlp_table: RlpFsmRlpTable,
    /// The tag, i.e. what field is being decoded at the current row.
    tag: Column<Advice>,
    /// A utility gadget to compare/query what tag we are at.
    tag_bits: BinaryNumberConfig<Tag, 5>,
    /// The tag that will be decoded next after the current tag is done decoding.
    tag_next: Column<Advice>,
    /// Boolean check whether or not the current tag represents a list or not.
    is_list: Column<Advice>,
    /// The maximum length, in terms of number of bytes that this tag can occupy.
    max_length: Column<Advice>,
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
    /// The accumulated value of the tag's bytes up to `tag_idx`.
    tag_value_acc: Column<Advice>,
    /// The depth at this row. Since RLP encoded data can be nested, we use
    /// the depth to go a level deeper and eventually leave that depth level.
    /// At depth == 0 we know that we are at the outermost level.
    depth: Column<Advice>,

    /// Check data_table.tx_id == 0 to know if it is meant to be padding row or not.
    is_padding_in_dt: IsZeroConfig<F>,

    /// Check equality between tx_id' and tx_id in the data table.
    tx_id_check_in_dt: IsEqualConfig<F>,
    /// Check equality between format' and format in the data table.
    format_check_in_dt: IsEqualConfig<F>,

    /// Check equality between tx_id' and tx_id in sm.
    tx_id_check_in_sm: IsEqualConfig<F>,
    /// Check equality between format' and format in sm.
    format_check_in_sm: IsEqualConfig<F>,

    /// Booleans to reduce the circuit's degree as tag_bits's degree is 5.
    is_tag_end: Column<Advice>,
    is_tag_begin: Column<Advice>,
    /// Boolean to reduce the circuit's degree
    /// is_case3 = (0xc0 <= byte_value < 0xf8) && (is_tag_end == false)
    is_case3: Column<Advice>,
    /// Boolean to reduce the circuit's degree
    /// transit_to_new_rlp_instance = (is_tag_end == true) && (depth == 1) && (state' != End)
    transit_to_new_rlp_instance: Column<Advice>,

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
    tidx_lte_tlength: ComparatorConfig<F, 3>,
    /// Check for tag_length <= 32
    tlength_lte_0x20: ComparatorConfig<F, 1>,
    /// Check for depth == 0
    depth_check: IsEqualConfig<F>,
    /// Check for depth == 1
    depth_eq_one: IsEqualConfig<F>,

    /// Internal tables
    /// Data table
    data_table: RlpFsmDataTable,
    /// ROM table
    rom_table: RlpFsmRomTable,
    /// Range256 table
    range256_table: Range256Table,
}

impl<F: Field> RlpCircuitConfig<F> {
    /// Configure the RLP circuit.
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        rom_table: RlpFsmRomTable,
        data_table: RlpFsmDataTable,
        rlp_table: RlpFsmRlpTable,
        range256_table: Range256Table,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let (tx_id, format) = (rlp_table.tx_id, rlp_table.format);
        let (
            q_first,
            q_enabled,
            byte_idx,
            byte_rev_idx,
            byte_value,
            state,
            tag,
            tag_next,
            is_list,
            max_length,
            tag_idx,
            tag_length,
            depth,
            is_tag_begin,
            is_tag_end,
            is_case3,
            transit_to_new_rlp_instance,
        ) = (
            meta.fixed_column(),
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
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        );

        let tag_value_acc = meta.advice_column_in(SecondPhase);
        let bytes_rlc = meta.advice_column_in(SecondPhase);

        let state_bits = BinaryNumberChip::configure(meta, q_enabled, Some(state.into()));
        let tag_bits = BinaryNumberChip::configure(meta, q_enabled, Some(tag.into()));

        // randomness values.
        let evm_word_rand = challenges.evm_word();
        let keccak_input_rand = challenges.keccak_input();

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

        //////////////////////////////////////////////////////////
        //////////// data table checks. //////////////////////////
        //////////////////////////////////////////////////////////
        let is_padding_in_dt = IsZeroChip::configure(
            meta,
            // the size of data table is always smaller than the size of sm rows
            // and q_enabled is true for all sm rows.
            |meta| meta.query_fixed(q_enabled, Rotation::cur()),
            data_table.tx_id,
        );

        let tx_id_check_in_dt = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enabled, Rotation::cur()),
            |meta| meta.query_advice(data_table.tx_id, Rotation::cur()),
            |meta| meta.query_advice(data_table.tx_id, Rotation::next()),
        );
        let format_check_in_dt = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enabled, Rotation::cur()),
            |meta| meta.query_advice(data_table.format, Rotation::cur()),
            |meta| meta.query_advice(data_table.format, Rotation::next()),
        );

        meta.create_gate("data table init checks", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "byte_idx starts from 1",
                meta.query_advice(data_table.byte_idx, Rotation::cur()),
                1.expr(),
            );
            cb.require_equal(
                "bytes_rlc starts from byte_value",
                meta.query_advice(data_table.bytes_rlc, Rotation::cur()),
                meta.query_advice(data_table.byte_value, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_first, Rotation::cur()))
        });

        meta.create_gate("data table checks", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // if the current row is padding, the next row is also padding.
            // if tx_id == 0 then tx_id' == 0
            cb.condition(is_padding_in_dt.expr(Rotation::cur())(meta), |cb| {
                // tx_id' = 0
                cb.require_zero(
                    "tx_id' == 0 if tx_id == 0",
                    meta.query_advice(data_table.tx_id, Rotation::next()),
                );
            });

            // if tx_id' != tx_id
            cb.condition(
                not::expr(tx_id_check_in_dt.is_equal_expression.expr()),
                |cb| {
                    // tx_id' == tx_id + 1 or tx_id' == 0
                    let (tx_id, tx_id_next) = (
                        meta.query_advice(data_table.tx_id, Rotation::cur()),
                        meta.query_advice(data_table.tx_id, Rotation::next()),
                    );
                    cb.require_zero(
                        "tx_id increments or decrements to 0",
                        (tx_id_next.expr() - tx_id - 1.expr()) * tx_id_next,
                    );
                },
            );

            // if tx_id' == tx_id
            cb.condition(tx_id_check_in_dt.is_equal_expression.expr(), |cb| {
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

            // if tx_id' == tx_id and format' == format
            cb.condition(
                and::expr([
                    not::expr(is_padding_in_dt.expr(Rotation::cur())(meta)),
                    tx_id_check_in_dt.is_equal_expression.expr(),
                    format_check_in_dt.is_equal_expression.expr(),
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

            // if (tx_id' == tx_id and format' != format) or (tx_id' != tx_id and tx_id' != 0)
            cb.condition(
                sum::expr([
                    // case 1
                    and::expr([
                        tx_id_check_in_dt.is_equal_expression.expr(),
                        not::expr(format_check_in_dt.is_equal_expression.expr()),
                    ]),
                    // case 2
                    and::expr([
                        not::expr(is_padding_in_dt.expr(Rotation::next())(meta)),
                        not::expr(tx_id_check_in_dt.is_equal_expression.expr()),
                    ]),
                ]),
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

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        meta.lookup_any("byte value check", |meta| {
            let cond = and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_padding_in_dt.expr(Rotation::cur())(meta),
            ]);

            vec![meta.query_advice(data_table.byte_value, Rotation::cur())]
                .into_iter()
                .zip(range256_table.table_exprs(meta).into_iter())
                .map(|(arg, table)| (cond.expr() * arg, table))
                .collect()
        });

        debug_assert!(meta.degree() <= 9);

        //////////////////////////////////////////////////////////
        //////////// sm lookups //////////////////////////////////
        //////////////////////////////////////////////////////////
        meta.lookup_any("data table lookup", |meta| {
            let q_enabled = meta.query_fixed(q_enabled, Rotation::cur());
            let cond = and::expr([q_enabled.expr(), not::expr(is_end(meta))]);

            let input_exprs = vec![
                1.expr(), // since data_table is not fixed.
                meta.query_advice(tx_id, Rotation::cur()),
                meta.query_advice(format, Rotation::cur()),
                meta.query_advice(byte_idx, Rotation::cur()),
                meta.query_advice(byte_rev_idx, Rotation::cur()),
                meta.query_advice(byte_value, Rotation::cur()),
                meta.query_advice(bytes_rlc, Rotation::cur()),
            ];
            let mut table_exprs = vec![q_enabled];
            table_exprs.extend(data_table.table_exprs(meta));
            assert_eq!(input_exprs.len(), table_exprs.len());

            input_exprs
                .into_iter()
                .zip(table_exprs.into_iter())
                .map(|(arg, table)| (cond.expr() * arg, table))
                .collect()
        });

        meta.lookup_any("ROM table lookup", |meta| {
            let cond = and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                not::expr(is_end(meta)),
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

        debug_assert!(meta.degree() <= 9);

        //////////////////////////////////////////////////
        /////////////////// SM checks ////////////////////
        //////////////////////////////////////////////////
        // construct the comparators.
        let cmp_enabled = |meta: &mut VirtualCells<F>| {
            and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                not::expr(is_end(meta)),
            ])
        };

        // macros that make the constraints more easier to read and understand
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

        macro_rules! constrain_unchanged_fields {
            ( $meta:ident, $cb:ident; $($field:expr),+ ) => {
                $(
                    $cb.require_equal(
                        concat!(stringify!($field), "_next = ", stringify!($field)),
                        $meta.query_advice($field, Rotation::cur()),
                        $meta.query_advice($field, Rotation::next()),
                    );
                )+
            };
        }

        macro_rules! constrain_eq {
            ( $meta:ident, $cb:ident, $field:expr, $value:expr ) => {
                $cb.require_equal(
                    concat!(stringify!($field), " = ", stringify!($value)),
                    $meta.query_advice($field, Rotation::cur()),
                    $value.expr(),
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
                    concat!("rlp_tag = ", stringify!($tag)),
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
                    concat!(stringify!($tag), " = ", stringify!($to)),
                    $meta.query_advice($tag, Rotation::next()),
                    $to.expr(),
                );
            };
        }

        // Booleans for comparing byte value
        byte_value_lte!(byte_value_lte_0x80, 0x80);
        byte_value_gte!(byte_value_gte_0x80, 0x80);
        byte_value_lte!(byte_value_lte_0xb8, 0xb8);
        byte_value_gte!(byte_value_gte_0xb8, 0xb8);
        byte_value_lte!(byte_value_lte_0xc0, 0xc0);
        byte_value_gte!(byte_value_gte_0xc0, 0xc0);
        byte_value_lte!(byte_value_lte_0xf8, 0xf8);
        byte_value_gte!(byte_value_gte_0xf8, 0xf8);

        // Booleans for comparing (tag_idx, tag_length, depth)
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

        // constraints on the booleans that we use to reduce degree
        meta.create_gate("booleans for reducing degree", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (bv_gt_0xc0, bv_eq_0xc0) = byte_value_gte_0xc0.expr(meta, None);
            let (bv_lt_0xf8, _) = byte_value_lte_0xf8.expr(meta, None);

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
            cb.require_equal(
                "is_case3 = (0xc0 <= byte_value < 0xf8) && (is_tag_end == false)",
                meta.query_advice(is_case3, Rotation::cur()),
                and::expr([
                    not::expr(meta.query_advice(is_tag_end, Rotation::cur())),
                    sum::expr([bv_gt_0xc0, bv_eq_0xc0]),
                    bv_lt_0xf8,
                ]),
            );
            cb.require_equal(
                "transit_to_new = (is_tag_end == true) && (depth == 1) && (state' != End)",
                meta.query_advice(transit_to_new_rlp_instance, Rotation::cur()),
                and::expr([
                    meta.query_advice(is_tag_end, Rotation::cur()),
                    depth_eq_one.is_equal_expression.expr(),
                    not::expr(is_next_end(meta)),
                ]),
            );

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

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
        let tag_value_acc_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(tag_value_acc, Rotation::cur());
        let is_tag_next_end_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(is_tag_end, Rotation::next());
        let is_tag_end_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(is_tag_end, Rotation::cur());
        let tx_id_check_in_sm = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enabled, Rotation::cur()),
            |meta| meta.query_advice(tx_id, Rotation::cur()),
            |meta| meta.query_advice(tx_id, Rotation::next()),
        );
        let format_check_in_sm = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enabled, Rotation::cur()),
            |meta| meta.query_advice(format, Rotation::cur()),
            |meta| meta.query_advice(format, Rotation::next()),
        );

        // TODO: add constraints on byte_idx transition
        meta.create_gate("state transition: byte_idx", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // if is_tag_next_end == 1 then
            //   next.byte_idx = cur.byte_idx
            // else
            //   next.byte_idx = cur.byte_idx + 1
            cb.condition(is_tag_next_end_expr(meta), |cb| {
                update_state!(meta, cb, byte_idx, byte_idx_expr(meta));
            });
            cb.condition(not::expr(is_tag_next_end_expr(meta)), |cb| {
                update_state!(meta, cb, byte_idx, byte_idx_expr(meta) + 1.expr());
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                tx_id_check_in_sm.is_equal_expression.expr(),
                format_check_in_sm.is_equal_expression.expr(),
            ]))
        });

        // DecodeTagStart => DecodeTagStart
        meta.create_gate(
            "state transition: DecodeTagStart => DecodeTagStart",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();
                let tag_expr = tag_expr(meta);
                let byte_value_expr = byte_value_expr(meta);

                let (bv_lt_0x80, bv_eq_0x80) = byte_value_lte_0x80.expr(meta, None);

                // case 1: 0x00 <= byte_value < 0x80
                let case_1 = and::expr([bv_lt_0x80, not::expr(is_tag_end_expr(meta))]);
                cb.condition(case_1.expr(), |cb| {
                    // assertions.
                    emit_rlp_tag!(meta, cb, tag_expr, false);

                    // is_list = false, tag_value_acc = byte_value
                    constrain_eq!(meta, cb, is_list, false);
                    constrain_eq!(meta, cb, rlp_table.tag_value, byte_value_expr);

                    // state transitions.
                    update_state!(meta, cb, tag, tag_next_expr(meta));
                    update_state!(meta, cb, state, DecodeTagStart);

                    constrain_unchanged_fields!(meta, cb; depth, rlp_table.tx_id, rlp_table.format);
                });

                // case 2: byte_value == 0x80
                let case_2 = and::expr([bv_eq_0x80, not::expr(is_tag_end_expr(meta))]);
                cb.condition(case_2.expr(), |cb| {
                    // assertions.
                    emit_rlp_tag!(meta, cb, tag_expr, true);

                    constrain_eq!(meta, cb, is_list, false);
                    constrain_eq!(meta, cb, rlp_table.tag_value, 0);

                    // state transitions.
                    update_state!(meta, cb, tag, tag_next_expr(meta));
                    update_state!(meta, cb, state, DecodeTagStart);

                    constrain_unchanged_fields!(meta, cb; depth, rlp_table.tx_id, rlp_table.format);
                });

                // case 3: 0xc0 <= byte_value < 0xf8
                let case_3 = meta.query_advice(is_case3, Rotation::cur());
                cb.condition(case_3.expr(), |cb| {
                    // assertions
                    constrain_eq!(meta, cb, is_list, true);

                    // state transitions.
                    update_state!(meta, cb, tag, tag_next_expr(meta));
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
                            rlp_table.tag_value,
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
                cb.condition(
                    and::expr([case_4.expr(), depth_eq_one.is_equal_expression.expr()]),
                    |cb| {
                        // assertions.
                        emit_rlp_tag!(meta, cb, RlpTag::RLC, false);
                        constrain_eq!(meta, cb, rlp_table.tag_value, bytes_rlc_expr(meta));
                        constrain_eq!(meta, cb, byte_rev_idx, 1);
                    },
                );
                cb.condition(
                    meta.query_advice(transit_to_new_rlp_instance, Rotation::cur()),
                    |cb| {
                        let tx_id = meta.query_advice(rlp_table.tx_id, Rotation::cur());
                        let tx_id_next = meta.query_advice(rlp_table.tx_id, Rotation::next());
                        let format = meta.query_advice(rlp_table.format, Rotation::cur());
                        let format_next = meta.query_advice(rlp_table.format, Rotation::next());

                        // state transition.
                        update_state!(meta, cb, byte_idx, 1);
                        update_state!(meta, cb, state, DecodeTagStart);
                        cb.require_zero(
                            "(tx_id' == tx_id + 1) or (format' == format + 1)",
                            (tx_id_next - tx_id - 1.expr()) * (format_next - format - 1.expr()),
                        );
                    },
                );
                cb.condition(
                    and::expr([
                        case_4.expr(),
                        not::expr(depth_eq_one.is_equal_expression.expr()),
                    ]),
                    |cb| {
                        update_state!(meta, cb, tag, tag_next_expr(meta));
                        update_state!(meta, cb, depth, depth_expr(meta) - 1.expr());
                        update_state!(meta, cb, state, DecodeTagStart);
                        constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format);
                    },
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enabled, Rotation::cur()),
                    is_decode_tag_start(meta),
                ]))
            },
        );

        // debug_assert!(meta.degree() <= 9);
        // DecodeTagStart => Bytes
        meta.create_gate("state transition: DecodeTagStart => Bytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (bv_gt_0x80, _) = byte_value_gte_0x80.expr(meta, None);
            let (bv_lt_0xb8, _) = byte_value_lte_0xb8.expr(meta, None);

            // condition.
            cb.condition(and::expr([
                bv_gt_0x80, bv_lt_0xb8,
                not::expr(is_tag_end_expr(meta)),
            ]), |cb| {
                // assertions
                do_not_emit!(meta, cb);
                constrain_eq!(meta, cb, is_list, false);

                // state transitions
                update_state!(meta, cb, tag_idx, 1);
                update_state!(meta, cb, tag_length, byte_value_expr(meta) - 0x80.expr());
                update_state!(meta, cb, tag_value_acc, byte_value_next_expr(meta));
                update_state!(meta, cb, state, State::Bytes);

                // depth is unchanged.
                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format, depth, tag, tag_next);
            });
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

                // state transitions
                update_state!(meta, cb, tag_idx, tag_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, tag_value_acc,
                    tag_value_acc_expr(meta) * b.expr() + byte_value_next_expr(meta));
                update_state!(meta, cb, state, State::Bytes);

                // depth, tag_length unchanged.
                constrain_unchanged_fields!(meta, cb; depth, tag, tag_next, tag_length, rlp_table.tx_id, rlp_table.format);
            });

            // Bytes => DecodeTagStart
            cb.condition(tidx_eq_tlen, |cb| {
                // assertions
                emit_rlp_tag!(meta, cb, tag_expr(meta), false);

                // state transitions.
                update_state!(meta, cb, tag, tag_next_expr(meta));
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
            let (bv_lt_0xc0, _) = byte_value_lte_0xc0.expr(meta, None);

            // condition: "0xb8 <= byte_value < 0xc0"
            cb.condition(and::expr([
                sum::expr([bv_gt_0xb8, bv_eq_0xb8]),
                not::expr(is_tag_end_expr(meta)),
                bv_lt_0xc0
            ]), |cb| {
                // assertions.
                do_not_emit!(meta, cb);
                constrain_eq!(meta, cb, is_list, false);

                // state transitions
                update_state!(meta, cb, tag_length, byte_value_expr(meta) - 0xb7.expr());
                update_state!(meta, cb, tag_idx, 1);
                update_state!(meta, cb, tag_value_acc, byte_value_next_expr(meta));
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
                do_not_emit!(meta, cb);

                // state transitions
                update_state!(meta, cb, tag_idx, tag_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, tag_value_acc,
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

                // state transition.
                update_state!(meta, cb, tag_length, tag_value_acc_expr(meta));
                update_state!(meta, cb, tag_idx, 1);
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
            cb.condition(and::expr([
                cond.expr(),
                not::expr(is_tag_end_expr(meta)),
            ]), |cb| {
                // assertions.
                constrain_eq!(meta, cb, is_tag_begin, true);

                // state transitions
                update_state!(meta, cb, tag_length, byte_value_expr(meta) - 0xf7.expr());
                update_state!(meta, cb, tag_idx, 1);
                update_state!(meta, cb, tag_value_acc, byte_value_next_expr(meta));
                update_state!(meta, cb, state, State::LongList);

                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format, tag, tag_next);
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
                do_not_emit!(meta, cb);

                // state transitions
                update_state!(meta, cb, tag_idx, tag_idx_expr(meta) + 1.expr());
                update_state!(
                    meta,
                    cb,
                    tag_value_acc,
                    tag_value_acc_expr(meta) * 256.expr() + byte_value_next_expr(meta)
                );
                update_state!(meta, cb, state, State::LongList);

                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format,
                    tag, tag_next, depth, tag_length);
            });

            // LongList => DecodeTagStart
            cb.condition(tidx_eq_tlen.expr(), |cb| {
                // assertions

                // state transitions
                update_state!(meta, cb, tag, tag_next_expr(meta));
                update_state!(meta, cb, depth, depth_expr(meta) + 1.expr());
                update_state!(meta, cb, state, State::DecodeTagStart);

                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format);
            });

            // depth == 0
            cb.condition(
                and::expr([tidx_eq_tlen.expr(), depth_check.is_equal_expression.expr()]),
                |cb| {
                    emit_rlp_tag!(meta, cb, RlpTag::Len, false);
                    constrain_eq!(meta, cb, tag_value_acc, byte_rev_idx_expr(meta) - 1.expr());
                    constrain_eq!(
                        meta,
                        cb,
                        rlp_table.tag_value,
                        byte_idx_expr(meta) + tag_value_acc_expr(meta)
                    );
                },
            );

            // depth != 0
            cb.condition(
                and::expr([
                    tidx_eq_tlen.expr(),
                    not::expr(depth_check.is_equal_expression.expr()),
                ]),
                |cb| {
                    do_not_emit!(meta, cb);
                },
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_long_list(meta),
            ]))
        });

        // DecodeTagStart => End
        /*
        TODO:
        meta.create_gate("state transition: DecodeTagStart => End", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(is_tag_end_expr(meta), |cb| {
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
         */

        // End => End
        meta.create_gate("state transition: End", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // assertions
            do_not_emit!(meta, cb);
            constrain_eq!(meta, cb, tx_id, 0);

            // state transitions
            update_state!(meta, cb, state, State::End);

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_end(meta),
            ]))
        });

        Self {
            q_first,
            q_enabled,
            state,
            state_bits,
            rlp_table,
            tag,
            tag_bits,
            tag_next,
            byte_idx,
            byte_rev_idx,
            byte_value,
            bytes_rlc,
            tag_idx,
            tag_length,
            tag_value_acc,
            is_list,
            max_length,
            depth,
            is_padding_in_dt,

            // data table checks.
            tx_id_check_in_dt,
            format_check_in_dt,

            tx_id_check_in_sm,
            format_check_in_sm,

            is_tag_begin,
            is_tag_end,
            is_case3,
            transit_to_new_rlp_instance,

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

            // internal tables
            data_table,
            rom_table,
            range256_table,
        }
    }

    fn assign_sm_row(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        witness: &RlpFsmWitnessRow<F>,
        witness_next: Option<&RlpFsmWitnessRow<F>>,
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
            || "rlp_table.tag_value",
            self.rlp_table.tag_value,
            row,
            || witness.rlp_table.tag_value,
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
            || "max_length",
            self.max_length,
            row,
            || Value::known(F::from(witness.state_machine.max_length as u64)),
        )?;
        region.assign_advice(
            || "is_list",
            self.is_list,
            row,
            || Value::known(F::from(witness.state_machine.tag.is_list() as u64)),
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
        region.assign_advice(
            || "sm.tag_value_acc",
            self.tag_value_acc,
            row,
            || witness.state_machine.tag_acc_value,
        )?;
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
        let byte_value = witness.state_machine.byte_value;
        let is_case3 =
            (byte_value < 0xf8) && (byte_value >= 0xc0) && !witness.state_machine.tag.is_end();
        let transit_to_new = witness.state_machine.tag.is_end()
            && (witness.state_machine.depth == 1)
            && witness_next.is_some();
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
        region.assign_advice(
            || "is_case3",
            self.is_case3,
            row,
            || Value::known(F::from(is_case3 as u64)),
        )?;
        region.assign_advice(
            || "transit_to_new_rlp_instance",
            self.transit_to_new_rlp_instance,
            row,
            || Value::known(F::from(transit_to_new as u64)),
        )?;

        let (tx_id_next, format_next) = if let Some(witness_next) = witness_next {
            (witness_next.rlp_table.tx_id, witness_next.rlp_table.format)
        } else {
            (0, Default::default())
        };

        let tx_id_check_chip = IsEqualChip::construct(self.tx_id_check_in_sm.clone());
        tx_id_check_chip.assign(
            region,
            row,
            Value::known(F::from(witness.rlp_table.tx_id as u64)),
            Value::known(F::from(tx_id_next as u64)),
        )?;

        let format_check_chip = IsEqualChip::construct(self.format_check_in_sm.clone());
        format_check_chip.assign(
            region,
            row,
            Value::known(F::from(witness.rlp_table.format as u64)),
            Value::known(F::from(usize::from(format_next) as u64)),
        )?;

        let tidx_le_tlength_chip = ComparatorChip::construct(self.tidx_lte_tlength.clone());
        tidx_le_tlength_chip.assign(
            region,
            row,
            F::from(witness.state_machine.tag_idx as u64),
            F::from(witness.state_machine.tag_length as u64),
        )?;

        let depth_check_chip = IsEqualChip::construct(self.depth_check.clone());
        depth_check_chip.assign(
            region,
            row,
            Value::known(F::from(witness.state_machine.depth as u64)),
            Value::known(F::zero()),
        )?;

        let depth_eq_one_chip = IsEqualChip::construct(self.depth_eq_one.clone());
        depth_eq_one_chip.assign(
            region,
            row,
            Value::known(F::from(witness.state_machine.depth as u64)),
            Value::known(F::one()),
        )?;

        let tlength_lte_0x20_chip = ComparatorChip::construct(self.tlength_lte_0x20.clone());
        tlength_lte_0x20_chip.assign(
            region,
            row,
            F::from(witness.state_machine.tag_length as u64),
            F::from(0x20),
        )?;

        let tag_chip = BinaryNumberChip::construct(self.tag_bits);
        tag_chip.assign(region, row, &witness.state_machine.tag)?;

        let state_chip = BinaryNumberChip::construct(self.state_bits);
        state_chip.assign(region, row, &witness.state_machine.state)?;

        let byte_value = F::from(witness.state_machine.byte_value as u64);
        let byte_0x80 = F::from(0x80_u64);
        let byte_0xb8 = F::from(0xb8_u64);
        let byte_0xc0 = F::from(0xc0_u64);
        let byte_0xf8 = F::from(0xf8_u64);
        let byte_value_lte_0x80 = ComparatorChip::construct(self.byte_value_lte_0x80.clone());
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

    fn assign_dt_row(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        witness: &DataTable<F>,
        witness_next: Option<&DataTable<F>>,
    ) -> Result<(), Error> {
        for (&column, value) in
            <RlpFsmDataTable as LookupTable<F>>::advice_columns(&self.data_table)
                .iter()
                .zip(witness.values().into_iter())
        {
            region.assign_advice(
                || format!("RLP data table row: row = {}", row),
                column,
                row,
                || value,
            )?;
        }
        let tx_id_check_chip = IsEqualChip::construct(self.tx_id_check_in_dt.clone());
        let (tx_id_next, format_next) = if let Some(witness_next) = witness_next {
            (witness_next.tx_id, witness_next.format)
        } else {
            (0, Default::default())
        };
        let padding_chip = IsZeroChip::construct(self.is_padding_in_dt.clone());
        padding_chip.assign(region, row, Value::known(F::from(witness.tx_id as u64)))?;
        tx_id_check_chip.assign(
            region,
            row,
            Value::known(F::from(witness.tx_id)),
            Value::known(F::from(tx_id_next)),
        )?;
        let format_check_chip = IsEqualChip::construct(self.format_check_in_dt.clone());
        format_check_chip.assign(
            region,
            row,
            Value::known(F::from(usize::from(witness.format) as u64)),
            Value::known(F::from(usize::from(format_next) as u64)),
        )?;

        Ok(())
    }

    /// Assign witness to the RLP circuit.
    pub(crate) fn assign<RLP: RlpFsmWitnessGen<F>>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: &[RLP],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let dt_rows = inputs
            .iter()
            .flat_map(|input| input.gen_data_table(challenges))
            .collect::<Vec<_>>();
        let sm_rows = inputs
            .iter()
            .flat_map(|input| input.gen_sm_witness(challenges))
            .collect::<Vec<_>>();

        self.range256_table.load(layouter)?;
        self.rom_table.load(layouter)?;

        log::debug!("num_sm_rows: {}", sm_rows.len());
        log::debug!("num_dt_rows: {}", dt_rows.len());

        layouter.assign_region(
            || "RLP data table region",
            |mut region| {
                for (i, dt_row) in dt_rows.iter().enumerate() {
                    let dt_row_next = if i == dt_rows.len() - 1 {
                        None
                    } else {
                        Some(&dt_rows[i + 1])
                    };
                    self.assign_dt_row(&mut region, i, dt_row, dt_row_next)?;
                }
                // assign padding rows
                Ok(())
            },
        )?;
        layouter.assign_region(
            || "RLP sm region",
            |mut region| {
                for (i, sm_row) in sm_rows.iter().enumerate() {
                    let sm_row_next = if i == sm_rows.len() - 1 {
                        None
                    } else {
                        Some(&sm_rows[i + 1])
                    };
                    self.assign_sm_row(&mut region, i, sm_row, sm_row_next)?;
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
            args.rom_table,
            args.data_table,
            args.rlp_table,
            args.range256_table,
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

impl<F: Field> SubCircuit<F> for RlpCircuit<F, Transaction> {
    type Config = RlpCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        let max_txs = block.circuits_params.max_txs;
        debug_assert!(block.txs.len() <= max_txs);

        Self {
            txs: block.txs.clone(),
            max_txs,
            size: 0,
            _marker: Default::default(),
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign(layouter, &self.txs, challenges)
    }

    fn min_num_rows_block(block: &Block<F>) -> (usize, usize) {
        let challenges: Challenges<Value<F>> =
            Challenges::mock(Value::unknown(), Value::unknown(), Value::unknown());
        let sm_rows: usize = block
            .txs
            .iter()
            .map(|tx| tx.gen_sm_witness(&challenges).len())
            .sum();

        // TODO: fix me
        (sm_rows, sm_rows)
    }
}

impl<F: Field> Circuit<F> for RlpCircuit<F, Transaction> {
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
            rom_table,
            data_table,
            rlp_table,
            u8_table,
            &challenge_exprs,
        );
        log::debug!("meta.degree() = {}", meta.degree());

        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = &config.1.values(&layouter);

        self.synthesize_sub(&config.0, challenges, &mut layouter)
    }
}

#[cfg(test)]
mod tests {
    use crate::{rlp_circuit_fsm::RlpCircuit, witness::Transaction};
    use eth_types::{geth_types::TxTypes, word, Address};
    use ethers_core::types::{transaction::eip2718::TypedTransaction, TransactionRequest};
    use ethers_signers::Wallet;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use mock::{eth, MOCK_CHAIN_ID};
    use rand::rngs::OsRng;

    fn get_tx(is_eip155: bool) -> Transaction {
        let rng = &mut OsRng;
        let from = Wallet::new(rng);
        let mut tx = TransactionRequest::new()
            .to(Address::random())
            .value(eth(10))
            .data(Vec::new())
            .gas_price(word!("0x4321"))
            .gas(word!("0x77320"))
            .nonce(word!("0x7f"));
        if is_eip155 {
            tx = tx.chain_id(MOCK_CHAIN_ID.as_u64());
        }
        let (tx_type, unsigned_bytes) = if is_eip155 {
            (TxTypes::Eip155, tx.rlp().to_vec())
        } else {
            (TxTypes::PreEip155, tx.rlp_unsigned().to_vec())
        };
        let typed_tx: TypedTransaction = tx.into();
        let sig = from.sign_transaction_sync(&typed_tx);
        let signed_bytes = typed_tx.rlp_signed(&sig).to_vec();

        log::debug!("num_unsigned_bytes: {}", unsigned_bytes.len());
        log::debug!("num_signed_bytes: {}", signed_bytes.len());

        Transaction::new_from_rlp_bytes(tx_type, signed_bytes, unsigned_bytes)
    }

    #[test]
    fn test_eip_155_tx() {
        let tx = get_tx(true);
        let rlp_circuit = RlpCircuit::<Fr, Transaction> {
            txs: vec![tx],
            max_txs: 10,
            size: 0,
            _marker: Default::default(),
        };

        let mock_prover = MockProver::run(14, &rlp_circuit, vec![]);
        assert!(mock_prover.is_ok());
        let mock_prover = mock_prover.unwrap();
        if let Err(errors) = mock_prover.verify_par() {
            log::debug!("errors.len() = {}", errors.len());
        }

        mock_prover.assert_satisfied_par();
    }

    #[test]
    fn test_pre_eip155_tx() {
        let tx = get_tx(false);
        let rlp_circuit = RlpCircuit::<Fr, Transaction> {
            txs: vec![tx],
            max_txs: 10,
            size: 0,
            _marker: Default::default(),
        };

        let mock_prover = MockProver::run(16, &rlp_circuit, vec![]);
        assert!(mock_prover.is_ok());
        let mock_prover = mock_prover.unwrap();
        if let Err(errors) = mock_prover.verify_par() {
            log::debug!("errors.len() = {}", errors.len());
        }

        mock_prover.assert_satisfied_par();
    }
}
