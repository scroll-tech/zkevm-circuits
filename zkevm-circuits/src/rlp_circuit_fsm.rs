//! Circuit implementation for verifying assignments to the RLP finite state machine.
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;

#[cfg(any(feature = "test", test))]
mod test;

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, RlpFsmRlpTable, U8Table},
    util::{
        is_zero::{IsZeroChip, IsZeroConfig},
        Challenges, SubCircuit, SubCircuitConfig,
    },
    witness::{
        rlp_fsm::StackOp,
        Block, DataTable, Format, RlpFsmWitnessGen, RlpFsmWitnessRow, RlpTag, RomTableRow, State,
        State::{DecodeTagStart, End},
        Tag,
        Tag::{AccessListAddress, AccessListStorageKey, BeginObject, EndObject, EndVector, TxType},
        Transaction,
    },
};
use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig, ComparatorInstruction},
    is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction},
    util::{and, not, select, sum, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{
        Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use std::marker::PhantomData;
use strum::IntoEnumIterator;

/// Data table allows us a lookup argument from the RLP circuit to check the byte value at an index
/// while decoding a tx of a given format.
#[derive(Clone, Copy, Debug)]
pub struct RlpFsmDataTable {
    /// Transaction index in the chunk of txs.
    pub tx_id: Column<Advice>,
    /// Format of the tx being decoded.
    pub format: Column<Advice>,
    /// The index of the current byte.
    pub byte_idx: Column<Advice>,
    /// The reverse index at this byte.
    pub byte_rev_idx: Column<Advice>,
    /// The byte value at this index.
    pub byte_value: Column<Advice>,
    /// The accumulated Random Linear Combination up until (including) the current byte.
    pub bytes_rlc: Column<Advice>,
    /// The accumulated gas cost up until (including) the current byte.
    pub gas_cost_acc: Column<Advice>,
}

impl<F: Field> LookupTable<F> for RlpFsmDataTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.tx_id.into(),
            self.format.into(),
            self.byte_idx.into(),
            self.byte_rev_idx.into(),
            self.byte_value.into(),
            self.bytes_rlc.into(),
            self.gas_cost_acc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tx_id"),
            String::from("format"),
            String::from("byte_idx"),
            String::from("byte_rev_idx"),
            String::from("byte_value"),
            String::from("bytes_rlc"),
        ]
    }
}

impl RlpFsmDataTable {
    /// Construct the data table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tx_id: meta.advice_column(),
            format: meta.advice_column(),
            byte_idx: meta.advice_column(),
            byte_rev_idx: meta.advice_column(),
            byte_value: meta.advice_column(),
            bytes_rlc: meta.advice_column_in(SecondPhase),
            gas_cost_acc: meta.advice_column(),
        }
    }
}

/// Read-only Memory table for the new RLP circuit design based on state machine. This table allows
/// us a lookup argument from the RLP circuit to check if a given row can occur depending on the tx
/// format, current and next tag.
#[derive(Clone, Copy, Debug)]
pub struct RlpFsmRomTable {
    /// Tag of the current field being decoded.
    pub tag: Column<Fixed>,
    /// Tag of the following field when the current field is finished decoding.
    pub tag_next: Column<Fixed>,
    /// The maximum length in terms of number of bytes that the current tag can take up.
    pub max_length: Column<Fixed>,
    /// Whether the current tag is a list or not.
    pub is_list: Column<Fixed>,
    /// The format of the current witness. This represents the type of tx we are decoding.
    pub format: Column<Fixed>,
}

impl<F: Field> LookupTable<F> for RlpFsmRomTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.tag.into(),
            self.tag_next.into(),
            self.max_length.into(),
            self.is_list.into(),
            self.format.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tag"),
            String::from("tag_next"),
            String::from("max_length"),
            String::from("is_list"),
            String::from("format"),
        ]
    }
}

impl RlpFsmRomTable {
    /// Construct the ROM table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.fixed_column(),
            tag_next: meta.fixed_column(),
            max_length: meta.fixed_column(),
            is_list: meta.fixed_column(),
            format: meta.fixed_column(),
        }
    }

    /// Load the ROM table.
    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "RLP ROM table",
            |mut region| {
                let rows: Vec<RomTableRow> = Format::iter()
                    .map(|format| format.rom_table_rows())
                    .concat();

                for (offset, row) in rows.iter().enumerate() {
                    for (&column, value) in <RlpFsmRomTable as LookupTable<F>>::fixed_columns(self)
                        .iter()
                        .zip(row.values::<F>().into_iter())
                    {
                        region.assign_fixed(
                            || format!("rom table row: offset = {offset}"),
                            column,
                            offset,
                            || value,
                        )?;
                    }
                }

                Ok(())
            },
        )
    }
}

/// Data decoding table simulates a stack-like structure for constraining remaining_bytes
#[derive(Clone, Copy, Debug)]
pub struct RlpDecodingTable {
    /// Key1 (Id), concat of (tx_id, format, depth, al_idx, sk_idx)
    pub id: Column<Advice>,
    /// Tx Id
    pub tx_id: Column<Advice>,
    /// Format
    pub format: Column<Advice>,
    /// Depth
    pub depth: Column<Advice>,
    /// Byte idx for comparing with state machine
    /// Byte idx is also used as Op counter similar to rw counter
    pub byte_idx: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
    /// Value Previous
    pub value_prev: Column<Advice>,
    /// Stack Op flag, Init
    pub is_stack_init: Column<Advice>,
    /// Stack Op flag, Push
    pub is_stack_push: Column<Advice>,
    /// Stack Op flag, Pop
    pub is_stack_pop: Column<Advice>,
    /// Stack Op flag, Update
    pub is_stack_update: Column<Advice>,
    /// Access list idx
    pub al_idx: Column<Advice>,
    /// Storage key idx
    pub sk_idx: Column<Advice>,
}

impl RlpDecodingTable {
    /// Construct the decoding table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            id: meta.advice_column_in(SecondPhase),
            tx_id: meta.advice_column(),
            format: meta.advice_column(),
            depth: meta.advice_column(),
            byte_idx: meta.advice_column(),
            value: meta.advice_column(),
            value_prev: meta.advice_column(),
            is_stack_init: meta.advice_column(),
            is_stack_push: meta.advice_column(),
            is_stack_pop: meta.advice_column(),
            is_stack_update: meta.advice_column(),
            al_idx: meta.advice_column(),
            sk_idx: meta.advice_column(),
        }
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
    /// Whether the row is the last row.
    q_last: Column<Fixed>,
    /// The state of RLP verifier at the current row.
    state: Column<Advice>,
    /// A utility gadget to compare/query what state we are at.
    state_bits: BinaryNumberConfig<State, 3>,
    /// The Rlp table which can be accessed by other circuits.
    rlp_table: RlpFsmRlpTable,
    /// The Rlp decoding table ensuring correct transition of
    /// stack constraints on remaining_bytes
    rlp_decoding_table: RlpDecodingTable,
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
    /// The gas cost accumulator of all the bytes of this RLP instance.
    gas_cost_acc: Column<Advice>,
    /// When the tag occupies several bytes, this index denotes the
    /// incremental index of the byte within this tag instance.
    tag_idx: Column<Advice>,
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
    /// transit_to_new_rlp_instance = (is_tag_end == true) && (depth == 0) && (state' != End)
    transit_to_new_rlp_instance: Column<Advice>,
    /// Boolean to reduce the circuit's degree
    is_same_rlp_instance: Column<Advice>,

    /// Boolean to reduce the circuit's degree
    /// Indicates the start of another new access list item
    is_new_access_list_address: Column<Advice>,
    /// Boolean to reduce the circuit's degree
    /// Indicates the start of another new storage key for an access list address
    is_new_access_list_storage_key: Column<Advice>,
    /// Boolean to reduce the circuit's degree
    /// Indicates the end of access list
    is_access_list_end: Column<Advice>,
    /// Boolean to reduce the circuit's degree
    /// Indicates the end of storage key list in a particular access list item
    is_storage_key_list_end: Column<Advice>,
    /// Decoding table id change
    /// id = (tx_id, format, depth, al_idx, sk_idx)
    stack_op_id_diff: Column<Advice>,
    /// Decoding table depth boolean to reduce degree.
    /// Indicates depth is 0.
    is_stack_depth_zero: Column<Advice>,
    /// Decoding table depth indicator for depth is 1.
    is_stack_depth_one: Column<Advice>,
    /// Decoding table depth indicator for depth is 2.
    is_stack_depth_two: Column<Advice>,
    /// Decoding table depth indicator for depth is 3.
    is_stack_depth_three: Column<Advice>,
    /// Decoding table depth indicator for depth is 4.
    is_stack_depth_four: Column<Advice>,
    /// Decoding table key change indicator. depth change.
    is_stack_depth_diff: Column<Advice>,
    /// Decoding table key change indicator. access list idx change.
    is_stack_al_idx_diff: Column<Advice>,
    /// Decoding table key change indicator. storage key idx change.
    is_stack_sk_idx_diff: Column<Advice>,
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
    /// Check for max_length <= 32
    mlength_lte_0x20: ComparatorConfig<F, 3>,
    /// Check for tag_length <= max_length
    tlength_lte_mlength: ComparatorConfig<F, 3>,
    /// Check for depth == 0
    depth_check: IsEqualConfig<F>,
    /// Check for depth == 1
    depth_eq_one: IsEqualConfig<F>,
    /// CHeck for depth == 2
    depth_eq_two: IsEqualConfig<F>,
    /// Check for depth == 4
    depth_eq_four: IsEqualConfig<F>,
    /// Check for byte_value == 0
    byte_value_is_zero: IsZeroConfig<F>,

    /// Internal tables
    /// Data table
    data_table: RlpFsmDataTable,
    /// ROM table
    rom_table: RlpFsmRomTable,
    /// Range u8 table
    u8_table: U8Table,
}

impl<F: Field> RlpCircuitConfig<F> {
    /// Configure the RLP circuit.
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        rom_table: RlpFsmRomTable,
        data_table: RlpFsmDataTable,
        u8_table: U8Table,
        rlp_table: RlpFsmRlpTable,
        rlp_decoding_table: RlpDecodingTable,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let (tx_id, format) = (rlp_table.tx_id, rlp_table.format);
        let tag_length = rlp_table.tag_length;
        let q_enabled = rlp_table.q_enable;
        let (
            q_first,
            q_last,
            byte_idx,
            byte_rev_idx,
            byte_value,
            gas_cost_acc,
            state,
            tag,
            tag_next,
            is_list,
            max_length,
            tag_idx,
            depth,
            is_tag_begin,
            is_tag_end,
            is_case3,
            transit_to_new_rlp_instance,
            is_same_rlp_instance,
            is_new_access_list_address,
            is_new_access_list_storage_key,
            is_access_list_end,
            is_storage_key_list_end,
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

        is_tag!(is_tag_begin_object, BeginObject);
        is_tag!(is_tag_begin_vector, BeginVector);
        is_tag!(is_tag_end_object, EndObject);
        is_tag!(is_tag_end_vector, EndVector);
        is_tag!(is_access_list_address, AccessListAddress);
        is_tag!(is_access_list_storage_key, AccessListStorageKey);

        //////////////////////////////////////////////////////////
        //////////// data table checks. //////////////////////////
        //////////////////////////////////////////////////////////
        let is_padding_in_dt = IsZeroChip::configure(
            meta,
            // the size of data table is always smaller than the size of sm rows
            // and q_enabled is true for all sm rows.
            |meta| meta.query_fixed(q_enabled, Rotation::cur()),
            data_table.tx_id,
            |meta| meta.advice_column(),
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

            // These two cases are not the very last non-padding RLP instance.
            // 1. (tx_id' == tx_id and format' != format)
            // 2. (tx_id' != tx_id and tx_id' != 0)
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

            // For the very last non-padding RLP instance, we have
            //   tx_id' != tx_id && tx_id' == 0
            cb.condition(
                and::expr([
                    is_padding_in_dt.expr(Rotation::next())(meta),
                    not::expr(tx_id_check_in_dt.is_equal_expression.expr()),
                ]),
                |cb| {
                    // byte_rev_idx == 1
                    cb.require_equal(
                        "byte_rev_idx is 1 at the last index",
                        meta.query_advice(data_table.byte_rev_idx, Rotation::cur()),
                        1.expr(),
                    );
                },
            );

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        meta.lookup("byte value check", |meta| {
            let cond = and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                not::expr(is_padding_in_dt.expr(Rotation::cur())(meta)),
            ]);

            vec![(
                cond * meta.query_advice(data_table.byte_value, Rotation::cur()),
                u8_table.into(),
            )]
        });

        debug_assert!(meta.degree() <= 9);

        //////////////////////////////////////////////////////////
        //////////// SM lookups //////////////////////////////////
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
                meta.query_advice(gas_cost_acc, Rotation::cur()),
            ];
            let mut table_exprs = vec![q_enabled];
            table_exprs.extend(data_table.table_exprs(meta));
            assert_eq!(input_exprs.len(), table_exprs.len());

            input_exprs
                .into_iter()
                .zip(table_exprs)
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
            .zip(rom_table.table_exprs(meta))
            .map(|(arg, table)| (cond.expr() * arg, table))
            .collect()
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////
        /////////////////// SM state transition checks ////////////////////
        ///////////////////////////////////////////////////////////////////
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
                    u8_table.into(),
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
                    u8_table.into(),
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
            u8_table.into(),
        );
        let mlength_lte_0x20 = ComparatorChip::configure(
            meta,
            cmp_enabled,
            |meta| meta.query_advice(max_length, Rotation::cur()),
            |_meta| 0x20.expr(),
            u8_table.into(),
        );
        let tlength_lte_mlength = ComparatorChip::configure(
            meta,
            cmp_enabled,
            |meta| meta.query_advice(tag_length, Rotation::cur()),
            |meta| meta.query_advice(max_length, Rotation::cur()),
            u8_table.into(),
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
        let depth_eq_two = IsEqualChip::configure(
            meta,
            cmp_enabled,
            |meta| meta.query_advice(depth, Rotation::cur()),
            |_| 2.expr(),
        );
        let depth_eq_four = IsEqualChip::configure(
            meta,
            cmp_enabled,
            |meta| meta.query_advice(depth, Rotation::cur()),
            |_| 4.expr(),
        );
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
        let byte_value_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(q_enabled, Rotation::cur()),
            byte_value,
            |meta| meta.advice_column(),
        );

        // constraints on the booleans that we use to reduce degree
        meta.create_gate("booleans for reducing degree (part one)", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (bv_gt_0xc0, bv_eq_0xc0) = byte_value_gte_0xc0.expr(meta, None);
            let (bv_lt_0xf8, _) = byte_value_lte_0xf8.expr(meta, None);

            // use sum instead of or because is_tag_* cannot be true at the same time
            cb.require_equal(
                "is_tag_end = is_tag_end_object || is_tag_end_vector",
                meta.query_advice(is_tag_end, Rotation::cur()),
                sum::expr([is_tag_end_object(meta), is_tag_end_vector(meta)]),
            );
            cb.require_equal(
                "is_tag_begin = is_tag_begin_object || is_tag_begin_vector",
                meta.query_advice(is_tag_begin, Rotation::cur()),
                sum::expr([is_tag_begin_object(meta), is_tag_begin_vector(meta)]),
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

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                not::expr(is_end(meta)),
            ]))
        });
        meta.create_gate("booleans for reducing degree (part two)", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "transit_to_new = (is_tag_end == true) && (depth == 0) && (state' != End)",
                meta.query_advice(transit_to_new_rlp_instance, Rotation::cur()),
                and::expr([
                    meta.query_advice(is_tag_end, Rotation::cur()),
                    depth_check.is_equal_expression.expr(),
                    not::expr(is_next_end(meta)),
                ]),
            );

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });
        meta.create_gate("booleans for reducing degree (part three)", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_same_rlp_instance",
                meta.query_advice(is_same_rlp_instance, Rotation::cur()),
                and::expr([
                    tx_id_check_in_sm.is_equal_expression.expr(),
                    format_check_in_sm.is_equal_expression.expr(),
                ]),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                not::expr(is_end(meta)),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

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
        let tag_bytes_rlc_expr = |meta: &mut VirtualCells<F>| {
            meta.query_advice(rlp_table.tag_bytes_rlc, Rotation::cur())
        };
        let is_tag_next_end_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(is_tag_end, Rotation::next());
        let is_tag_end_expr =
            |meta: &mut VirtualCells<F>| meta.query_advice(is_tag_end, Rotation::cur());

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
                not::expr(is_end(meta)),
                meta.query_advice(is_same_rlp_instance, Rotation::cur()),
            ]))
        });
        debug_assert!(meta.degree() <= 9);

        meta.create_gate("sm init", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            let tag = tag_expr(meta);

            constrain_eq!(meta, cb, state, DecodeTagStart.expr());
            constrain_eq!(meta, cb, tx_id, 1.expr());
            constrain_eq!(meta, cb, byte_idx, 1.expr());
            cb.require_zero(
                "tag == TxType or tag == BeginObject",
                (tag.expr() - TxType.expr()) * (tag - BeginObject.expr()),
            );

            cb.gate(meta.query_fixed(q_first, Rotation::cur()))
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
                    constrain_eq!(meta, cb, rlp_table.tag_bytes_rlc, byte_value_expr);
                    constrain_eq!(meta, cb, rlp_table.tag_length, 1);

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
                    constrain_eq!(meta, cb, rlp_table.tag_bytes_rlc, 0);
                    constrain_eq!(meta, cb, rlp_table.tag_length, 0);

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

                // case 4: tag in [EndObject, EndVector]
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
                    and::expr([case_4.expr(), depth_check.is_equal_expression.expr()]),
                    |cb| {
                        let gas_cost = meta.query_advice(gas_cost_acc, Rotation::cur());

                        // assertions
                        emit_rlp_tag!(meta, cb, RlpTag::GasCost, false);
                        constrain_eq!(meta, cb, rlp_table.tag_value, gas_cost);
                    },
                );
                cb.condition(
                    meta.query_advice(transit_to_new_rlp_instance, Rotation::cur()),
                    |cb| {
                        let tag_next = meta.query_advice(tag, Rotation::next());

                        // state transition.
                        update_state!(meta, cb, byte_idx, 1);
                        update_state!(meta, cb, depth, 0);
                        update_state!(meta, cb, state, DecodeTagStart);

                        cb.require_zero(
                            "tag == TxType or tag == BeginObject",
                            (tag_next.expr() - TxType.expr())
                                * (tag_next.expr() - BeginObject.expr()),
                        );
                    },
                );
                // tx_id' == tx_id => format' == format + 1
                cb.condition(
                    and::expr([
                        meta.query_advice(transit_to_new_rlp_instance, Rotation::cur()),
                        tx_id_check_in_sm.is_equal_expression.expr(),
                    ]),
                    |cb| {
                        let format = meta.query_advice(rlp_table.format, Rotation::cur());
                        let format_next = meta.query_advice(rlp_table.format, Rotation::next());
                        cb.require_equal("format' == format + 1", format_next, format + 1.expr());
                    },
                );
                // tx_id' != tx_id => tx_id' == tx_id + 1
                cb.condition(
                    and::expr([
                        meta.query_advice(transit_to_new_rlp_instance, Rotation::cur()),
                        not::expr(tx_id_check_in_sm.is_equal_expression.expr()),
                    ]),
                    |cb| {
                        let tx_id = meta.query_advice(rlp_table.tx_id, Rotation::cur());
                        let tx_id_next = meta.query_advice(rlp_table.tx_id, Rotation::next());
                        cb.require_equal("tx_id' == tx_id + 1", tx_id_next, tx_id + 1.expr());
                    },
                );
                cb.condition(
                    and::expr([
                        case_4.expr(),
                        not::expr(depth_check.is_equal_expression.expr()), // depth > 0
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
                update_state!(meta, cb, rlp_table.tag_bytes_rlc, byte_value_next_expr(meta));
                update_state!(meta, cb, state, State::Bytes);

                // depth is unchanged.
                constrain_unchanged_fields!(meta, cb; rlp_table.tx_id, rlp_table.format, depth, tag, tag_next);
            });
            // otherwise, we get an invalid rlp error.

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
            let (mlen_lt_0x20, mlen_eq_0x20) = mlength_lte_0x20.expr(meta, None);

            let b = select::expr(
                mlen_lt_0x20,
                256.expr(),
                select::expr(mlen_eq_0x20, evm_word_rand, keccak_input_rand.expr()),
            );

            // Bytes => Bytes
            cb.condition(tidx_lt_tlen, |cb| {
                // assertions
                do_not_emit!(meta, cb);

                // state transitions
                update_state!(meta, cb, tag_idx, tag_idx_expr(meta) + 1.expr());
                update_state!(meta, cb, tag_value_acc,
                    tag_value_acc_expr(meta) * b.expr() + byte_value_next_expr(meta));
                update_state!(meta, cb, rlp_table.tag_bytes_rlc,
                    tag_bytes_rlc_expr(meta) * keccak_input_rand.expr() + byte_value_next_expr(meta));
                update_state!(meta, cb, state, State::Bytes);

                // depth, tag_length unchanged.
                constrain_unchanged_fields!(meta, cb; depth, tag, tag_next, tag_length, rlp_table.tx_id, rlp_table.format);
            });

            // Bytes => DecodeTagStart
            cb.condition(tidx_eq_tlen, |cb| {
                // assertions
                let (lt, eq) = tlength_lte_mlength.expr(meta, Some(Rotation::cur()));
                cb.require_equal(
                    "tag_length <= max_length",
                    // we can use `sum` instead of `or` for two reasons
                    // 1. both `lt` and `eq` are boolean and they cannot be true at the same time,
                    //    therefore the result of `sum` is same as `or`.
                    // 2. sum has lower degree
                    sum::expr([
                        lt, eq,
                    ]),
                    true.expr(),
                );
                emit_rlp_tag!(meta, cb, tag_expr(meta), false);
                constrain_eq!(meta, cb, rlp_table.tag_value, tag_value_acc_expr(meta));

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
                update_state!(meta, cb, rlp_table.tag_bytes_rlc, byte_value_next_expr(meta));
                update_state!(meta, cb, tag_value_acc, byte_value_next_expr(meta));
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

            let cond = and::expr([
                sum::expr([bv_gt_0xf8, bv_eq_0xf8]),
                not::expr(is_tag_end_expr(meta)),
            ]);
            cb.condition(cond.expr(), |cb| {
                // assertions.
                do_not_emit!(meta, cb);
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
                let (lt, eq) = tlength_lte_mlength.expr(meta, Some(Rotation::cur()));
                cb.require_equal("tag_length <= max_length", sum::expr([lt, eq]), true.expr());

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
        meta.create_gate("state transition: DecodeTagStart => End", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // condition.
            cb.require_equal(
                "depth == 0",
                depth_check.is_equal_expression.expr(),
                true.expr(),
            );
            cb.require_equal("is_tag_end == true", is_tag_end_expr(meta), true.expr());

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_decode_tag_start(meta),
                is_next_end(meta),
            ]))
        });

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

        meta.create_gate("sm ends in End state", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            constrain_eq!(meta, cb, state, State::End);

            cb.gate(meta.query_fixed(q_last, Rotation::cur()))
        });

        ///////////////////////////////////////////////////////////////////
        /////////////////// Access List Constraint Transitions ////////////
        ///////////////////////////////////////////////////////////////////
        meta.create_gate("booleans for reducing degree (part four)", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_new_access_list_address",
                meta.query_advice(is_new_access_list_address, Rotation::cur()),
                is_access_list_address(meta),
            );
            cb.require_equal(
                "is_new_access_list_storage_key",
                meta.query_advice(is_new_access_list_storage_key, Rotation::cur()),
                is_access_list_storage_key(meta),
            );
            cb.require_boolean(
                "is_new_access_list_address is boolean",
                meta.query_advice(is_new_access_list_address, Rotation::cur()),
            );
            cb.require_boolean(
                "is_new_access_list_storage_key is boolean",
                meta.query_advice(is_new_access_list_storage_key, Rotation::cur()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_decode_tag_start(meta),
            ]))
        });
        meta.create_gate("boolean for reducing degree (part five)", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_access_list_end",
                meta.query_advice(is_access_list_end, Rotation::cur()),
                depth_eq_two.is_equal_expression.expr(),
            );
            cb.require_equal(
                "is_storage_key_list_end",
                meta.query_advice(is_storage_key_list_end, Rotation::cur()),
                depth_eq_four.is_equal_expression.expr(),
            );
            cb.require_boolean(
                "is_access_list_end is boolean",
                meta.query_advice(is_access_list_end, Rotation::cur()),
            );
            cb.require_boolean(
                "is_storage_key_list_end is boolean",
                meta.query_advice(is_storage_key_list_end, Rotation::cur()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                is_tag_end_vector(meta),
            ]))
        });

        // Access List Increments
        meta.create_gate("access list: access_list_idx increments", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(
                meta.query_advice(is_new_access_list_address, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "al_idx - al_idx::prev = 1",
                        meta.query_advice(rlp_table.access_list_idx, Rotation::prev()) + 1.expr(),
                        meta.query_advice(rlp_table.access_list_idx, Rotation::cur()),
                    );
                },
            );

            cb.condition(
                meta.query_advice(is_new_access_list_storage_key, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "sk_idx - sk_idx::prev = 1",
                        meta.query_advice(rlp_table.storage_key_idx, Rotation::prev()) + 1.expr(),
                        meta.query_advice(rlp_table.storage_key_idx, Rotation::cur()),
                    );
                },
            );

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        // Access List Clearing
        // note: right now no other nested structures are defined at these depth levels
        // hence using depth alone is sufficient to determine clearing conditions.
        // however, this might change in the future if more nested structures are introduced at same
        // depth level
        meta.create_gate(
            "access list: clearing access_list_idx and storage_key_idx",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                cb.condition(
                    meta.query_advice(is_access_list_end, Rotation::cur()),
                    |cb| {
                        cb.require_zero(
                            "al_idx = 0",
                            meta.query_advice(rlp_table.access_list_idx, Rotation::cur()),
                        );
                    },
                );

                cb.condition(
                    meta.query_advice(is_storage_key_list_end, Rotation::cur()),
                    |cb| {
                        cb.require_zero(
                            "sk_idx = 0",
                            meta.query_advice(rlp_table.storage_key_idx, Rotation::cur()),
                        );
                    },
                );

                cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
            },
        );

        // Access List Consistency
        // When no conditions for access list address or storage key changes are present, these idxs
        // stay the same
        meta.create_gate(
            "access list: access_list_idx and storage_key_idx don't change when no conditions present",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                cb.condition(
                    and::expr([
                        not::expr(meta.query_advice(is_new_access_list_address, Rotation::cur())),
                        not::expr(meta.query_advice(is_access_list_end, Rotation::cur())),
                    ]),
                    |cb| {
                    cb.require_equal(
                        "al_idx stays the same",
                        meta.query_advice(rlp_table.access_list_idx, Rotation::prev()),
                        meta.query_advice(rlp_table.access_list_idx, Rotation::cur()),
                    );
                });

                cb.condition(
                    and::expr([
                        not::expr(meta.query_advice(is_new_access_list_storage_key, Rotation::cur())),
                        not::expr(meta.query_advice(is_storage_key_list_end, Rotation::cur())),
                    ]),
                    |cb| {
                    cb.require_equal(
                        "storage_key_idx stays the same",
                        meta.query_advice(rlp_table.storage_key_idx, Rotation::prev()),
                        meta.query_advice(rlp_table.storage_key_idx, Rotation::cur()),
                    );
                });

                cb.gate(and::expr([
                    meta.query_fixed(q_enabled, Rotation::cur()),
                    not::expr(meta.query_fixed(q_first, Rotation::cur())),
                ]))
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////
        /////////////////// Rlp Decoding Table Transitions ////////////////
        ///////////////////////// (Stack Constraints) /////////////////////
        ///////////////////////////////////////////////////////////////////
        let (
            is_stack_depth_zero,
            is_stack_depth_one,
            is_stack_depth_two,
            is_stack_depth_three,
            is_stack_depth_four,
            stack_op_id_diff,
            is_stack_depth_diff,
            is_stack_al_idx_diff,
            is_stack_sk_idx_diff,
        ) = (
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

        meta.create_gate(
            "Decoding table depth, operation and key change indicators",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // stack operation indicators
                cb.condition(not::expr(is_end(meta)), |cb| {
                    cb.require_equal(
                        "each row must have a stack operation",
                        sum::expr([
                            meta.query_advice(rlp_decoding_table.is_stack_init, Rotation::cur()),
                            meta.query_advice(rlp_decoding_table.is_stack_push, Rotation::cur()),
                            meta.query_advice(rlp_decoding_table.is_stack_pop, Rotation::cur()),
                            meta.query_advice(rlp_decoding_table.is_stack_update, Rotation::cur()),
                        ]),
                        1.expr(),
                    );
                });

                cb.require_boolean(
                    "is_stack_init is binary",
                    meta.query_advice(rlp_decoding_table.is_stack_init, Rotation::cur()),
                );
                cb.require_boolean(
                    "is_stack_push is binary",
                    meta.query_advice(rlp_decoding_table.is_stack_push, Rotation::cur()),
                );
                cb.require_boolean(
                    "is_stack_pop is binary",
                    meta.query_advice(rlp_decoding_table.is_stack_pop, Rotation::cur()),
                );
                cb.require_boolean(
                    "is_stack_update is binary",
                    meta.query_advice(rlp_decoding_table.is_stack_update, Rotation::cur()),
                );

                // depth indicators
                cb.condition(not::expr(is_end(meta)), |cb| {
                    cb.require_equal(
                        "each row must have a depth indicator",
                        sum::expr([
                            meta.query_advice(is_stack_depth_zero, Rotation::cur()),
                            meta.query_advice(is_stack_depth_one, Rotation::cur()),
                            meta.query_advice(is_stack_depth_two, Rotation::cur()),
                            meta.query_advice(is_stack_depth_three, Rotation::cur()),
                            meta.query_advice(is_stack_depth_four, Rotation::cur()),
                        ]),
                        1.expr(),
                    );
                });

                for (idx, col) in [
                    is_stack_depth_zero,
                    is_stack_depth_one,
                    is_stack_depth_two,
                    is_stack_depth_three,
                    is_stack_depth_four,
                ]
                .into_iter()
                .enumerate()
                {
                    cb.require_boolean(
                        "stack depth indicator is binary",
                        meta.query_advice(col, Rotation::cur()),
                    );

                    cb.condition(meta.query_advice(col, Rotation::cur()), |cb| {
                        cb.require_zero(
                            "stack depth indicator has correct depth",
                            meta.query_advice(rlp_decoding_table.depth, Rotation::cur())
                                - idx.expr(),
                        );
                    });
                }

                // key change indicators
                cb.require_boolean(
                    "is_stack_depth_diff is binary",
                    meta.query_advice(is_stack_depth_diff, Rotation::cur()),
                );
                cb.require_boolean(
                    "is_stack_al_idx_diff is binary",
                    meta.query_advice(is_stack_al_idx_diff, Rotation::cur()),
                );
                cb.require_boolean(
                    "is_stack_sk_idx_diff is binary",
                    meta.query_advice(is_stack_sk_idx_diff, Rotation::cur()),
                );

                cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
            },
        );

        meta.create_gate("Conditions for when key = (tx_id, format, depth, al_idx, sk_idx) stays the same", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(
                not::expr(meta.query_advice(rlp_decoding_table.is_stack_init, Rotation::cur())),
                |cb| {
                    cb.require_equal(
                        "Unless stack is init, no change on tx_id",
                        meta.query_advice(rlp_decoding_table.tx_id, Rotation::prev()),
                        meta.query_advice(rlp_decoding_table.tx_id, Rotation::cur()),
                    );
                    cb.require_equal(
                        "Unless stack is init, no change on format",
                        meta.query_advice(rlp_decoding_table.tx_id, Rotation::prev()),
                        meta.query_advice(rlp_decoding_table.tx_id, Rotation::cur()),
                    );
                }
            );
            cb.condition(
                not::expr(meta.query_advice(stack_op_id_diff, Rotation::cur())),
                |cb| {
                    cb.require_equal(
                        "Key stays the same when no stack op id diff",
                        meta.query_advice(rlp_decoding_table.id, Rotation::prev()),
                        meta.query_advice(rlp_decoding_table.id, Rotation::cur()),
                    );
                }
            );
            cb.condition(
                not::expr(meta.query_advice(stack_op_id_diff, Rotation::cur())),
                |cb| {
                    cb.require_zero(
                        "When key stays the same, stack is not init (when tx_id and format change) and no change for depth, al_idx and sk_idx",
                        sum::expr([
                            meta.query_advice(rlp_decoding_table.is_stack_init, Rotation::cur()),
                            meta.query_advice(is_stack_depth_diff, Rotation::cur()),
                            meta.query_advice(is_stack_al_idx_diff, Rotation::cur()),
                            meta.query_advice(is_stack_sk_idx_diff, Rotation::cur()),
                        ])
                    );
                }
            );
            cb.condition(
                not::expr(meta.query_advice(is_stack_depth_diff, Rotation::cur())),
                |cb| {
                    cb.require_equal(
                        "Stack depth doesn't change",
                        meta.query_advice(rlp_decoding_table.depth, Rotation::prev()),
                        meta.query_advice(rlp_decoding_table.depth, Rotation::cur()),
                    );
                }
            );
            cb.condition(
                and::expr([
                    meta.query_advice(is_stack_depth_diff, Rotation::cur()),
                    not::expr(meta.query_advice(rlp_decoding_table.is_stack_init, Rotation::cur())),
                ]),
                |cb| {
                    cb.require_boolean(
                        "When stack is not INIT, depth can only stay the same or increment by 1",
                        meta.query_advice(rlp_decoding_table.depth, Rotation::cur()) - meta.query_advice(rlp_decoding_table.depth, Rotation::prev()),
                    );
                }
            );
            cb.condition(
                not::expr(meta.query_advice(is_stack_al_idx_diff, Rotation::cur())),
                |cb| {
                    cb.require_equal(
                        "Stack al_idx doesn't change",
                        meta.query_advice(rlp_decoding_table.al_idx, Rotation::prev()),
                        meta.query_advice(rlp_decoding_table.al_idx, Rotation::cur()),
                    );
                }
            );
            cb.condition(
                not::expr(meta.query_advice(is_stack_sk_idx_diff, Rotation::cur())),
                |cb| {
                    cb.require_equal(
                        "Stack sk_idx doesn't change",
                        meta.query_advice(rlp_decoding_table.sk_idx, Rotation::prev()),
                        meta.query_advice(rlp_decoding_table.sk_idx, Rotation::cur()),
                    );
                }
            );

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        // Operation-specific constraints
        // Specifies how different stack op change the stack op key
        meta.create_gate("Decoding table stack op UPDATE", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Constraints true for any UPDATE operation
            cb.require_equal(
                "UPDATE stack operation reads 1 byte",
                meta.query_advice(rlp_decoding_table.value, Rotation::cur()) + 1.expr(),
                meta.query_advice(rlp_decoding_table.value_prev, Rotation::cur()),
            );
            cb.require_equal(
                "UPDATE stack operation doesn't skip bytes",
                meta.query_advice(rlp_decoding_table.value, Rotation::prev()),
                meta.query_advice(rlp_decoding_table.value_prev, Rotation::cur()),
            );

            // When key changes with an UPDATE, it's a new storage key on depth 4"
            cb.condition(meta.query_advice(stack_op_id_diff, Rotation::cur()), |cb| {
                cb.require_equal(
                    "Key change with UPDATE is on depth 4 (for a new storage key)",
                    meta.query_advice(is_stack_depth_four, Rotation::cur()),
                    1.expr(),
                );
                cb.require_zero(
                    "Depth and al_idx don't change",
                    sum::expr([
                        meta.query_advice(is_stack_depth_diff, Rotation::cur()),
                        meta.query_advice(is_stack_al_idx_diff, Rotation::cur()),
                    ]),
                );
                cb.require_equal(
                    "sk_idx increments by 1",
                    meta.query_advice(rlp_decoding_table.sk_idx, Rotation::prev()) + 1.expr(),
                    meta.query_advice(rlp_decoding_table.sk_idx, Rotation::cur()),
                );
            });

            // For any other depth, the key must stay the same
            cb.condition(
                sum::expr([
                    meta.query_advice(is_stack_depth_zero, Rotation::cur()),
                    meta.query_advice(is_stack_depth_one, Rotation::cur()),
                    meta.query_advice(is_stack_depth_two, Rotation::cur()),
                    meta.query_advice(is_stack_depth_three, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_zero(
                        "For UPDATE on any other depth, key must stay the same",
                        meta.query_advice(stack_op_id_diff, Rotation::cur()),
                    );
                },
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                meta.query_advice(rlp_decoding_table.is_stack_update, Rotation::cur()),
            ]))
        });

        meta.create_gate("Decoding table stack op POP", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Constraints true for any POP operation
            cb.require_equal(
                "POP stack operation doesn't skip bytes",
                meta.query_advice(rlp_decoding_table.value, Rotation::prev()),
                meta.query_advice(rlp_decoding_table.value_prev, Rotation::cur()),
            );

            // When key changes with a POP, it's the end of decoding an access list item on depth 2"
            cb.condition(meta.query_advice(stack_op_id_diff, Rotation::cur()), |cb| {
                cb.require_equal(
                    "Key change with POP is on depth 2 (the end of decoding an access list item)",
                    meta.query_advice(is_stack_depth_two, Rotation::cur()),
                    1.expr(),
                );
                cb.require_zero(
                    "Depth and sk_idx don't change",
                    sum::expr([
                        meta.query_advice(is_stack_depth_diff, Rotation::cur()),
                        meta.query_advice(is_stack_sk_idx_diff, Rotation::cur()),
                    ]),
                );
                cb.require_equal(
                    "al_idx increments by 1",
                    meta.query_advice(rlp_decoding_table.al_idx, Rotation::prev()) + 1.expr(),
                    meta.query_advice(rlp_decoding_table.al_idx, Rotation::cur()),
                );
            });

            // For any other depth, the key must stay the same
            cb.condition(
                sum::expr([
                    meta.query_advice(is_stack_depth_zero, Rotation::cur()),
                    meta.query_advice(is_stack_depth_one, Rotation::cur()),
                    meta.query_advice(is_stack_depth_three, Rotation::cur()),
                    meta.query_advice(is_stack_depth_four, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_zero(
                        "For POP on any other depth, key must stay the same",
                        meta.query_advice(stack_op_id_diff, Rotation::cur()),
                    );
                },
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                meta.query_advice(rlp_decoding_table.is_stack_pop, Rotation::cur()),
            ]))
        });

        meta.create_gate("Decoding table stack op PUSH", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Constraints true for any PUSH operation
            cb.require_zero(
                "Before a new PUSH, all previous bytes must be processed.",
                meta.query_advice(rlp_decoding_table.value, Rotation::prev()),
            );
            cb.require_zero(
                "PUSH has value_prev at 0",
                meta.query_advice(rlp_decoding_table.value_prev, Rotation::cur()),
            );

            // When key changes with a PUSH, there're 4 scenarios:
            // depth=1: start decoding after TxType and Len on depth 0
            // depth=2: start decoding the access list
            // depth=3: a new access list item
            // depth=4: a new storage key list
            cb.condition(
                and::expr([
                    meta.query_advice(stack_op_id_diff, Rotation::cur()),
                    sum::expr([
                        meta.query_advice(is_stack_depth_one, Rotation::cur()),
                        meta.query_advice(is_stack_depth_two, Rotation::cur()),
                    ]),
                ]),
                |cb| {
                    cb.require_zero(
                        "al_idx and sk_idx don't change",
                        sum::expr([
                            meta.query_advice(is_stack_al_idx_diff, Rotation::cur()),
                            meta.query_advice(is_stack_sk_idx_diff, Rotation::cur()),
                        ]),
                    );
                    cb.require_equal(
                        "depth increments by 1",
                        meta.query_advice(is_stack_depth_diff, Rotation::cur()),
                        1.expr(),
                    );
                },
            );

            cb.condition(
                and::expr([
                    meta.query_advice(stack_op_id_diff, Rotation::cur()),
                    meta.query_advice(is_stack_depth_three, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_zero(
                        "If depth increments by 1, the al_idx is 1",
                        meta.query_advice(is_stack_depth_diff, Rotation::cur())
                            * (meta.query_advice(rlp_decoding_table.al_idx, Rotation::cur())
                                - 1.expr()),
                    );
                    cb.require_zero(
                        "If depth stays the same, the al_idx increments by 1",
                        (1.expr() - meta.query_advice(is_stack_depth_diff, Rotation::cur()))
                            * (meta.query_advice(rlp_decoding_table.al_idx, Rotation::cur())
                                - meta.query_advice(rlp_decoding_table.al_idx, Rotation::prev())
                                - 1.expr()),
                    );
                    cb.require_zero(
                        "sk_idx doesn't change",
                        meta.query_advice(is_stack_sk_idx_diff, Rotation::cur()),
                    );
                },
            );

            cb.condition(
                and::expr([
                    meta.query_advice(stack_op_id_diff, Rotation::cur()),
                    meta.query_advice(is_stack_depth_four, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_zero(
                        "If depth increments by 1, the al_idx is 1",
                        meta.query_advice(is_stack_depth_diff, Rotation::cur())
                            * (meta.query_advice(rlp_decoding_table.al_idx, Rotation::cur())
                                - 1.expr()),
                    );
                    cb.require_zero(
                        "If depth stays the same, the al_idx increments by 1",
                        (1.expr() - meta.query_advice(is_stack_depth_diff, Rotation::cur()))
                            * (meta.query_advice(rlp_decoding_table.al_idx, Rotation::cur())
                                - meta.query_advice(rlp_decoding_table.al_idx, Rotation::prev())
                                - 1.expr()),
                    );
                    cb.require_equal(
                        "For a new storage key list, sk_idx always starts at 1",
                        meta.query_advice(rlp_decoding_table.sk_idx, Rotation::cur()),
                        1.expr(),
                    );
                },
            );

            cb.condition(meta.query_advice(stack_op_id_diff, Rotation::cur()), |cb| {
                cb.require_zero(
                    "depth 0 has no PUSH. Depth 0 has INIT.",
                    meta.query_advice(is_stack_depth_zero, Rotation::cur()),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                meta.query_advice(rlp_decoding_table.is_stack_push, Rotation::cur()),
            ]))
        });

        meta.create_gate("Decoding table stack op INIT", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "stack init pushes all remaining_bytes onto depth 0",
                meta.query_advice(rlp_decoding_table.value, Rotation::cur()),
                meta.query_advice(byte_rev_idx, Rotation::cur()),
            );
            cb.require_equal(
                "stack can only init once with the first byte",
                meta.query_advice(byte_idx, Rotation::cur()),
                1.expr(),
            );
            cb.require_zero(
                "stack inits at depth 0",
                meta.query_advice(rlp_decoding_table.depth, Rotation::cur()),
            );
            cb.require_zero(
                "stack inits with al_idx at 0",
                meta.query_advice(rlp_decoding_table.al_idx, Rotation::cur()),
            );
            cb.require_zero(
                "stack inits with sk_idx at 0",
                meta.query_advice(rlp_decoding_table.sk_idx, Rotation::cur()),
            );
            cb.condition(
                not::expr(meta.query_fixed(q_first, Rotation::cur())),
                |cb| {
                    cb.require_boolean(
                        "tx_id can only stay the same or increment by 1",
                        meta.query_advice(rlp_decoding_table.tx_id, Rotation::cur())
                            - meta.query_advice(rlp_decoding_table.tx_id, Rotation::prev()),
                    );
                },
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                meta.query_advice(rlp_decoding_table.is_stack_init, Rotation::cur()),
            ]))
        });

        // Cross-depth stack constraints in the RlpDecodingTable
        // These two sets of lookups ensure exact correspondence of PUSH and POP records
        meta.lookup_any(
            "Each stack PUSH must correspond exactly to a POP into a lower depth level",
            |meta| {
                let enable = and::expr([
                    meta.query_fixed(q_enabled, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.is_stack_push, Rotation::cur()),
                ]);

                let input_exprs = vec![
                    meta.query_advice(rlp_decoding_table.tx_id, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.format, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.depth, Rotation::cur()) - 1.expr(),
                    1.expr(), // is_pop = true
                    meta.query_advice(rlp_decoding_table.value, Rotation::cur()) + 1.expr(),
                ];
                let table_exprs = vec![
                    meta.query_advice(rlp_decoding_table.tx_id, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.format, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.depth, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.is_stack_pop, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.value_prev, Rotation::cur())
                        - meta.query_advice(rlp_decoding_table.value, Rotation::cur()),
                ];
                input_exprs
                    .into_iter()
                    .zip(table_exprs)
                    .map(|(input, table)| (input * enable.expr(), table))
                    .collect()
            },
        );
        meta.lookup_any(
            "Each stack POP must correspond exactly to a PUSH onto a higher depth",
            |meta| {
                let enable = and::expr([
                    meta.query_fixed(q_enabled, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.is_stack_pop, Rotation::cur()),
                ]);

                let input_exprs = vec![
                    meta.query_advice(rlp_decoding_table.tx_id, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.format, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.depth, Rotation::cur()) + 1.expr(),
                    1.expr(), // is_push = true
                    meta.query_advice(rlp_decoding_table.value_prev, Rotation::cur())
                        - meta.query_advice(rlp_decoding_table.value, Rotation::cur())
                        - 1.expr(),
                ];
                let table_exprs = vec![
                    meta.query_advice(rlp_decoding_table.tx_id, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.format, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.depth, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.is_stack_push, Rotation::cur()),
                    meta.query_advice(rlp_decoding_table.value, Rotation::cur()),
                ];
                input_exprs
                    .into_iter()
                    .zip(table_exprs)
                    .map(|(input, table)| (input * enable.expr(), table))
                    .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);

        Self {
            q_first,
            q_last,
            state,
            state_bits,
            rlp_table,
            rlp_decoding_table,
            tag,
            tag_bits,
            tag_next,
            byte_idx,
            byte_rev_idx,
            byte_value,
            bytes_rlc,
            gas_cost_acc,
            tag_idx,
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
            is_same_rlp_instance,

            // access list checks
            is_new_access_list_address,
            is_new_access_list_storage_key,
            is_access_list_end,
            is_storage_key_list_end,

            // decoding table
            stack_op_id_diff,
            is_stack_depth_zero,
            is_stack_depth_one,
            is_stack_depth_two,
            is_stack_depth_three,
            is_stack_depth_four,
            is_stack_depth_diff,
            is_stack_al_idx_diff,
            is_stack_sk_idx_diff,

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
            mlength_lte_0x20,
            tlength_lte_mlength,
            depth_check,
            depth_eq_one,
            depth_eq_two,
            depth_eq_four,
            byte_value_is_zero,

            // internal tables
            data_table,
            rom_table,
            u8_table,
        }
    }

    fn assign_sm_row(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        witness: &RlpFsmWitnessRow<F>,
        witness_next: Option<&RlpFsmWitnessRow<F>>,
        witness_prev: Option<&RlpFsmWitnessRow<F>>,
    ) -> Result<(), Error> {
        // assign to selector
        region.assign_fixed(
            || "q_enable",
            self.rlp_table.q_enable,
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
            || "rlp_table.tag_bytes_rlc",
            self.rlp_table.tag_bytes_rlc,
            row,
            || witness.rlp_table.tag_bytes_rlc,
        )?;
        region.assign_advice(
            || "rlp_table.tag_length",
            self.rlp_table.tag_length,
            row,
            || Value::known(F::from(witness.rlp_table.tag_length as u64)),
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
        region.assign_advice(
            || "rlp_table.access_list_idx",
            self.rlp_table.access_list_idx,
            row,
            || Value::known(F::from(witness.rlp_table.access_list_idx)),
        )?;
        region.assign_advice(
            || "rlp_table.storage_key_idx",
            self.rlp_table.storage_key_idx,
            row,
            || Value::known(F::from(witness.rlp_table.storage_key_idx)),
        )?;

        // RlpDecodingTable assignments
        let stack_op_id_diff = if let Some(witness_prev) = witness_prev {
            (witness_prev.rlp_decoding_table.tx_id != witness.rlp_decoding_table.tx_id)
                || (witness_prev.rlp_decoding_table.format != witness.rlp_decoding_table.format)
                || (witness_prev.rlp_decoding_table.depth != witness.rlp_decoding_table.depth)
                || (witness_prev.rlp_decoding_table.al_idx != witness.rlp_decoding_table.al_idx)
                || (witness_prev.rlp_decoding_table.sk_idx != witness.rlp_decoding_table.sk_idx)
        } else {
            true
        };
        region.assign_advice(
            || "stack_op_id_diff",
            self.stack_op_id_diff,
            row,
            || Value::known(F::from(stack_op_id_diff as u64)),
        )?;

        region.assign_advice(
            || "rlp_decoding_table.id",
            self.rlp_decoding_table.id,
            row,
            || witness.rlp_decoding_table.id,
        )?;
        region.assign_advice(
            || "rlp_decoding_table.tx_id",
            self.rlp_decoding_table.tx_id,
            row,
            || Value::known(F::from(witness.rlp_table.tx_id)),
        )?;
        region.assign_advice(
            || "rlp_decoding_table.format",
            self.rlp_decoding_table.format,
            row,
            || Value::known(F::from(usize::from(witness.rlp_table.format) as u64)),
        )?;
        region.assign_advice(
            || "rlp_decoding_table.depth",
            self.rlp_decoding_table.depth,
            row,
            || Value::known(F::from(witness.rlp_decoding_table.depth as u64)),
        )?;
        region.assign_advice(
            || "rlp_decoding_table.value",
            self.rlp_decoding_table.value,
            row,
            || Value::known(F::from(witness.rlp_decoding_table.value as u64)),
        )?;
        region.assign_advice(
            || "rlp_decoding_table.value_prev",
            self.rlp_decoding_table.value_prev,
            row,
            || Value::known(F::from(witness.rlp_decoding_table.value_prev as u64)),
        )?;
        region.assign_advice(
            || "rlp_decoding_table.is_stack_init",
            self.rlp_decoding_table.is_stack_init,
            row,
            || {
                Value::known(F::from(
                    matches!(witness.rlp_decoding_table.stack_op, StackOp::Init) as u64,
                ))
            },
        )?;
        region.assign_advice(
            || "rlp_decoding_table.is_stack_push",
            self.rlp_decoding_table.is_stack_push,
            row,
            || {
                Value::known(F::from(
                    matches!(witness.rlp_decoding_table.stack_op, StackOp::Push) as u64,
                ))
            },
        )?;
        region.assign_advice(
            || "rlp_decoding_table.is_stack_pop",
            self.rlp_decoding_table.is_stack_pop,
            row,
            || {
                Value::known(F::from(
                    matches!(witness.rlp_decoding_table.stack_op, StackOp::Pop) as u64,
                ))
            },
        )?;
        region.assign_advice(
            || "rlp_decoding_table.is_stack_update",
            self.rlp_decoding_table.is_stack_update,
            row,
            || {
                Value::known(F::from(
                    matches!(witness.rlp_decoding_table.stack_op, StackOp::Update) as u64,
                ))
            },
        )?;
        region.assign_advice(
            || "rlp_decoding_table.al_idx",
            self.rlp_decoding_table.al_idx,
            row,
            || Value::known(F::from(witness.rlp_decoding_table.al_idx)),
        )?;
        region.assign_advice(
            || "rlp_decoding_table.sk_idx",
            self.rlp_decoding_table.sk_idx,
            row,
            || Value::known(F::from(witness.rlp_decoding_table.sk_idx)),
        )?;
        region.assign_advice(
            || "rlp_decoding_table.byte_idx",
            self.rlp_decoding_table.byte_idx,
            row,
            || Value::known(F::from(witness.rlp_decoding_table.byte_idx as u64)),
        )?;

        let is_new_access_list_address = witness.state_machine.state == DecodeTagStart
            && witness.state_machine.tag == AccessListAddress;
        region.assign_advice(
            || "is_new_access_list_address",
            self.is_new_access_list_address,
            row,
            || Value::known(F::from(is_new_access_list_address as u64)),
        )?;
        let is_new_access_list_storage_key = witness.state_machine.state == DecodeTagStart
            && witness.state_machine.tag == AccessListStorageKey;
        region.assign_advice(
            || "is_new_access_list_storage_key",
            self.is_new_access_list_storage_key,
            row,
            || Value::known(F::from(is_new_access_list_storage_key as u64)),
        )?;
        let is_access_list_end =
            witness.state_machine.tag == EndVector && witness.state_machine.depth == 2;
        region.assign_advice(
            || "is_access_list_end",
            self.is_access_list_end,
            row,
            || Value::known(F::from(is_access_list_end as u64)),
        )?;
        let is_storage_key_list_end =
            witness.state_machine.tag == EndVector && witness.state_machine.depth == 4;
        region.assign_advice(
            || "is_storage_key_list_end",
            self.is_storage_key_list_end,
            row,
            || Value::known(F::from(is_storage_key_list_end as u64)),
        )?;
        for (idx, col) in [
            self.is_stack_depth_zero,
            self.is_stack_depth_one,
            self.is_stack_depth_two,
            self.is_stack_depth_three,
            self.is_stack_depth_four,
        ]
        .into_iter()
        .enumerate()
        {
            region.assign_advice(
                || format!("is_stack_depth_x (depth: {:?})", idx),
                col,
                row,
                || Value::known(F::from((witness.rlp_decoding_table.depth == idx) as u64)),
            )?;
        }
        let stack_depth_prev = if let Some(witness_prev) = witness_prev {
            witness_prev.rlp_decoding_table.depth
        } else {
            0usize
        };
        region.assign_advice(
            || "is_stack_depth_diff",
            self.is_stack_depth_diff,
            row,
            || {
                Value::known(F::from(
                    (matches!(witness.rlp_decoding_table.stack_op, StackOp::Init)
                        || (witness.rlp_decoding_table.depth != stack_depth_prev))
                        as u64,
                ))
            },
        )?;
        let al_idx_prev = if let Some(witness_prev) = witness_prev {
            witness_prev.rlp_decoding_table.al_idx
        } else {
            0u64
        };
        region.assign_advice(
            || "is_stack_al_idx_diff",
            self.is_stack_al_idx_diff,
            row,
            || {
                Value::known(F::from(
                    (matches!(witness.rlp_decoding_table.stack_op, StackOp::Init)
                        || (witness.rlp_decoding_table.al_idx != al_idx_prev))
                        as u64,
                ))
            },
        )?;
        let sk_idx_prev = if let Some(witness_prev) = witness_prev {
            witness_prev.rlp_decoding_table.sk_idx
        } else {
            0u64
        };
        region.assign_advice(
            || "is_stack_sk_idx_diff",
            self.is_stack_sk_idx_diff,
            row,
            || {
                Value::known(F::from(
                    (matches!(witness.rlp_decoding_table.stack_op, StackOp::Init)
                        || (witness.rlp_decoding_table.sk_idx != sk_idx_prev))
                        as u64,
                ))
            },
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
        region.assign_advice(
            || "gas_cost_acc",
            self.gas_cost_acc,
            row,
            || witness.state_machine.gas_cost_acc,
        )?;

        // assign to intermediates
        let byte_value = witness.state_machine.byte_value;
        let is_case3 = (0xc0..0xf8).contains(&byte_value) && !witness.state_machine.tag.is_end();
        let transit_to_new = witness.state_machine.tag.is_end()
            && (witness.state_machine.depth == 0)
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
            Value::known(F::from(witness.rlp_table.tx_id)),
            Value::known(F::from(tx_id_next)),
        )?;

        let format_check_chip = IsEqualChip::construct(self.format_check_in_sm.clone());
        format_check_chip.assign(
            region,
            row,
            Value::known(F::from(witness.rlp_table.format as u64)),
            Value::known(F::from(usize::from(format_next) as u64)),
        )?;

        let is_same_rlp_instance =
            (witness.rlp_table.tx_id == tx_id_next) && (witness.rlp_table.format == format_next);
        region.assign_advice(
            || "is_same_rlp_instance",
            self.is_same_rlp_instance,
            row,
            || Value::known(F::from(is_same_rlp_instance as u64)),
        )?;

        let tidx_le_tlength_chip = ComparatorChip::construct(self.tidx_lte_tlength.clone());
        tidx_le_tlength_chip.assign(
            region,
            row,
            F::from(witness.state_machine.tag_idx as u64),
            F::from(witness.rlp_table.tag_length as u64),
        )?;
        let tlength_lte_mlength_chip = ComparatorChip::construct(self.tlength_lte_mlength.clone());
        tlength_lte_mlength_chip.assign(
            region,
            row,
            F::from(witness.rlp_table.tag_length as u64),
            F::from(witness.state_machine.max_length as u64),
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
        let depth_eq_two_chip = IsEqualChip::construct(self.depth_eq_two.clone());
        depth_eq_two_chip.assign(
            region,
            row,
            Value::known(F::from(witness.state_machine.depth as u64)),
            Value::known(F::from(2u64)),
        )?;
        let depth_eq_four_chip = IsEqualChip::construct(self.depth_eq_four.clone());
        depth_eq_four_chip.assign(
            region,
            row,
            Value::known(F::from(witness.state_machine.depth as u64)),
            Value::known(F::from(4u64)),
        )?;

        let mlength_lte_0x20_chip = ComparatorChip::construct(self.mlength_lte_0x20.clone());
        mlength_lte_0x20_chip.assign(
            region,
            row,
            F::from(witness.state_machine.max_length as u64),
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
        let bv_chip = IsZeroChip::construct(self.byte_value_is_zero.clone());
        bv_chip.assign(region, row, Value::known(byte_value))?;

        Ok(())
    }

    fn assign_sm_end_row(&self, region: &mut Region<'_, F>, row: usize) -> Result<(), Error> {
        region.assign_fixed(
            || "q_enable",
            self.rlp_table.q_enable,
            row,
            || Value::known(F::one()),
        )?;
        region.assign_advice(
            || "sm.state",
            self.state,
            row,
            || Value::known(F::from(usize::from(End) as u64)),
        )?;
        region.assign_advice(
            || "sm.tag",
            self.tag,
            row,
            || Value::known(F::from(usize::from(EndObject) as u64)),
        )?;
        let state_chip = BinaryNumberChip::construct(self.state_bits);
        state_chip.assign(region, row, &End)?;
        let tag_chip = BinaryNumberChip::construct(self.tag_bits);
        tag_chip.assign(region, row, &EndObject)?;

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
                || format!("RLP data table row: row = {row}"),
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
        padding_chip.assign(region, row, Value::known(F::from(witness.tx_id)))?;
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
        last_row: usize,
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

        debug_assert!(sm_rows.len() <= last_row);

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
                    let sm_row_prev = if i == 0 { None } else { Some(&sm_rows[i - 1]) };
                    self.assign_sm_row(&mut region, i, sm_row, sm_row_next, sm_row_prev)?;
                }
                for i in sm_rows.len()..last_row {
                    self.assign_sm_end_row(&mut region, i)?;
                }
                region.assign_fixed(|| "q_first", self.q_first, 0, || Value::known(F::one()))?;
                region.assign_fixed(
                    || "q_last",
                    self.q_last,
                    last_row - 1,
                    || Value::known(F::one()),
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

/// Arguments to configure the RLP circuit.
pub struct RlpCircuitConfigArgs<F: Field> {
    /// RLP table.
    pub rlp_table: RlpFsmRlpTable,
    /// u8 table
    pub u8_table: U8Table,
    /// Challenge API.
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for RlpCircuitConfig<F> {
    type ConfigArgs = RlpCircuitConfigArgs<F>;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let data_table = RlpFsmDataTable::construct(meta);
        let rom_table = RlpFsmRomTable::construct(meta);
        let decoding_table = RlpDecodingTable::construct(meta);

        Self::configure(
            meta,
            rom_table,
            data_table,
            args.u8_table,
            args.rlp_table,
            decoding_table,
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
    /// Maximum number of rows supported.
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
        let size = block.circuits_params.max_rlp_rows;
        debug_assert!(block.txs.len() <= max_txs);

        let padding_txs = (block.txs.len()..max_txs)
            .map(|i| {
                let mut tx = Transaction::dummy(block.chain_id);
                tx.id = i + 1;
                tx
            })
            .collect::<Vec<Transaction>>();
        let txs = [block.txs.clone(), padding_txs].concat();

        Self {
            txs,
            max_txs,
            size,
            _marker: Default::default(),
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign(layouter, &self.txs, self.size, challenges)
    }

    fn min_num_rows_block(block: &Block<F>) -> (usize, usize) {
        let challenges: Challenges<Value<F>> =
            Challenges::mock(Value::unknown(), Value::unknown(), Value::unknown());
        let sm_rows: usize = block
            .txs
            .iter()
            .map(|tx| tx.gen_sm_witness(&challenges).len())
            .sum();
        let max_num_rows = block.circuits_params.max_rlp_rows;

        (sm_rows, max_num_rows)
    }
}
