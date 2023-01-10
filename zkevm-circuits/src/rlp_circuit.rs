//! Circuit implementation for RLP-encoding verification. Please refer: https://hackmd.io/@rohitnarurkar/S1zSz0KM9.

use std::marker::PhantomData;

use eth_types::Field;
use gadgets::binary_number::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction};
use gadgets::util::{select, sum};
use gadgets::{
    comparator::{ComparatorChip, ComparatorConfig, ComparatorInstruction},
    less_than::{LtChip, LtConfig, LtInstruction},
};

#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

// use crate::evm_circuit::table::FixedTableTag;
use crate::util::{Challenges, SubCircuit, SubCircuitConfig};
use crate::witness::Block;
use crate::witness::RlpTxTag::{
    ChainId, DataPrefix, Gas, GasPrice, Nonce, Prefix, SigR, SigS, SigV, To,
};
use crate::{
    evm_circuit::{
        util::{and, constraint_builder::BaseConstraintBuilder, not, or},
        witness::{RlpTxTag, RlpWitnessGen},
    },
    table::RlpTable,
    util::Expr,
    witness::{RlpDataType, SignedTransaction},
};

#[derive(Clone, Debug)]
struct RlpTagROM {
    // TODO: we can merge these three cols into one col using LC as
    //       as their type are (u8, u8, u8)
    tag: Column<Fixed>,
    tag_next: Column<Fixed>,
    max_length: Column<Fixed>,
}

#[derive(Clone, Debug)]
/// Config for the RLP circuit.
pub struct RlpCircuitConfig<F> {
    minimum_rows: usize,
    /// Denotes whether or not the row is enabled.
    q_usable: Column<Fixed>,
    /// Denotes whether the row is the first row in the layout.
    is_first: Column<Advice>,
    /// Denotes whether the row is the last byte in the RLP-encoded data.
    is_last: Column<Advice>,
    /// Embedded lookup table in RLP circuit.
    rlp_table: RlpTable,
    /// Denotes the index of this row, starting from `1` and ending at `n`
    /// where `n` is the byte length of the RLP-encoded data.
    index: Column<Advice>,
    /// Denotes the index of this row, but reversed. It starts from `n` where
    /// `n` is the byte length of the RLP-encoded data and ends at `1`.
    rindex: Column<Advice>,
    /// Placeholder row do not increase the index and mainly used for
    /// DataPrefix when |tx.data| = 1 and tx.data < 0x80.
    placeholder: Column<Advice>,
    /// Denotes the byte value at this row index from the RLP-encoded data.
    byte_value: Column<Advice>,
    /// Denotes the RLC accumulator value used for call data bytes.
    calldata_bytes_rlc_acc: Column<Advice>,
    /// Tag bits
    tag_bits: BinaryNumberConfig<RlpTxTag, 4>,
    /// Tag ROM
    tag_rom: RlpTagROM,
    /// Denotes the current tag's span in bytes.
    tag_length: Column<Advice>,
    /// Denotes an accumulator for the length of data, in the case where len >
    /// 55 and the length is represented in its big-endian form.
    length_acc: Column<Advice>,
    /// Denotes an accumulator for the byte value field over all rows (bytes).
    all_bytes_rlc_acc: Column<Advice>,
    /// Denotes if tag is simple
    /// (the one that tag_bits provides has degree 4, which is too large)
    is_simple_tag: Column<Advice>,
    /// Denotes if tag is Prefix
    is_prefix_tag: Column<Advice>,
    /// Denotes if tag is DataPrefix
    is_dp_tag: Column<Advice>,
    /// Comparison chip to check: 1 <= tag_index.
    tag_index_cmp_1: ComparatorConfig<F, 3>,
    /// Comparison chip to check: tag_index <= tag_length.
    tag_index_length_cmp: ComparatorConfig<F, 3>,
    /// Comparison chip to check: 1 <= tag_length.
    tag_length_cmp_1: ComparatorConfig<F, 3>,
    /// Lt chip to check: tag_index < 10.
    tag_index_lt_10: LtConfig<F, 3>,
    /// Lt chip to check: tag_index < 34.
    tag_index_lt_34: LtConfig<F, 3>,
    /// Lt chip to check: 127 < value.
    value_gt_127: LtConfig<F, 1>,
    /// Lt chip to check: 183 < value.
    value_gt_183: LtConfig<F, 1>,
    /// Lt chip to check: 191 < value.
    value_gt_191: LtConfig<F, 1>,
    /// Lt chip to check: 247 < value.
    value_gt_247: LtConfig<F, 1>,
    /// Lt chip to check: value < 129.
    value_lt_129: LtConfig<F, 1>,
    /// IsEq Chip to check: value == 128,
    value_eq_128: IsEqualConfig<F>,
    /// Lt chip to check: value < 184.
    value_lt_184: LtConfig<F, 1>,
    /// Lt chip to check: value < 192.
    value_lt_192: LtConfig<F, 1>,
    /// Lt chip to check: value < 248.
    value_lt_248: LtConfig<F, 1>,
    /// Comparison chip to check: 0 <= length_acc.
    length_acc_cmp_0: ComparatorConfig<F, 3>,
}

impl<F: Field> RlpCircuitConfig<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        rlp_table: &RlpTable,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let q_usable = meta.fixed_column();
        let is_first = meta.advice_column();
        let is_last = meta.advice_column();
        let index = meta.advice_column();
        let rindex = meta.advice_column();
        let placeholder = meta.advice_column();
        let byte_value = meta.advice_column();
        let calldata_bytes_rlc_acc = meta.advice_column_in(SecondPhase);
        let tag_length = meta.advice_column();
        let length_acc = meta.advice_column();
        let all_bytes_rlc_acc = meta.advice_column_in(SecondPhase);
        let evm_word_rand = challenges.evm_word();
        let keccak_input_rand = challenges.keccak_input();
        // these three columns are used to replace the degree-4 expressions with
        // degree-1 expressions
        let is_simple_tag = meta.advice_column();
        let is_prefix_tag = meta.advice_column();
        let is_dp_tag = meta.advice_column();
        let tag_bits = BinaryNumberChip::configure(meta, q_usable, Some(rlp_table.tag));
        let tag_rom = RlpTagROM {
            tag: meta.fixed_column(),
            tag_next: meta.fixed_column(),
            max_length: meta.fixed_column(),
        };

        // Helper macro to declare booleans to check the current row tag.
        macro_rules! is_tx_tag {
            ($var:ident, $tag_variant:ident) => {
                let $var = |meta: &mut VirtualCells<F>| {
                    tag_bits.value_equals(RlpTxTag::$tag_variant, Rotation::cur())(meta)
                };
            };
        }
        is_tx_tag!(is_prefix, Prefix);
        is_tx_tag!(is_nonce, Nonce);
        is_tx_tag!(is_gas_price, GasPrice);
        is_tx_tag!(is_gas, Gas);
        is_tx_tag!(is_to, To);
        is_tx_tag!(is_value, Value);
        is_tx_tag!(is_data_prefix, DataPrefix);
        is_tx_tag!(is_data, Data);
        is_tx_tag!(is_chainid, ChainId);
        is_tx_tag!(is_sig_v, SigV);
        is_tx_tag!(is_sig_r, SigR);
        is_tx_tag!(is_sig_s, SigS);
        is_tx_tag!(is_padding, Padding);

        // Enable the comparator and lt chips if the current row is enabled.
        let cmp_lt_enabled = |meta: &mut VirtualCells<F>| {
            let q_usable = meta.query_fixed(q_usable, Rotation::cur());
            let is_padding = is_padding(meta);

            q_usable * not::expr(is_padding)
        };

        let tag_index_cmp_1 = ComparatorChip::configure(
            meta,
            cmp_lt_enabled,
            |_meta| 1.expr(),
            |meta| meta.query_advice(rlp_table.tag_rindex, Rotation::cur()),
        );
        let tag_index_length_cmp = ComparatorChip::configure(
            meta,
            cmp_lt_enabled,
            |meta| meta.query_advice(rlp_table.tag_rindex, Rotation::cur()),
            |meta| meta.query_advice(tag_length, Rotation::cur()),
        );
        let tag_length_cmp_1 = ComparatorChip::configure(
            meta,
            cmp_lt_enabled,
            |_meta| 1.expr(),
            |meta| meta.query_advice(tag_length, Rotation::cur()),
        );
        let tag_index_lt_10 = LtChip::configure(
            meta,
            cmp_lt_enabled,
            |meta| meta.query_advice(rlp_table.tag_rindex, Rotation::cur()),
            |_meta| 10.expr(),
        );
        let tag_index_lt_34 = LtChip::configure(
            meta,
            cmp_lt_enabled,
            |meta| meta.query_advice(rlp_table.tag_rindex, Rotation::cur()),
            |_meta| 34.expr(),
        );
        let value_gt_127 = LtChip::configure(
            meta,
            cmp_lt_enabled,
            |_meta| 127.expr(),
            |meta| meta.query_advice(byte_value, Rotation::cur()),
        );
        let value_gt_183 = LtChip::configure(
            meta,
            cmp_lt_enabled,
            |_meta| 183.expr(),
            |meta| meta.query_advice(byte_value, Rotation::cur()),
        );
        let value_gt_191 = LtChip::configure(
            meta,
            cmp_lt_enabled,
            |_meta| 191.expr(),
            |meta| meta.query_advice(byte_value, Rotation::cur()),
        );
        let value_gt_247 = LtChip::configure(
            meta,
            cmp_lt_enabled,
            |_meta| 247.expr(),
            |meta| meta.query_advice(byte_value, Rotation::cur()),
        );
        let value_lt_129 = LtChip::configure(
            meta,
            cmp_lt_enabled,
            |meta| meta.query_advice(byte_value, Rotation::cur()),
            |_meta| 129.expr(),
        );
        let value_eq_128 = IsEqualChip::configure(
            meta,
            cmp_lt_enabled,
            |meta| meta.query_advice(byte_value, Rotation::cur()),
            |_| 128.expr(),
        );
        let value_lt_184 = LtChip::configure(
            meta,
            cmp_lt_enabled,
            |meta| meta.query_advice(byte_value, Rotation::cur()),
            |_meta| 184.expr(),
        );
        let value_lt_192 = LtChip::configure(
            meta,
            cmp_lt_enabled,
            |meta| meta.query_advice(byte_value, Rotation::cur()),
            |_meta| 192.expr(),
        );
        let value_lt_248 = LtChip::configure(
            meta,
            cmp_lt_enabled,
            |meta| meta.query_advice(byte_value, Rotation::cur()),
            |_meta| 248.expr(),
        );
        let length_acc_cmp_0 = ComparatorChip::configure(
            meta,
            cmp_lt_enabled,
            |_meta| 0.expr(),
            |meta| meta.query_advice(length_acc, Rotation::cur()),
        );

        meta.create_gate("is_simple_tag", |meta| {
            let is_simple_tag = meta.query_advice(is_simple_tag, Rotation::cur());
            let is_prefix_tag = meta.query_advice(is_prefix_tag, Rotation::cur());
            let is_data_prefix_tag = meta.query_advice(is_dp_tag, Rotation::cur());
            let q_usable = meta.query_fixed(q_usable, Rotation::cur());
            let tags = sum::expr([
                is_nonce(meta),
                is_gas_price(meta),
                is_gas(meta),
                is_to(meta),
                is_value(meta),
                is_sig_v(meta),
                is_sig_r(meta),
                is_sig_s(meta),
                is_chainid(meta),
            ]);
            vec![
                q_usable.expr() * (is_simple_tag - tags),
                q_usable.expr() * (is_prefix_tag - is_prefix(meta)),
                q_usable.expr() * (is_data_prefix_tag - is_data_prefix(meta)),
            ]
        });

        // TODO: add lookup for byte_value in the fixed byte table.

        meta.lookup_any("(tag, tag_next) in tag_ROM", |meta| {
            let is_simple_tag = meta.query_advice(is_simple_tag, Rotation::cur());
            let tag = meta.query_advice(rlp_table.tag, Rotation::cur());
            let tag_next = meta.query_advice(rlp_table.tag, Rotation::next());
            let rom_tag = meta.query_fixed(tag_rom.tag, Rotation::cur());
            let rom_tag_next = meta.query_fixed(tag_rom.tag_next, Rotation::cur());
            let q_usable = meta.query_fixed(q_usable, Rotation::cur());
            let (_, tag_idx_eq_one) = tag_index_cmp_1.expr(meta, None);
            let condition = q_usable * is_simple_tag * tag_idx_eq_one;

            vec![
                (condition.expr() * tag, rom_tag),
                (condition * tag_next, rom_tag_next),
            ]
        });

        meta.create_gate("Common constraints", |meta| {
            let mut cb = BaseConstraintBuilder::new(9);

            let (tindex_lt, tindex_eq) = tag_index_cmp_1.expr(meta, None);
            assert_eq!(tindex_lt.degree(), 1, "{}", tindex_lt.degree());
            assert_eq!(tindex_eq.degree(), 2, "{}", tindex_lt.degree());
            let (tlength_lt, tlength_eq) = tag_length_cmp_1.expr(meta, None);
            let (tindex_lt_tlength, tindex_eq_tlength) = tag_index_length_cmp.expr(meta, None);
            let (length_acc_gt_0, length_acc_eq_0) = length_acc_cmp_0.expr(meta, None);
            let is_simple_tag = meta.query_advice(is_simple_tag, Rotation::cur());
            let is_prefix_tag = meta.query_advice(is_prefix_tag, Rotation::cur());
            let is_dp_tag = meta.query_advice(is_dp_tag, Rotation::cur());
            let is_tag_word = sum::expr([
                is_gas_price(meta),
                is_value(meta),
                is_sig_r(meta),
                is_sig_s(meta),
            ]);

            //////////////////////////////////////////////////////////////////////////////////////
            ////////////////////////////////// RlpTxTag::Prefix //////////////////////////////////
            //////////////////////////////////////////////////////////////////////////////////////
            cb.condition(is_prefix_tag.expr(), |cb| {
                // tag_index < 10
                cb.require_equal(
                    "tag_index < 10",
                    tag_index_lt_10.is_lt(meta, None),
                    1.expr(),
                );

                // tag_index >= 1
                cb.require_zero(
                    "tag_index >= 1",
                    not::expr(or::expr([tindex_lt.clone(), tindex_eq.clone()])),
                );
            });

            // if tag_index > 1
            cb.condition(is_prefix_tag.expr() * tindex_lt.clone(), |cb| {
                cb.require_equal(
                    "tag::next == RlpTxTag::Prefix",
                    meta.query_advice(rlp_table.tag, Rotation::next()),
                    RlpTxTag::Prefix.expr(),
                );
                cb.require_equal(
                    "tag_index::next == tag_index - 1",
                    meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                    meta.query_advice(rlp_table.tag_rindex, Rotation::cur()) - 1.expr(),
                );
                cb.require_equal(
                    "tag_length::next == tag_length",
                    meta.query_advice(tag_length, Rotation::next()),
                    meta.query_advice(tag_length, Rotation::cur()),
                );
            });

            // if tag_index == 1
            cb.condition(is_prefix_tag.expr() * tindex_eq.clone(), |cb| {
                cb.require_equal(
                    "tag::next == RlpTxTag::Nonce",
                    meta.query_advice(rlp_table.tag, Rotation::next()),
                    RlpTxTag::Nonce.expr(),
                );
                cb.require_equal(
                    "tag_index::next == tag_length::next",
                    meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                    meta.query_advice(tag_length, Rotation::next()),
                );
                // we add +1 to account for the 2 additional rows for RlpLength and Rlp.
                cb.require_equal(
                    "rindex::next == length_acc + 1",
                    meta.query_advice(rindex, Rotation::next()),
                    meta.query_advice(length_acc, Rotation::cur()) + 1.expr(),
                );
            });

            // if tag_index == tag_length && tag_length > 1
            cb.condition(
                is_prefix_tag.expr() * tindex_eq_tlength.clone() * tlength_lt.clone(),
                |cb| {
                    cb.require_equal("247 < value", value_gt_247.is_lt(meta, None), 1.expr());
                    // cb.require_equal("value < 256", value_lt_256.is_lt(meta, None), 1.expr());
                    cb.require_equal(
                        "tag_index::next == value - 0xf7",
                        meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                        meta.query_advice(byte_value, Rotation::cur()) - 247.expr(),
                    );
                    cb.require_zero(
                        "length_acc == 0",
                        meta.query_advice(length_acc, Rotation::cur()),
                    );
                },
            );

            // if tag_index == tag_length && tag_length == 1
            cb.condition(
                is_prefix_tag.expr() * tindex_eq_tlength.clone() * tlength_eq.clone(),
                |cb| {
                    cb.require_equal("191 < value", value_gt_191.is_lt(meta, None), 1.expr());
                    cb.require_equal("value < 248", value_lt_248.is_lt(meta, None), 1.expr());
                    cb.require_equal(
                        "length_acc == value - 0xc0 (1)",
                        meta.query_advice(length_acc, Rotation::cur()),
                        meta.query_advice(byte_value, Rotation::cur()) - 192.expr(),
                    );
                },
            );

            // if tag_index < tag_length && tag_length > 1
            cb.condition(
                is_prefix_tag.expr() * tindex_lt_tlength.clone() * tlength_lt.clone(),
                |cb| {
                    cb.require_equal(
                        "length_acc == (length_acc::prev * 256) + value",
                        meta.query_advice(length_acc, Rotation::cur()),
                        meta.query_advice(length_acc, Rotation::prev()) * 256.expr()
                            + meta.query_advice(byte_value, Rotation::cur()),
                    );
                },
            );

            //////////////////////////////////////////////////////////////////////////////////////
            //////// RlpTxTag::Nonce, GasPrice, Gas, To, Value, ChainID, SigV, SigR, SigS ////////
            //////////////////////////////////////////////////////////////////////////////////////
            cb.condition(is_simple_tag.clone(), |cb| {
                // TODO: add tag_length < max_length

                // tag_index >= 1
                cb.require_zero(
                    "1 <= tag_index",
                    not::expr(or::expr([tindex_lt.clone(), tindex_eq.clone()])),
                );
            });

            // cb.require_equal(
            //     "interm == is_simple_tag "
            //     is_simple_tag.clone()
            // )
            // if tag_index == tag_length && tag_length == 1
            cb.condition(
                is_simple_tag.clone() * tindex_eq_tlength.clone() * tlength_eq.clone(),
                |cb| {
                    let value = select::expr(
                        value_eq_128.is_equal_expression.expr(),
                        0.expr(),
                        meta.query_advice(byte_value, Rotation::cur()),
                    );
                    cb.require_equal("byte_value < 129", value_lt_129.is_lt(meta, None), 1.expr());
                    cb.require_equal(
                        "value == value_acc",
                        value,
                        meta.query_advice(rlp_table.value_acc, Rotation::cur()),
                    );
                },
            );

            // if tag_index == tag_length && tag_length > 1
            cb.condition(
                is_simple_tag.clone() * tindex_eq_tlength.clone() * tlength_lt.clone(),
                |cb| {
                    cb.require_equal("127 < value", value_gt_127.is_lt(meta, None), 1.expr());
                    cb.require_equal("value < 184", value_lt_184.is_lt(meta, None), 1.expr());
                    cb.require_equal(
                        "length_acc == value - 0x80",
                        meta.query_advice(length_acc, Rotation::cur()),
                        meta.query_advice(byte_value, Rotation::cur()) - 128.expr(),
                    );
                    cb.require_equal(
                        "tag_index::next == length_acc",
                        meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                        meta.query_advice(length_acc, Rotation::cur()),
                    );
                    cb.require_equal(
                        "value_acc == 0",
                        meta.query_advice(rlp_table.value_acc, Rotation::cur()),
                        0.expr(),
                    );
                },
            );

            // if tag_index > 1
            cb.condition(is_simple_tag.clone() * tindex_lt.clone(), |cb| {
                cb.require_equal(
                    "tag::next == tag",
                    meta.query_advice(rlp_table.tag, Rotation::next()),
                    meta.query_advice(rlp_table.tag, Rotation::cur()),
                );
                cb.require_equal(
                    "tag_index::next == tag_index - 1",
                    meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                    meta.query_advice(rlp_table.tag_rindex, Rotation::cur()) - 1.expr(),
                );
                cb.require_equal(
                    "tag_length::next == tag_length",
                    meta.query_advice(tag_length, Rotation::next()),
                    meta.query_advice(tag_length, Rotation::cur()),
                );
                let power_base = select::expr(
                    is_tag_word,
                    evm_word_rand.expr(),
                    256.expr(),
                );
                cb.require_equal(
                    "[simple_tag] value_acc::next == value_acc::cur * power_base + value::next",
                    meta.query_advice(rlp_table.value_acc, Rotation::next()),
                    meta.query_advice(rlp_table.value_acc, Rotation::cur()) * power_base +
                        meta.query_advice(byte_value, Rotation::next()),
                );
            });

            // if tag_index == 1
            cb.condition(is_simple_tag * tindex_eq.clone(), |cb| {
                cb.require_equal(
                    "tag_index::next == tag_length::next",
                    meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                    meta.query_advice(tag_length, Rotation::next()),
                );
            });

            //////////////////////////////////////////////////////////////////////////////////////
            ///////////////////////////////// RlpTxTag::DataPrefix ///////////////////////////////
            //////////////////////////////////////////////////////////////////////////////////////
            cb.condition(is_dp_tag.expr(), |cb| {
                // tag_index < 10
                cb.require_equal(
                    "tag_index < 10",
                    tag_index_lt_10.is_lt(meta, None),
                    1.expr(),
                );

                // tag_index >= 1
                cb.require_zero(
                    "tag_index >= 1",
                    not::expr(or::expr([tindex_lt.clone(), tindex_eq.clone()])),
                );
            });

            // if tag_index > 1
            cb.condition(is_dp_tag.expr() * tindex_lt.clone(), |cb| {
                cb.require_equal(
                    "tag::next == RlpTxTag::DataPrefix",
                    meta.query_advice(rlp_table.tag, Rotation::next()),
                    RlpTxTag::DataPrefix.expr(),
                );
                cb.require_equal(
                    "tag_index::next == tag_index - 1",
                    meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                    meta.query_advice(rlp_table.tag_rindex, Rotation::cur()) - 1.expr(),
                );
                cb.require_equal(
                    "tag_length::next == tag_length",
                    meta.query_advice(tag_length, Rotation::next()),
                    meta.query_advice(tag_length, Rotation::cur()),
                );
            });

            // if length_acc == 0
            cb.condition(
                is_dp_tag.expr() * tindex_eq.clone() * length_acc_eq_0,
                |cb| {
                    let is_tx_hash = meta.query_advice(rlp_table.data_type, Rotation::cur())
                        - RlpDataType::TxSign.expr();
                    let tag_next = select::expr(
                        is_tx_hash,
                        SigV.expr(),
                        ChainId.expr(),
                    );
                    cb.require_equal(
                        "value_acc == length_acc",
                        meta.query_advice(rlp_table.value_acc, Rotation::cur()),
                        meta.query_advice(length_acc, Rotation::cur()),
                    );
                    cb.require_equal(
                        "tag::next == RlpTxTag::ChainId",
                        meta.query_advice(rlp_table.tag, Rotation::next()),
                        tag_next,
                    );
                    cb.require_equal(
                        "tag_index::next == tag_length::next",
                        meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                        meta.query_advice(tag_length, Rotation::next()),
                    );
                },
            );

            // if length_acc > 0
            cb.condition(
                is_dp_tag.expr() * tindex_eq.clone() * length_acc_gt_0,
                |cb| {
                    cb.require_equal(
                        "tag::next == RlpTxTag::Data",
                        meta.query_advice(rlp_table.tag, Rotation::next()),
                        RlpTxTag::Data.expr(),
                    );
                    cb.require_equal(
                        "tag_index::next == tag_length::next",
                        meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                        meta.query_advice(tag_length, Rotation::next()),
                    );
                    cb.require_equal(
                        "tag_length::next == length_acc",
                        meta.query_advice(tag_length, Rotation::next()),
                        meta.query_advice(length_acc, Rotation::cur()),
                    );
                    cb.require_equal(
                        "value_acc == length_acc",
                        meta.query_advice(rlp_table.value_acc, Rotation::cur()),
                        meta.query_advice(length_acc, Rotation::cur()),
                    );
                },
            );

            // if tag_index == tag_length && tag_length > 1
            cb.condition(
                is_dp_tag.expr() * tindex_eq_tlength.clone() * tlength_lt.clone(),
                |cb| {
                    cb.require_equal("value > 183", value_gt_183.is_lt(meta, None), 1.expr());
                    cb.require_equal("value < 192", value_lt_192.is_lt(meta, None), 1.expr());
                    cb.require_equal(
                        "tag_index == (value - 0xb7) + 1",
                        meta.query_advice(rlp_table.tag_rindex, Rotation::cur()),
                        meta.query_advice(byte_value, Rotation::cur()) - 182.expr(),
                    );
                    cb.require_zero(
                        "length_acc == 0",
                        meta.query_advice(length_acc, Rotation::cur()),
                    );
                },
            );

            // if tag_index < tag_length && tag_length > 1
            cb.condition(
                is_dp_tag.expr() * tindex_lt_tlength * tlength_lt,
                |cb| {
                    cb.require_equal(
                        "length_acc == (length_acc::prev * 256) + value",
                        meta.query_advice(length_acc, Rotation::cur()),
                        meta.query_advice(length_acc, Rotation::prev()) * 256.expr()
                            + meta.query_advice(byte_value, Rotation::cur()),
                    );
                },
            );

            // if tag_index == tag_length && tag_length == 1
            cb.condition(
                is_dp_tag.expr() * tindex_eq_tlength * tlength_eq,
                |cb| {
                    cb.require_equal("value < 184", value_lt_184.is_lt(meta, None), 1.expr());
                    let real_length_acc = select::expr(
                        value_gt_127.is_lt(meta, None),
                        meta.query_advice(byte_value, Rotation::cur()) - 128.expr(), // value > 127
                        1.expr(),
                    );
                    cb.require_equal(
                        "length_acc == value > 127 ? value - 0x80 : 1",
                        meta.query_advice(length_acc, Rotation::cur()),
                        real_length_acc,
                    );
                },
            );

            //////////////////////////////////////////////////////////////////////////////////////
            //////////////////////////////////// RlpTxTag::Data //////////////////////////////////
            //////////////////////////////////////////////////////////////////////////////////////
            cb.condition(is_data(meta), |cb| {
                // tag_index >= 1
                cb.require_zero(
                    "tag_index >= 1",
                    not::expr(or::expr([tindex_lt.clone(), tindex_eq.clone()])),
                );
            });

            // if tag_index > 1
            cb.condition(is_data(meta) * tindex_lt.clone(), |cb| {
                cb.require_equal(
                    "tag::next == RlpTxTag::Data",
                    meta.query_advice(rlp_table.tag, Rotation::next()),
                    RlpTxTag::Data.expr(),
                );
                cb.require_equal(
                    "tag_rindex::next == tag_rindex - 1",
                    meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                    meta.query_advice(rlp_table.tag_rindex, Rotation::cur()) - 1.expr(),
                );
                cb.require_equal(
                    "tag_length::next == tag_length",
                    meta.query_advice(tag_length, Rotation::next()),
                    meta.query_advice(tag_length, Rotation::cur()),
                );
                cb.require_equal(
                    "calldata_bytes_rlc_acc' == calldata_bytes_rlc_acc * r + byte_value'",
                    meta.query_advice(calldata_bytes_rlc_acc, Rotation::next()),
                    meta.query_advice(calldata_bytes_rlc_acc, Rotation::cur()) * keccak_input_rand.clone()
                        + meta.query_advice(byte_value, Rotation::next()),
                );
                cb.require_equal(
                    "rlp_table.value_acc == byte_value",
                    meta.query_advice(rlp_table.value_acc, Rotation::cur()),
                    meta.query_advice(byte_value, Rotation::cur()),
                );
            });

            // if tag_index == 1 for TxSign
            cb.condition(
                and::expr(vec![
                    is_data(meta),
                    tindex_eq.clone(),
                    not::expr(meta.query_advice(rlp_table.data_type, Rotation::cur())),
                ]),
                |cb| {
                    cb.require_equal(
                        "[data] tag::next == RlpTxTag::ChainId",
                        meta.query_advice(rlp_table.tag, Rotation::next()),
                        RlpTxTag::ChainId.expr(),
                    );
                    cb.require_equal(
                        "tag_index::next == tag_length::next",
                        meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                        meta.query_advice(tag_length, Rotation::next()),
                    );
                }
            );

            // if tag_index == 1 for TxHash
            cb.condition(
                and::expr(vec![
                    is_data(meta),
                    tindex_eq.clone(),
                    meta.query_advice(rlp_table.data_type, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_equal(
                        "tag::next == RlpTxTag::SigV",
                        meta.query_advice(rlp_table.tag, Rotation::next()),
                        RlpTxTag::SigV.expr(),
                    );
                    cb.require_equal(
                        "tag_index::next == tag_length::next",
                        meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                        meta.query_advice(tag_length, Rotation::next()),
                    );
                }
            );

            cb.gate(meta.query_fixed(q_usable, Rotation::cur()))
        });

        meta.create_gate("DataType::TxSign (unsigned transaction)", |meta| {
            let mut cb = BaseConstraintBuilder::new(9);

            let (_, tindex_eq) = tag_index_cmp_1.expr(meta, None);

            //////////////////////////////////////////////////////////////////////////////////////
            ////////////////////////////////// RlpTxTag::ChainID /////////////////////////////////
            //////////////////////////////////////////////////////////////////////////////////////

            // if tag_index == 1
            cb.condition(is_chainid(meta) * tindex_eq, |cb| {
                // checks for RlpTxTag::Zero on the next row.
                cb.require_equal(
                    "next tag is Zero",
                    meta.query_advice(rlp_table.tag, Rotation::next()),
                    RlpTxTag::Zero.expr(),
                );
                cb.require_equal(
                    "next tag is Zero => tag_rindex::next == 1",
                    meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                    1.expr(),
                );
                cb.require_equal(
                    "next tag is Zero => value::next == 128",
                    meta.query_advice(byte_value, Rotation::next()),
                    128.expr(),
                );
                cb.require_equal(
                    "next tag is Zero => value_acc::next == 0",
                    meta.query_advice(rlp_table.value_acc, Rotation::next()),
                    0.expr(),
                );

                // checks for RlpTxTag::Zero on the next(2) row.
                cb.require_equal(
                    "tag::Rotation(2) == RlpTxTag::Zero",
                    meta.query_advice(rlp_table.tag, Rotation(2)),
                    RlpTxTag::Zero.expr(),
                );
                cb.require_equal(
                    "tag_rindex::Rotation(2) == tag_length::Rotation(2)",
                    meta.query_advice(rlp_table.tag_rindex, Rotation(2)),
                    meta.query_advice(tag_length, Rotation(2)),
                );
                cb.require_equal(
                    "next-to-next tag is Zero => tag_rindex::Rotation(2) == 1",
                    meta.query_advice(rlp_table.tag_rindex, Rotation(2)),
                    1.expr(),
                );
                cb.require_equal(
                    "next-to-next tag is Zero => value::Rotation(2) == 128",
                    meta.query_advice(byte_value, Rotation(2)),
                    128.expr(),
                );
                cb.require_equal(
                    "next-to-next tag is Zero => value_acc::Rotation(2) == 0",
                    meta.query_advice(rlp_table.value_acc, Rotation(2)),
                    0.expr(),
                );

                // checks for RlpTxTag::RlpLength on the next(3) row.
                cb.require_equal(
                    "tag::Rotation(3) == RlpTxTag::RlpLength",
                    meta.query_advice(rlp_table.tag, Rotation(3)),
                    RlpTxTag::RlpLength.expr(),
                );
                cb.require_equal(
                    "tag_rindex::Rotation(3) == tag_length::Rotation(3)",
                    meta.query_advice(rlp_table.tag_rindex, Rotation(3)),
                    meta.query_advice(tag_length, Rotation(3)),
                );
                cb.require_equal(
                    "tag_rindex::Rotation(3) == 1",
                    meta.query_advice(rlp_table.tag_rindex, Rotation(3)),
                    1.expr(),
                );
                cb.require_equal(
                    "value_acc::Rotation(3) == Rlp encoding length == index::Rotation(2)",
                    meta.query_advice(rlp_table.value_acc, Rotation(3)),
                    meta.query_advice(index, Rotation(2)),
                );

                // checks for RlpTxTag::Rlp on the next(4) row.
                cb.require_equal(
                    "tag::Rotation(4) == RlpTxTag::Rlp",
                    meta.query_advice(rlp_table.tag, Rotation(4)),
                    RlpTxTag::Rlp.expr(),
                );
                // reaches the end of an RLP(TxSign) instance
                cb.require_zero(
                    "next(4) tag is Rlp => rindex == 0",
                    meta.query_advice(rindex, Rotation(4)),
                );
                cb.require_equal(
                    "tag_rindex::Rotation(4) == tag_length::Rotation(4)",
                    meta.query_advice(rlp_table.tag_rindex, Rotation(4)),
                    meta.query_advice(tag_length, Rotation(4)),
                );
                cb.require_equal(
                    "tag_rindex::Rotation(4) == 1",
                    meta.query_advice(rlp_table.tag_rindex, Rotation(4)),
                    1.expr(),
                );
                cb.require_equal(
                    "last tag is Rlp => value_acc::Rotation(4) == all_bytes_rlc_acc::Rotation(2)",
                    meta.query_advice(rlp_table.value_acc, Rotation(4)),
                    meta.query_advice(all_bytes_rlc_acc, Rotation(2)),
                );
                cb.require_equal(
                    "last tag is Rlp => is_last::Rotation(4) == 1",
                    meta.query_advice(is_last, Rotation(4)),
                    1.expr(),
                );
            });

            cb.gate(and::expr(vec![
                meta.query_fixed(q_usable, Rotation::cur()),
                not::expr(meta.query_advice(rlp_table.data_type, Rotation::cur())),
            ]))
        });

        meta.create_gate("DataType::TxHash (signed transaction)", |meta| {
            let mut cb = BaseConstraintBuilder::new(9);

            let (_, tindex_eq) = tag_index_cmp_1.expr(meta, None);

            // if tag_index == 1
            cb.condition(is_sig_s(meta) * tindex_eq, |cb| {
                // rindex == 0 for the end of an RLP(TxHash) instance
                cb.require_equal(
                    "next(2) tag is Rlp => rindex == 0",
                    meta.query_advice(rindex, Rotation(2)),
                    0.expr(),
                );
                // RlpTxTag::RlpLength checks.
                cb.require_equal(
                    "next tag is RlpLength",
                    meta.query_advice(rlp_table.tag, Rotation::next()),
                    RlpTxTag::RlpLength.expr(),
                );
                cb.require_equal(
                    "tag_rindex::next == 1",
                    meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                    1.expr(),
                );
                cb.require_equal(
                    "tag::next == RlpLength => value_acc::next == index::cur",
                    meta.query_advice(rlp_table.value_acc, Rotation::next()),
                    meta.query_advice(index, Rotation::cur()),
                );

                // RlpTxTag::Rlp checks.
                cb.require_equal(
                    "tag::Rotation(2) == RlpTxTag::Rlp",
                    meta.query_advice(rlp_table.tag, Rotation(2)),
                    RlpTxTag::Rlp.expr(),
                );
                cb.require_equal(
                    "last tag is Rlp => value_acc::Rotation(2) == all_bytes_rlc_acc::cur()",
                    meta.query_advice(rlp_table.value_acc, Rotation(2)),
                    meta.query_advice(all_bytes_rlc_acc, Rotation::cur()),
                );
                cb.require_equal(
                    "is_last::Rotation(2) == 1",
                    meta.query_advice(is_last, Rotation(2)),
                    1.expr(),
                );
            });

            cb.gate(and::expr(vec![
                meta.query_fixed(q_usable, Rotation::cur()),
                meta.query_advice(rlp_table.data_type, Rotation::cur()),
            ]))
        });

        // Constraints that always need to be satisfied.
        meta.create_gate("always", |meta| {
            let mut cb = BaseConstraintBuilder::new(9);

            cb.require_boolean(
                "is_first is boolean",
                meta.query_advice(is_first, Rotation::cur()),
            );
            cb.require_boolean(
                "is_last is boolean",
                meta.query_advice(is_last, Rotation::cur()),
            );
            cb.require_in_set(
                "data_type is in set {TxHash, TxSign}",
                meta.query_advice(rlp_table.data_type, Rotation::cur()),
                vec![RlpDataType::TxHash.expr(), RlpDataType::TxSign.expr()],
            );

            cb.gate(meta.query_fixed(q_usable, Rotation::cur()))
        });

        // Constraints for the first row in the layout.
        meta.create_gate("is_first == 1", |meta| {
            let mut cb = BaseConstraintBuilder::new(9);

            cb.require_equal(
                "value_rlc == value",
                meta.query_advice(all_bytes_rlc_acc, Rotation::cur()),
                meta.query_advice(byte_value, Rotation::cur()),
            );
            cb.require_equal(
                "index == 1",
                meta.query_advice(index, Rotation::cur()),
                1.expr(),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_usable, Rotation::cur()),
                meta.query_advice(is_first, Rotation::cur()),
                not::expr(is_padding(meta)),
            ]))
        });

        // Constraints for every row except the last row in one RLP instance.
        meta.create_gate("is_last == 0", |meta| {
            let mut cb = BaseConstraintBuilder::new(9);

            cb.condition(
                not::expr(meta.query_advice(placeholder, Rotation::cur())),
                |cb| {
                    cb.require_equal(
                        "index' == index + 1",
                        meta.query_advice(index, Rotation::next()),
                        meta.query_advice(index, Rotation::cur()) + 1.expr(),
                    );
                    cb.require_equal(
                        "rindex' == rindex - 1",
                        meta.query_advice(rindex, Rotation::next()),
                        meta.query_advice(rindex, Rotation::cur()) - 1.expr(),
                    );
                    cb.require_equal(
                        "all_bytes_rlc_acc' == (all_bytes_rlc_acc * r) + byte_value'",
                        meta.query_advice(all_bytes_rlc_acc, Rotation::next()),
                        meta.query_advice(all_bytes_rlc_acc, Rotation::cur()) * keccak_input_rand
                            + meta.query_advice(byte_value, Rotation::next()),
                    );
                },
            );
            cb.condition(meta.query_advice(placeholder, Rotation::cur()), |cb| {
                cb.require_equal(
                    "index' == index",
                    meta.query_advice(index, Rotation::next()),
                    meta.query_advice(index, Rotation::cur()),
                );
                cb.require_equal(
                    "rindex' == rindex",
                    meta.query_advice(rindex, Rotation::next()),
                    meta.query_advice(rindex, Rotation::cur()),
                );
                cb.require_equal(
                    "all_bytes_rlc_acc' == all_bytes_rlc_acc",
                    meta.query_advice(all_bytes_rlc_acc, Rotation::next()),
                    meta.query_advice(all_bytes_rlc_acc, Rotation::cur()),
                );
                cb.require_equal(
                    "byte_value' == byte_value",
                    meta.query_advice(byte_value, Rotation::next()),
                    meta.query_advice(byte_value, Rotation::cur()),
                );
            });

            cb.require_equal(
                "tx_id' == tx_id",
                meta.query_advice(rlp_table.tx_id, Rotation::next()),
                meta.query_advice(rlp_table.tx_id, Rotation::cur()),
            );
            cb.require_equal(
                "data_type' == data_type",
                meta.query_advice(rlp_table.data_type, Rotation::next()),
                meta.query_advice(rlp_table.data_type, Rotation::cur()),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_usable, Rotation::cur()),
                not::expr(meta.query_advice(is_last, Rotation::cur())),
                not::expr(is_padding(meta)),
            ]))
        });

        meta.create_gate("placeholder row only happens on DataPrefix", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            let (_, tag_length_eq_one) = tag_length_cmp_1.expr(meta, Some(Rotation::cur()));

            cb.require_equal("tag == DataPrefix", is_data_prefix(meta), 1.expr());
            cb.require_equal("tag_length == 1", tag_length_eq_one, 1.expr());
            cb.require_equal(
                "byte_value <= 0x80",
                value_lt_129.is_lt(meta, None),
                1.expr(),
            );
            cb.require_zero(
                "byte_value != 0x80",
                value_eq_128.is_equal_expression.expr(),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_usable, Rotation::cur()),
                meta.query_advice(placeholder, Rotation::cur()),
            ]))
        });

        // Constraints for the last row, i.e. RLP summary row.
        meta.create_gate("is_last == 1", |meta| {
            let mut cb = BaseConstraintBuilder::new(9);

            cb.require_equal(
                "is_last == 1 then tag == RlpTxTag::Rlp",
                meta.query_advice(rlp_table.tag, Rotation::cur()),
                RlpTxTag::Rlp.expr(),
            );

            // if data_type::cur == TxHash
            // - tx_id does not change.
            // - TxSign rows follow.
            cb.condition(
                meta.query_advice(rlp_table.data_type, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "tx_id does not change",
                        meta.query_advice(rlp_table.tx_id, Rotation::cur()),
                        meta.query_advice(rlp_table.tx_id, Rotation::next()),
                    );
                    cb.require_equal(
                        "TxSign rows follow TxHash rows",
                        meta.query_advice(rlp_table.data_type, Rotation::next()),
                        RlpDataType::TxSign.expr(),
                    );
                    cb.require_equal(
                        "TxSign rows' first row is Prefix again",
                        meta.query_advice(rlp_table.tag, Rotation::next()),
                        RlpTxTag::Prefix.expr(),
                    );
                    cb.require_equal(
                        "TxSign rows' first row starts with rlp_table.tag_rindex = tag_length",
                        meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                        meta.query_advice(tag_length, Rotation::next()),
                    );
                },
            );

            // if data_type::cur == TxSign and it was **not**
            // the last tx in the layout (tag::next != Padding)
            // - tx_id increments.
            // - TxHash rows follow.
            let is_tag_next_padding =
                tag_bits.value_equals(RlpTxTag::Padding, Rotation::next())(meta);
            cb.condition(
                and::expr(vec![
                    not::expr(meta.query_advice(rlp_table.data_type, Rotation::cur())),
                    not::expr(is_tag_next_padding),
                ]),
                |cb| {
                    cb.require_equal(
                        "tx_id increments",
                        meta.query_advice(rlp_table.tx_id, Rotation::cur()) + 1.expr(),
                        meta.query_advice(rlp_table.tx_id, Rotation::next()),
                    );
                    cb.require_equal(
                        "TxHash rows follow TxSign rows",
                        meta.query_advice(rlp_table.data_type, Rotation::next()),
                        RlpDataType::TxHash.expr(),
                    );
                    cb.require_equal(
                        "TxHash rows' first row is Prefix again",
                        meta.query_advice(rlp_table.tag, Rotation::next()),
                        RlpTxTag::Prefix.expr(),
                    );
                    cb.require_equal(
                        "TxSign rows' first row starts with rlp_table.tag_rindex = tag_length",
                        meta.query_advice(rlp_table.tag_rindex, Rotation::next()),
                        meta.query_advice(tag_length, Rotation::next()),
                    );
                },
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_usable, Rotation::cur()),
                meta.query_advice(is_last, Rotation::cur()),
            ]))
        });

        meta.create_gate("padding rows", |meta| {
            let mut cb = BaseConstraintBuilder::new(9);

            cb.condition(is_padding(meta), |cb| {
                cb.require_equal(
                    "tag_next == Padding",
                    meta.query_advice(rlp_table.tag, Rotation::next()),
                    RlpTxTag::Padding.expr(),
                );

                cb.require_zero(
                    "tx_id == 0",
                    meta.query_advice(rlp_table.tx_id, Rotation::cur()),
                );
                cb.require_zero(
                    "data_type == 0",
                    meta.query_advice(rlp_table.data_type, Rotation::cur()),
                );
                cb.require_zero(
                    "tag_rindex == 0",
                    meta.query_advice(rlp_table.tag_rindex, Rotation::cur()),
                );
                cb.require_zero(
                    "value_acc == 0",
                    meta.query_advice(rlp_table.value_acc, Rotation::cur()),
                );
            });

            cb.gate(meta.query_fixed(q_usable, Rotation::cur()))
        });

        Self {
            minimum_rows: meta.minimum_rows(),
            q_usable,
            is_first,
            is_last,
            rlp_table: *rlp_table,
            index,
            rindex,
            placeholder,
            byte_value,
            calldata_bytes_rlc_acc,
            tag_bits,
            tag_rom,
            tag_length,
            length_acc,
            all_bytes_rlc_acc,
            is_simple_tag,
            is_prefix_tag,
            is_dp_tag,
            tag_index_cmp_1,
            tag_index_length_cmp,
            tag_length_cmp_1,
            tag_index_lt_10,
            tag_index_lt_34,
            value_gt_127,
            value_gt_183,
            value_gt_191,
            value_gt_247,
            value_lt_129,
            value_eq_128,
            value_lt_184,
            value_lt_192,
            value_lt_248,
            length_acc_cmp_0,
        }
    }

    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        signed_txs: &[SignedTransaction],
        k: usize,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let keccak_input_rand = challenges.keccak_input();
        let tag_chip = BinaryNumberChip::construct(self.tag_bits);
        let tag_index_cmp_1_chip = ComparatorChip::construct(self.tag_index_cmp_1.clone());
        let tag_index_length_cmp_chip =
            ComparatorChip::construct(self.tag_index_length_cmp.clone());
        let tag_length_cmp_1_chip = ComparatorChip::construct(self.tag_length_cmp_1.clone());

        let tag_index_lt_10_chip = LtChip::construct(self.tag_index_lt_10);
        let tag_index_lt_34_chip = LtChip::construct(self.tag_index_lt_34);

        let value_gt_127_chip = LtChip::construct(self.value_gt_127);
        let value_gt_183_chip = LtChip::construct(self.value_gt_183);
        let value_gt_191_chip = LtChip::construct(self.value_gt_191);
        let value_gt_247_chip = LtChip::construct(self.value_gt_247);
        let value_lt_129_chip = LtChip::construct(self.value_lt_129);
        let value_eq_128_chip = IsEqualChip::construct(self.value_eq_128.clone());
        let value_lt_184_chip = LtChip::construct(self.value_lt_184);
        let value_lt_192_chip = LtChip::construct(self.value_lt_192);
        let value_lt_248_chip = LtChip::construct(self.value_lt_248);

        let length_acc_cmp_0_chip = ComparatorChip::construct(self.length_acc_cmp_0.clone());

        debug_assert!(
            k >= self.minimum_rows,
            "k: {}, minimum_rows: {}",
            k,
            self.minimum_rows,
        );
        let padding_end_offset = k - self.minimum_rows + 1;
        layouter.assign_region(
            || "assign tag rom",
            |mut region| {
                for (i, (tag, tag_next, max_length)) in [
                    (RlpTxTag::Nonce, RlpTxTag::GasPrice, 10),
                    (RlpTxTag::GasPrice, RlpTxTag::Gas, 34),
                    (RlpTxTag::Gas, RlpTxTag::To, 10),
                    (RlpTxTag::To, RlpTxTag::Value, 22),
                    (RlpTxTag::Value, RlpTxTag::DataPrefix, 34),
                    (RlpTxTag::ChainId, RlpTxTag::Zero, 10),
                    (RlpTxTag::SigV, RlpTxTag::SigR, 10),
                    (RlpTxTag::SigR, RlpTxTag::SigS, 34),
                    (RlpTxTag::SigS, RlpTxTag::RlpLength, 34),
                ]
                .into_iter()
                .enumerate()
                {
                    let offset = i;
                    region.assign_fixed(
                        || "tag",
                        self.tag_rom.tag,
                        offset,
                        || Value::known(F::from(tag as u64)),
                    )?;
                    region.assign_fixed(
                        || "tag_next",
                        self.tag_rom.tag_next,
                        offset,
                        || Value::known(F::from(tag_next as u64)),
                    )?;
                    region.assign_fixed(
                        || "max_length",
                        self.tag_rom.max_length,
                        offset,
                        || Value::known(F::from(max_length)),
                    )?;
                }

                Ok(())
            },
        )?;

        layouter.assign_region(
            || "assign RLP-encoded data",
            |mut region| {
                let mut offset = 0;
                let simple_tags = [
                    Nonce,
                    GasPrice,
                    Gas,
                    To,
                    RlpTxTag::Value,
                    SigV,
                    SigR,
                    SigS,
                    ChainId,
                ];

                for signed_tx in signed_txs.iter() {
                    // tx hash (signed tx)
                    let mut all_bytes_rlc_acc = Value::known(F::zero());
                    let tx_hash_rows = signed_tx.gen_witness(challenges);
                    let has_placeholder =
                        signed_tx.tx.call_data.len() == 1 && signed_tx.tx.call_data[0] < 0x80;
                    let n_rows = if has_placeholder {
                        tx_hash_rows.len() - 1
                    } else {
                        tx_hash_rows.len()
                    };
                    for (idx, row) in tx_hash_rows
                        .iter()
                        .chain(signed_tx.rlp_rows(keccak_input_rand).iter())
                        .enumerate()
                    {
                        let prev_row_placeholder = row.tag == RlpTxTag::Data && has_placeholder;
                        let cur_row_placeholder = row.tag == DataPrefix && has_placeholder;
                        // update value accumulator over the entire RLP encoding.
                        if !prev_row_placeholder {
                            // prev row has already accumulate the byte_value
                            all_bytes_rlc_acc = all_bytes_rlc_acc
                                .zip(keccak_input_rand)
                                .map(|(acc, rand)| acc * rand + F::from(row.value as u64));
                        }

                        // q_usable
                        region.assign_fixed(
                            || format!("q_usable: {}", offset),
                            self.q_usable,
                            offset,
                            || Value::known(F::one()),
                        )?;
                        // is_first
                        region.assign_advice(
                            || format!("assign is_first {}", offset),
                            self.is_first,
                            offset,
                            || Value::known(F::from((idx == 0) as u64)),
                        )?;
                        // advices
                        let rindex = (n_rows + 2 - row.index) as u64; // rindex decreases from n_rows+1 to 0
                        let rlp_table = &self.rlp_table;
                        let is_simple_tag =
                            simple_tags.iter().filter(|tag| **tag == row.tag).count();
                        let is_prefix_tag = (row.tag == Prefix).into();
                        let is_dp_tag = (row.tag == DataPrefix).into();

                        for (name, column, value) in [
                            ("is_last", self.is_last, (row.index == n_rows + 2).into()),
                            ("tx_id", rlp_table.tx_id, row.tx_id as u64),
                            ("tag", rlp_table.tag, (row.tag as u64)),
                            ("is_simple_tag", self.is_simple_tag, is_simple_tag as u64),
                            ("is_prefix_tag", self.is_prefix_tag, is_prefix_tag),
                            ("is_dp_tag", self.is_dp_tag, is_dp_tag),
                            ("tag_index", rlp_table.tag_rindex, (row.tag_rindex as u64)),
                            ("data_type", rlp_table.data_type, (row.data_type as u64)),
                            ("index", self.index, (row.index as u64)),
                            ("rindex", self.rindex, (rindex)),
                            ("placeholder", self.placeholder, cur_row_placeholder as u64),
                            ("value", self.byte_value, (row.value as u64)),
                            ("tag_length", self.tag_length, (row.tag_length as u64)),
                            ("length_acc", self.length_acc, (row.length_acc)),
                        ] {
                            region.assign_advice(
                                || format!("assign {} {}", name, offset),
                                column,
                                offset,
                                || Value::known(F::from(value)),
                            )?;
                        }
                        for (name, column, value) in [
                            (
                                "rlp_table::value_acc",
                                self.rlp_table.value_acc,
                                row.value_acc,
                            ),
                            (
                                "calldata_bytes_acc_rlc",
                                self.calldata_bytes_rlc_acc,
                                row.value_rlc_acc,
                            ),
                            (
                                "all_bytes_rlc_acc",
                                self.all_bytes_rlc_acc,
                                all_bytes_rlc_acc,
                            ),
                        ] {
                            region.assign_advice(
                                || format!("assign {} {}", name, offset),
                                column,
                                offset,
                                || value,
                            )?;
                        }

                        tag_chip.assign(&mut region, offset, &row.tag)?;

                        for (chip, lhs, rhs) in [
                            (&tag_index_cmp_1_chip, 1, row.tag_rindex as u64),
                            (
                                &tag_index_length_cmp_chip,
                                row.tag_rindex,
                                row.tag_length as u64,
                            ),
                            (&tag_length_cmp_1_chip, 1, row.tag_length as u64),
                            (&length_acc_cmp_0_chip, 0, row.length_acc),
                        ] {
                            chip.assign(&mut region, offset, F::from(lhs as u64), F::from(rhs))?;
                        }

                        value_eq_128_chip.assign(
                            &mut region,
                            offset,
                            Value::known(F::from(row.value as u64)),
                            Value::known(F::from(128u64)),
                        )?;

                        for (chip, lhs, rhs) in [
                            (&tag_index_lt_10_chip, row.tag_rindex, 10),
                            (&tag_index_lt_34_chip, row.tag_rindex, 34),
                        ] {
                            chip.assign(
                                &mut region,
                                offset,
                                F::from(lhs as u64),
                                F::from(rhs as u64),
                            )?;
                        }
                        for (chip, lhs, rhs) in [
                            (&value_gt_127_chip, 127, row.value),
                            (&value_gt_183_chip, 183, row.value),
                            (&value_gt_191_chip, 191, row.value),
                            (&value_gt_247_chip, 247, row.value),
                            (&value_lt_129_chip, row.value as usize, 129),
                            (&value_lt_184_chip, row.value as usize, 184),
                            (&value_lt_192_chip, row.value as usize, 192),
                            (&value_lt_248_chip, row.value as usize, 248),
                        ] {
                            chip.assign(
                                &mut region,
                                offset,
                                F::from(lhs as u64),
                                F::from(rhs as u64),
                            )?;
                        }

                        offset += 1;
                    }

                    // tx sign (unsigned tx)
                    let mut all_bytes_rlc_acc = Value::known(F::zero());
                    let tx_sign_rows = signed_tx.tx.gen_witness(challenges);
                    let has_placeholder =
                        signed_tx.tx.call_data.len() == 1 && signed_tx.tx.call_data[0] < 0x80;
                    let n_rows = if has_placeholder {
                        tx_sign_rows.len() - 1
                    } else {
                        tx_sign_rows.len()
                    };
                    for (idx, row) in tx_sign_rows
                        .iter()
                        .chain(signed_tx.tx.rlp_rows(challenges.keccak_input()).iter())
                        .enumerate()
                    {
                        let prev_row_placeholder = row.tag == RlpTxTag::Data && has_placeholder;
                        let cur_row_placeholder = row.tag == DataPrefix && has_placeholder;
                        // update value accumulator over the entire RLP encoding.
                        if !prev_row_placeholder {
                            // prev row has already accumulate the byte_value
                            all_bytes_rlc_acc = all_bytes_rlc_acc
                                .zip(keccak_input_rand)
                                .map(|(acc, rand)| acc * rand + F::from(row.value as u64));
                        }

                        // q_usable
                        region.assign_fixed(
                            || format!("q_usable: {}", offset),
                            self.q_usable,
                            offset,
                            || Value::known(F::one()),
                        )?;
                        // is_first
                        region.assign_advice(
                            || format!("assign is_first {}", offset),
                            self.is_first,
                            offset,
                            || Value::known(F::from((idx == 0) as u64)),
                        )?;
                        // advices
                        let rindex = (n_rows + 2 - row.index) as u64; // rindex decreases from n_rows+1 to 0
                        let rlp_table = &self.rlp_table;
                        let is_simple_tag =
                            simple_tags.iter().filter(|tag| **tag == row.tag).count();
                        let is_prefix_tag = (row.tag == Prefix).into();
                        let is_dp_tag = (row.tag == DataPrefix).into();
                        for (name, column, value) in [
                            ("is_last", self.is_last, (row.index == n_rows + 2).into()),
                            ("tx_id", rlp_table.tx_id, row.tx_id as u64),
                            ("tag", rlp_table.tag, row.tag as u64),
                            ("is_simple_tag", self.is_simple_tag, is_simple_tag as u64),
                            ("is_prefix_tag", self.is_prefix_tag, is_prefix_tag),
                            ("is_dp_tag", self.is_dp_tag, is_dp_tag),
                            ("tag_rindex", rlp_table.tag_rindex, row.tag_rindex as u64),
                            ("data_type", rlp_table.data_type, row.data_type as u64),
                            ("index", self.index, row.index as u64),
                            ("rindex", self.rindex, rindex),
                            ("placeholder", self.placeholder, cur_row_placeholder as u64),
                            ("byte value", self.byte_value, row.value as u64),
                            ("tag_length", self.tag_length, row.tag_length as u64),
                            ("length_acc", self.length_acc, row.length_acc),
                        ] {
                            region.assign_advice(
                                || format!("assign {} {}", name, offset),
                                column,
                                offset,
                                || Value::known(F::from(value)),
                            )?;
                        }
                        for (name, column, value) in [
                            ("rlp_table::value_acc", rlp_table.value_acc, row.value_acc),
                            (
                                "calldata_bytes_rlc_acc",
                                self.calldata_bytes_rlc_acc,
                                row.value_rlc_acc,
                            ),
                            (
                                "all_bytes_rlc_acc",
                                self.all_bytes_rlc_acc,
                                all_bytes_rlc_acc,
                            ),
                        ] {
                            region.assign_advice(
                                || format!("assign {} {}", name, offset),
                                column,
                                offset,
                                || value,
                            )?;
                        }

                        tag_chip.assign(&mut region, offset, &row.tag)?;

                        for (chip, lhs, rhs) in [
                            (&tag_index_cmp_1_chip, 1, row.tag_rindex as u64),
                            (
                                &tag_index_length_cmp_chip,
                                row.tag_rindex,
                                row.tag_length as u64,
                            ),
                            (&tag_length_cmp_1_chip, 1, row.tag_length as u64),
                            (&length_acc_cmp_0_chip, 0, row.length_acc),
                        ] {
                            chip.assign(&mut region, offset, F::from(lhs as u64), F::from(rhs))?;
                        }

                        value_eq_128_chip.assign(
                            &mut region,
                            offset,
                            Value::known(F::from(row.value as u64)),
                            Value::known(F::from(128u64)),
                        )?;

                        for (chip, lhs, rhs) in [
                            (&tag_index_lt_10_chip, row.tag_rindex, 10),
                            (&tag_index_lt_34_chip, row.tag_rindex, 34),
                        ] {
                            chip.assign(
                                &mut region,
                                offset,
                                F::from(lhs as u64),
                                F::from(rhs as u64),
                            )?;
                        }

                        for (chip, lhs, rhs) in [
                            (&value_gt_127_chip, 127, row.value),
                            (&value_gt_183_chip, 183, row.value),
                            (&value_gt_191_chip, 191, row.value),
                            (&value_gt_247_chip, 247, row.value),
                            (&value_lt_129_chip, row.value as usize, 129),
                            (&value_lt_184_chip, row.value as usize, 184),
                            (&value_lt_192_chip, row.value as usize, 192),
                            (&value_lt_248_chip, row.value as usize, 248),
                        ] {
                            chip.assign(
                                &mut region,
                                offset,
                                F::from(lhs as u64),
                                F::from(rhs as u64),
                            )?;
                        }

                        offset += 1;
                    }
                }

                // TODO: speed up the assignment of padding rows
                let padding_start_offset = offset;
                // end with padding rows.
                for offset in padding_start_offset..padding_end_offset {
                    self.assign_padding_rows(&mut region, offset)?;
                }

                Ok(())
            },
        )
    }

    fn assign_padding_rows(&self, region: &mut Region<'_, F>, offset: usize) -> Result<(), Error> {
        for column in [
            self.rlp_table.tx_id,
            self.rlp_table.tag_rindex,
            self.rlp_table.value_acc,
            self.rlp_table.data_type,
        ]
        .into_iter()
        {
            region.assign_advice(
                || format!("padding row, offset: {}", offset),
                column,
                offset,
                || Value::known(F::zero()),
            )?;
        }
        region.assign_advice(
            || format!("padding row, tag = Padding, offset: {}", offset),
            self.rlp_table.tag,
            offset,
            || {
                Value::known(F::from(
                    <RlpTxTag as Into<usize>>::into(RlpTxTag::Padding) as u64
                ))
            },
        )?;
        region.assign_fixed(
            || format!("padding row, offset: {}", offset),
            self.q_usable,
            offset,
            || Value::known(F::one()),
        )?;

        Ok(())
    }
}

/// Circuit configuration arguments
pub struct RlpCircuitConfigArgs<F: Field> {
    /// RlpTable
    rlp_table: RlpTable,
    /// Challenges
    challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for RlpCircuitConfig<F> {
    type ConfigArgs = RlpCircuitConfigArgs<F>;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        RlpCircuitConfig::configure(meta, &args.rlp_table, &args.challenges)
    }
}

/// Circuit to verify RLP encoding is correct
#[derive(Clone, Debug)]
pub struct RlpCircuit<F, RLP> {
    /// Rlp encoding inputs
    pub inputs: Vec<RLP>,
    /// Size of the circuit
    pub size: usize,
    _marker: PhantomData<F>,
}

impl<F: Field, RLP> Default for RlpCircuit<F, RLP> {
    fn default() -> Self {
        Self {
            inputs: vec![],
            size: 0,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> SubCircuit<F> for RlpCircuit<F, SignedTransaction> {
    type Config = RlpCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        let signed_txs = block
            .txs
            .iter()
            .zip(block.sigs.iter())
            .map(|(tx, sig)| SignedTransaction {
                tx: tx.clone(),
                signature: *sig,
            })
            .collect::<Vec<_>>();

        Self {
            inputs: signed_txs,
            // FIXME: this hard-coded size is used to pass unit test, we should use 1 << k instead.
            size: 1 << 18,
            _marker: Default::default(),
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign(layouter, &self.inputs, self.size, challenges)
    }

    fn min_num_rows_block(block: &crate::witness::Block<F>) -> usize {
        std::cmp::max(
            1 << 18,
            block
                .txs
                .iter()
                .zip(block.sigs.iter())
                .map(|(tx, sig)| {
                    let mut len = rlp::encode(tx).len() + 1; // 1 for DataPrefix placeholder
                    let signed_tx = SignedTransaction {
                        tx: tx.clone(),
                        signature: *sig,
                    };
                    len += rlp::encode(&signed_tx).len() + 1; // 1 for DataPrefix placeholder
                    len
                })
                .count(),
        )
    }
}

impl<F: Field> Circuit<F> for RlpCircuit<F, SignedTransaction> {
    type Config = (RlpCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rlp_table = RlpTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let rand_exprs = challenges.exprs(meta);
        let config = RlpCircuitConfig::configure(meta, &rlp_table, &rand_exprs);

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);
        config.assign(
            &mut layouter,
            self.inputs.as_slice(),
            self.size,
            &challenges,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use eth_types::Field;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use mock::CORRECT_MOCK_TXS;

    use crate::evm_circuit::witness::SignedTransaction;

    use super::RlpCircuit;

    fn verify_txs<F: Field>(k: u32, inputs: Vec<SignedTransaction>, success: bool) {
        let circuit = RlpCircuit::<F, SignedTransaction> {
            inputs,
            size: 1 << k,
            _marker: PhantomData,
        };

        const NUM_BLINDING_ROWS: usize = 8;
        let instance = vec![];
        let prover = MockProver::<F>::run(k, &circuit, instance).unwrap();
        let err = prover.verify_par();
        let print_failures = true;
        if err.is_err() && print_failures {
            if let Some(e) = err.err() {
                for s in e.iter() {
                    println!("{}", s);
                }
            }
        }
        let err = prover.verify_par();
        assert_eq!(err.is_ok(), success);
    }

    #[test]
    fn rlp_circuit_tx_1() {
        verify_txs::<Fr>(8, vec![CORRECT_MOCK_TXS[0].clone().into()], true);
        verify_txs::<Fr>(8, vec![CORRECT_MOCK_TXS[4].clone().into()], true);

        // test against the case in which tx.data has only one byte and is less than
        // 0x80
        let mut mock_tx = CORRECT_MOCK_TXS[0].clone();
        mock_tx.input(vec![0x3f].into());
        verify_txs::<Fr>(8, vec![mock_tx.into()], true);
    }

    #[test]
    fn rlp_circuit_tx_2() {
        verify_txs::<Fr>(8, vec![CORRECT_MOCK_TXS[1].clone().into()], true);
    }

    #[test]
    fn rlp_circuit_tx_3() {
        verify_txs::<Fr>(20, vec![CORRECT_MOCK_TXS[2].clone().into()], true);
    }

    #[test]
    fn rlp_circuit_multi_txs() {
        verify_txs::<Fr>(
            10,
            vec![
                CORRECT_MOCK_TXS[0].clone().into(),
                CORRECT_MOCK_TXS[1].clone().into(),
                CORRECT_MOCK_TXS[2].clone().into(),
            ],
            true,
        );
    }
}
