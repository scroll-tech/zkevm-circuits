//! This circuit decodes zstd compressed data.

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;

#[cfg(any(feature = "test", test))]
mod test;

use std::marker::PhantomData;

use array_init::array_init;
use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig},
    util::{and, not, select, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, VirtualCells,
    },
    poly::Rotation,
};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{KeccakTable, U8Table},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{Block, ZstdTag, N_BITS_PER_BYTE, N_BITS_ZSTD_TAG},
};

/// Tables, challenge API used to configure the Decompression circuit.
pub struct DecompressionCircuitConfigArgs<F> {
    /// Challenge API.
    pub challenges: Challenges<Expression<F>>,
    /// U8 table, i.e. RangeTable for 0..8.
    pub u8_table: U8Table,
    /// Table from the Keccak circuit.
    pub keccak_table: KeccakTable,
}

/// The Decompression circuit's configuration. The columns used to constrain the Decompression
/// logic are defined here. Refer the [design doc][doclink] for design decisions and specifications.
///
/// [doclink]: https://www.notion.so/scrollzkp/zstd-in-circuit-decompression-23f8036538e440ebbbc17c69033d36f5?pvs=4
#[derive(Clone, Debug)]
pub struct DecompressionCircuitConfig<F> {
    /// Fixed column to mark all enabled rows.
    q_enable: Column<Fixed>,
    /// Fixed column to mark the first row in the layout.
    q_first: Column<Fixed>,
    /// Boolean column to mark whether or not the row represents a padding column.
    is_padding: Column<Advice>,

    /// The index of the byte being processed within the current frame. The first byte has a
    /// byte_idx == 1. byte_idx follows the relation byte_idx' >= byte_idx. That is, byte_idx is
    /// increasing, but can repeat over two or more rows if we are decoding bits from the same byte
    /// over those consecutive rows. For instance, if a Huffman Code bitstring is 2 bits long,
    /// we might end up decoding on the same byte_idx at the most 4 times.
    byte_idx: Column<Advice>,
    /// The number of bytes in the zstd encoded data.
    encoded_len: Column<Advice>,
    /// The byte value at the current byte index. This will be decomposed in its bits.
    value_byte: Column<Advice>,
    /// The 8 bits for the above byte, little-endian.
    value_bits: [Column<Advice>; N_BITS_PER_BYTE],
    /// The random linear combination of all encoded bytes up to and including the current one.
    value_rlc: Column<Advice>,
    /// An accumulator for the number of decoded bytes. For every byte decoded, we expect the
    /// accumulator to be incremented.
    decoded_len: Column<Advice>,
    /// The byte value that is decoded at the current row. We don't decode a byte at every row. And
    /// we might end up decoding more than one bytes while the byte_idx remains the same, for
    /// instance, while processing bits and decoding the Huffman Codes.
    decoded_byte: Column<Advice>,
    /// The random linear combination of all decoded bytes up to and including the current one.
    decoded_rlc: Column<Advice>,
    /// All zstd tag related columns.
    tag_gadget: ZstdTagGadget<F>,

    /// The range table to check value is byte.
    u8_table: U8Table,
}

/// All tag related columns are placed in this type.
#[derive(Clone, Debug)]
pub struct ZstdTagGadget<F> {
    /// The zstd tag at the current row.
    tag: Column<Advice>,
    /// Helper gadget to construct equality constraints against the current tag.
    tag_bits: BinaryNumberConfig<ZstdTag, N_BITS_ZSTD_TAG>,
    /// The tag that follows once the current tag is done processing.
    tag_next: Column<Advice>,
    /// The value held by this tag, generally a linear combination of the bytes within the tag.
    tag_value: Column<Advice>,
    /// An accumulator for the tag value, which on the last byte of the tag should equal the
    /// tag_value itself.
    tag_value_acc: Column<Advice>,
    /// The number of bytes reserved for the tag.
    tag_len: Column<Advice>,
    /// The index within tag_len.
    tag_idx: Column<Advice>,
    /// The maximum number of bytes that this tag can hold.
    max_len: Column<Advice>,
    /// Check: tag_idx <= tag_len.
    idx_cmp_len: ComparatorConfig<F, 1>,
    /// Check: tag_len <= max_len.
    len_cmp_max: ComparatorConfig<F, 1>,
}

impl<F: Field> SubCircuitConfig<F> for DecompressionCircuitConfig<F> {
    type ConfigArgs = DecompressionCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            challenges,
            u8_table,
            keccak_table: _,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.fixed_column();
        let q_first = meta.fixed_column();
        let is_padding = meta.advice_column();
        let byte_idx = meta.advice_column();
        let encoded_len = meta.advice_column();
        let value_byte = meta.advice_column();
        let value_bits = array_init(|_| meta.advice_column());
        let value_rlc = meta.advice_column_in(SecondPhase);
        let decoded_len = meta.advice_column();
        let decoded_byte = meta.advice_column();
        let decoded_rlc = meta.advice_column_in(SecondPhase);
        let tag_gadget = {
            let tag = meta.advice_column();
            let tag_len = meta.advice_column();
            let tag_idx = meta.advice_column();
            let max_len = meta.advice_column();
            ZstdTagGadget {
                tag,
                tag_bits: BinaryNumberChip::configure(meta, q_enable, Some(tag.into())),
                tag_next: meta.advice_column(),
                tag_value: meta.advice_column(),
                tag_value_acc: meta.advice_column(),
                tag_len,
                tag_idx,
                max_len,
                idx_cmp_len: ComparatorChip::configure(
                    meta,
                    |meta| meta.query_fixed(q_enable, Rotation::cur()),
                    |meta| meta.query_advice(tag_idx, Rotation::cur()),
                    |meta| meta.query_advice(tag_len, Rotation::cur()),
                    u8_table.into(),
                ),
                len_cmp_max: ComparatorChip::configure(
                    meta,
                    |meta| meta.query_fixed(q_enable, Rotation::cur()),
                    |meta| meta.query_advice(tag_len, Rotation::cur()),
                    |meta| meta.query_advice(max_len, Rotation::cur()),
                    u8_table.into(),
                ),
            }
        };

        macro_rules! is_tag {
            ($var:ident, $tag_variant:ident) => {
                #[allow(unused_variables)]
                let $var = |meta: &mut VirtualCells<F>| {
                    tag_gadget
                        .tag_bits
                        .value_equals(ZstdTag::$tag_variant, Rotation::cur())(meta)
                };
            };
        }

        is_tag!(is_magic_number, MagicNumber);
        is_tag!(is_frame_header_descriptor, FrameHeaderDescriptor);
        is_tag!(is_frame_content_size, FrameContentSize);
        is_tag!(is_block_header, BlockHeader);
        is_tag!(is_raw_block, RawBlockBytes);
        is_tag!(is_rle_block, RleBlockBytes);
        is_tag!(is_zb_literals_header, ZstdBlockLiteralsHeader);
        is_tag!(is_zb_huffman_header, ZstdBlockHuffmanHeader);
        is_tag!(is_zb_fse_code, ZstdBlockFseCode);
        is_tag!(is_zb_huffman_code, ZstdBlockHuffmanCode);
        is_tag!(is_zb_jump_table, ZstdBlockJumpTable);
        is_tag!(is_lstream_1, Lstream1);
        is_tag!(is_lstream_2, Lstream2);
        is_tag!(is_lstream_3, Lstream3);
        is_tag!(is_lstream_4, Lstream4);

        meta.create_gate("DecompressionCircuit: all rows", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "is_padding is boolean",
                meta.query_advice(is_padding, Rotation::cur()),
            );

            cb.require_boolean(
                "is_padding transitions from 0 -> 1 only once",
                meta.query_advice(is_padding, Rotation::next())
                    - meta.query_advice(is_padding, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("DecompressionCircuit: all non-padded rows", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let bits = value_bits.map(|bit| meta.query_advice(bit, Rotation::cur()));

            // This is also sufficient to check that value_byte is in 0..=255
            cb.require_equal(
                "verify value byte's bits decomposition",
                meta.query_advice(value_byte, Rotation::cur()),
                bits[0].expr()
                    + 2.expr() * bits[1].expr()
                    + 4.expr() * bits[2].expr()
                    + 8.expr() * bits[3].expr()
                    + 16.expr() * bits[4].expr()
                    + 32.expr() * bits[5].expr()
                    + 64.expr() * bits[6].expr()
                    + 128.expr() * bits[7].expr(),
            );
            for bit in bits {
                cb.require_boolean("every value bit is boolean", bit.expr());
            }

            cb.require_boolean(
                "byte_idx' == byte_idx or byte_idx' == byte_idx + 1",
                meta.query_advice(byte_idx, Rotation::next())
                    - meta.query_advice(byte_idx, Rotation::cur()),
            );

            cb.require_equal(
                "encoded length remains the same",
                meta.query_advice(encoded_len, Rotation::cur()),
                meta.query_advice(encoded_len, Rotation::next()),
            );

            let byte_idx_next = meta.query_advice(byte_idx, Rotation::next());
            let byte_idx_curr = meta.query_advice(byte_idx, Rotation::cur());
            let is_new_byte = byte_idx_next - byte_idx_curr;
            let value_rlc_next = meta.query_advice(value_rlc, Rotation::next());
            let value_rlc_curr = meta.query_advice(value_rlc, Rotation::cur());
            let value_byte_next = meta.query_advice(value_byte, Rotation::next());
            cb.require_equal(
                "value_rlc' computation",
                value_rlc_next,
                select::expr(
                    is_new_byte,
                    value_rlc_curr.expr() * challenges.keccak_input() + value_byte_next,
                    value_rlc_curr,
                ),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::cur())),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        meta.lookup(
            "DecompressionCircuit: decoded byte is in U8 range",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(is_padding, Rotation::cur())),
                ]);

                vec![(
                    condition * meta.query_advice(decoded_byte, Rotation::cur()),
                    u8_table.into(),
                )]
            },
        );

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("DecompressionCircuit: first row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "value_rlc == value_byte",
                meta.query_advice(value_rlc, Rotation::cur()),
                meta.query_advice(value_byte, Rotation::cur()),
            );

            cb.require_equal(
                "byte_idx == 1",
                meta.query_advice(byte_idx, Rotation::cur()),
                1.expr(),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_fixed(q_first, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::cur())),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("DecompressionCircuit: last row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "byte_idx == encoded_len",
                meta.query_advice(byte_idx, Rotation::cur()),
                meta.query_advice(encoded_len, Rotation::cur()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_padding, Rotation::next())
                    - meta.query_advice(is_padding, Rotation::cur()),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        Self {
            q_enable,
            q_first,
            is_padding,
            byte_idx,
            encoded_len,
            value_byte,
            value_bits,
            value_rlc,
            decoded_len,
            decoded_byte,
            decoded_rlc,
            tag_gadget,
            u8_table,
        }
    }
}

/// The Decompression circuit decodes an instance of zstd compressed data.
#[derive(Clone, Debug, Default)]
pub struct DecompressionCircuit<F> {
    _data: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for DecompressionCircuit<F> {
    type Config = DecompressionCircuitConfig<F>;

    fn new_from_block(_block: &Block<F>) -> Self {
        unimplemented!()
    }

    fn min_num_rows_block(_block: &Block<F>) -> (usize, usize) {
        unimplemented!()
    }

    fn synthesize_sub(
        &self,
        _config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        _layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
