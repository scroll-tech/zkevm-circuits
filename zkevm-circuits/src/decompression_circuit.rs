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
    less_than::{LtChip, LtConfig},
    util::{and, not, select, sum, Expr},
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
    table::{
        decompression::{
            BitstringAccumulationTable, BlockTypeRomTable, FseAuxiliaryTable,
            LiteralsHeaderRomTable, LiteralsHeaderTable, TagRomTable,
        },
        KeccakTable, LookupTable, Pow2Table, PowOfRandTable, RangeTable,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{
        Block, ZstdTag, N_BITS_PER_BYTE, N_BITS_ZSTD_TAG, N_BLOCK_HEADER_BYTES, N_JUMP_TABLE_BYTES,
    },
};

/// Tables, challenge API used to configure the Decompression circuit.
pub struct DecompressionCircuitConfigArgs<F> {
    /// Challenge API.
    pub challenges: Challenges<Expression<F>>,
    /// Lookup table for FSE table by symbol.
    pub fse_aux_table: FseAuxiliaryTable<F>,
    /// Lookup table to validate bitstring values within or spanned over bytes.
    pub bs_acc_table: BitstringAccumulationTable,
    /// Lookup table to get regenerated and compressed size from LiteralsHeader.
    pub literals_header_table: LiteralsHeaderTable,
    /// RangeTable for [0, 8).
    pub range8: RangeTable<8>,
    /// RangeTable for [0; 128).
    pub range128: RangeTable<128>,
    /// U8 table, i.e. RangeTable for [0, 1 << 8).
    pub range256: RangeTable<256>,
    /// Power of 2 table.
    pub pow2_table: Pow2Table,
    /// Table from the Keccak circuit.
    pub keccak_table: KeccakTable,
    /// Power of randomness table.
    pub pow_rand_table: PowOfRandTable,
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
    /// Holds the number of bytes in the decoded data.
    decoded_len: Column<Advice>,
    /// An accumulator for the number of decoded bytes. For every byte decoded, we expect the
    /// accumulator to be incremented.
    decoded_len_acc: Column<Advice>,
    /// The byte value that is decoded at the current row. We don't decode a byte at every row. And
    /// we might end up decoding more than one bytes while the byte_idx remains the same, for
    /// instance, while processing bits and decoding the Huffman Codes.
    decoded_byte: Column<Advice>,
    /// The random linear combination of all decoded bytes up to and including the current one.
    decoded_rlc: Column<Advice>,
    /// Block level details are specified in these columns.
    block_gadget: BlockGadget<F>,
    /// All zstd tag related columns.
    tag_gadget: TagGadget<F>,
    /// Auxiliary columns, multi-purpose depending on the current tag.
    aux_fields: AuxFields,
    /// Fields used to decode from bitstream.
    bitstream_decoder: BitstreamDecoder<F>,
}

/// Block level details are specified in these columns.
#[derive(Clone, Debug)]
pub struct BlockGadget<F> {
    /// Boolean column to indicate that we are processing a block.
    is_block: Column<Advice>,
    /// The incremental index of the byte within this block.
    idx: Column<Advice>,
    /// The number of compressed bytes in the block.
    block_len: Column<Advice>,
    /// Boolean column to mark whether or not this is the last block.
    is_last_block: Column<Advice>,
    /// Check: block_idx <= block_len.
    idx_cmp_len: ComparatorConfig<F, 1>,
}

/// All tag related columns are placed in this type.
#[derive(Clone, Debug)]
pub struct TagGadget<F> {
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
    /// Whether this tag outputs a decoded byte or not.
    is_output: Column<Advice>,
    /// Whether this tag is processed from back-to-front.
    is_reverse: Column<Advice>,
    /// Randomness exponentiated by the tag's length. This is used to then accumulate the value
    /// RLC post processing of this tag.
    rand_pow_tag_len: Column<Advice>,
    /// The RLC of bytes within this tag. This is accounted for only for tags processed in reverse
    /// order.
    tag_rlc: Column<Advice>,
    /// Helper column to accumulate the RLC value of bytes within this tag. This is different from
    /// tag_value and tag_value_acc since tag_value_acc may use 256 as the multiplier for the tag
    /// value, however the tag_rlc always uses the keccak randomness.
    tag_rlc_acc: Column<Advice>,
    /// Helper gadget to check whether max_len < 0x20.
    mlen_lt_0x20: LtConfig<F, 1>,
    /// A boolean column to indicate that tag has been changed on this row.
    is_tag_change: Column<Advice>,
    /// Check: tag_idx <= tag_len.
    idx_cmp_len: ComparatorConfig<F, 1>,
    /// Check: tag_len <= max_len.
    len_cmp_max: ComparatorConfig<F, 1>,
    /// Helper column to reduce the circuit degree. Set when tag == BlockHeader.
    is_block_header: Column<Advice>,
    /// Helper column to reduce the circuit degree. Set when tag == LiteralsHeader.
    is_literals_header: Column<Advice>,
    /// Helper column to reduce the circuit degree. Set when tag == FseCode.
    is_fse_code: Column<Advice>,
}

/// Auxiliary columns that can be used for different purposes given the current tag that we are
/// decoding.
#[derive(Clone, Debug)]
pub struct AuxFields {
    /// Auxiliary column 1.
    aux1: Column<Advice>,
    /// Auxiliary column 2.
    aux2: Column<Advice>,
    /// Auxiliary column 3.
    aux3: Column<Advice>,
    /// Auxiliary column 4.
    aux4: Column<Advice>,
    /// Auxiliary column 5.
    aux5: Column<Advice>,
}

/// Fields used while decoding from bitstream while not being byte-aligned, i.e. the bitstring
/// could span over two bytes.
#[derive(Clone, Debug)]
pub struct BitstreamDecoder<F> {
    /// The bit-index where the bittsring begins. 0 <= bit_index_start < 8.
    bit_index_start: Column<Advice>,
    /// The bit-index where the bitstring ends. 0 <= bit_index_end < 16.
    bit_index_end: Column<Advice>,
    /// Helper gadget to know if the bitstring was contained in a single byte. We compare
    /// bit_index_end with 8 and if bit_index_end < 8 then the bitstring is contained. Otherwise it
    /// spans over two bytes.
    bitstream_contained: LtConfig<F, 1>,
    /// The accumulated binary value of the bitstring.
    bit_value: Column<Advice>,
    /// The symbol that this bitstring decodes to. We are using this for decoding using FSE table
    /// or a Huffman Tree. So this symbol represents the decoded value that the bitstring maps to.
    decoded_symbol: Column<Advice>,
}

impl<F: Field> SubCircuitConfig<F> for DecompressionCircuitConfig<F> {
    type ConfigArgs = DecompressionCircuitConfigArgs<F>;

    /// The layout is as follows:
    ///
    /// | Tag                     | N(bytes) | Max(N(bytes)) |
    /// |-------------------------|----------|---------------|
    /// | FrameHeaderDescriptor   | 1        | 1             |
    /// | FrameContentSize        | ?        | 8             |
    /// | BlockHeader             | 3        | 3             |
    /// | RawBlockBytes           | ?        | ?             |
    /// | BlockHeader             | 3        | 3             |
    /// | RleBlockBytes           | ?        | ?             |
    /// | BlockHeader             | 3        | 3             |
    /// | ZstdBlockLiteralsHeader | ?        | 5             |
    /// | ZstdBlockHuffmanHeader  | ?        | ?             |
    /// | ZstdBlockFseCode        | ?        | ?             |
    /// | ZstdBlockHuffmanCode    | ?        | ?             |
    /// | ZstdBlockJumpTable      | ?        | ?             |
    /// | ZstdBlockLstream        | ?        | ?             |
    /// | ZstdBlockLstream        | ?        | ?             |
    /// | ZstdBlockLstream        | ?        | ?             |
    /// | ZstdBlockLstream        | ?        | ?             |
    /// | Sequences               | ?        | ?             |
    ///
    /// The above layout is for a frame that consists of 3 blocks:
    /// - Raw Block
    /// - RLE Block
    /// - Zstd Compressed Literals Block
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            challenges,
            fse_aux_table,
            bs_acc_table,
            literals_header_table,
            range8,
            range128,
            range256,
            pow2_table,
            keccak_table: _,
            pow_rand_table,
        }: Self::ConfigArgs,
    ) -> Self {
        // Create the fixed columns read-only memory table for zstd (tag, tag_next, max_len).
        let tag_rom_table = TagRomTable::construct(meta);
        let block_type_rom_table = BlockTypeRomTable::construct(meta);
        let literals_header_rom_table = LiteralsHeaderRomTable::construct(meta);

        debug_assert!(meta.degree() <= 9);

        let q_enable = meta.fixed_column();
        let q_first = meta.fixed_column();
        let is_padding = meta.advice_column();
        let byte_idx = meta.advice_column();
        let encoded_len = meta.advice_column();
        let value_byte = meta.advice_column();
        let value_bits = array_init(|_| meta.advice_column());
        let value_rlc = meta.advice_column_in(SecondPhase);
        let decoded_len = meta.advice_column();
        let decoded_len_acc = meta.advice_column();
        let decoded_byte = meta.advice_column();
        let decoded_rlc = meta.advice_column_in(SecondPhase);
        let block_gadget = {
            let block_idx = meta.advice_column();
            let block_len = meta.advice_column();
            BlockGadget {
                is_block: meta.advice_column(),
                idx: block_idx,
                block_len,
                is_last_block: meta.advice_column(),
                idx_cmp_len: ComparatorChip::configure(
                    meta,
                    |meta| meta.query_fixed(q_enable, Rotation::cur()),
                    |meta| meta.query_advice(block_idx, Rotation::cur()),
                    |meta| meta.query_advice(block_len, Rotation::cur()),
                    range256.into(),
                ),
            }
        };
        let tag_gadget = {
            let tag = meta.advice_column();
            let tag_len = meta.advice_column();
            let tag_idx = meta.advice_column();
            let max_len = meta.advice_column();
            TagGadget {
                tag,
                tag_bits: BinaryNumberChip::configure(meta, q_enable, Some(tag.into())),
                tag_next: meta.advice_column(),
                tag_value: meta.advice_column_in(SecondPhase),
                tag_value_acc: meta.advice_column_in(SecondPhase),
                tag_len,
                tag_idx,
                rand_pow_tag_len: meta.advice_column_in(SecondPhase),
                max_len,
                is_output: meta.advice_column(),
                is_reverse: meta.advice_column(),
                tag_rlc: meta.advice_column_in(SecondPhase),
                tag_rlc_acc: meta.advice_column_in(SecondPhase),
                mlen_lt_0x20: LtChip::configure(
                    meta,
                    |meta| meta.query_fixed(q_enable, Rotation::cur()),
                    |meta| meta.query_advice(max_len, Rotation::cur()),
                    |_meta| 0x20.expr(),
                    range256.into(),
                ),
                is_tag_change: meta.advice_column(),
                idx_cmp_len: ComparatorChip::configure(
                    meta,
                    |meta| meta.query_fixed(q_enable, Rotation::cur()),
                    |meta| meta.query_advice(tag_idx, Rotation::cur()),
                    |meta| meta.query_advice(tag_len, Rotation::cur()),
                    range256.into(),
                ),
                len_cmp_max: ComparatorChip::configure(
                    meta,
                    |meta| meta.query_fixed(q_enable, Rotation::cur()),
                    |meta| meta.query_advice(tag_len, Rotation::cur()),
                    |meta| meta.query_advice(max_len, Rotation::cur()),
                    range256.into(),
                ),
                is_block_header: meta.advice_column(),
                is_literals_header: meta.advice_column(),
                is_fse_code: meta.advice_column(),
            }
        };
        let aux_fields = AuxFields {
            aux1: meta.advice_column(),
            aux2: meta.advice_column(),
            aux3: meta.advice_column(),
            aux4: meta.advice_column(),
            aux5: meta.advice_column(),
        };
        let bitstream_decoder = {
            let bit_index_end = meta.advice_column();
            BitstreamDecoder {
                bit_index_start: meta.advice_column(),
                bit_index_end,
                bitstream_contained: LtChip::configure(
                    meta,
                    |meta| meta.query_fixed(q_enable, Rotation::cur()),
                    |meta| meta.query_advice(bit_index_end, Rotation::cur()),
                    |_| 8.expr(),
                    range256.into(),
                ),
                bit_value: meta.advice_column(),
                decoded_symbol: meta.advice_column(),
            }
        };

        macro_rules! is_tag {
            ($var:ident, $tag_variant:ident) => {
                let $var = |meta: &mut VirtualCells<F>| {
                    tag_gadget
                        .tag_bits
                        .value_equals(ZstdTag::$tag_variant, Rotation::cur())(meta)
                };
            };
        }

        is_tag!(_is_null, Null);
        is_tag!(is_frame_header_descriptor, FrameHeaderDescriptor);
        is_tag!(is_frame_content_size, FrameContentSize);
        is_tag!(is_block_header, BlockHeader);
        is_tag!(is_raw_block, RawBlockBytes);
        is_tag!(is_rle_block, RleBlockBytes);
        is_tag!(is_zb_literals_header, ZstdBlockLiteralsHeader);
        is_tag!(is_zb_raw_block, ZstdBlockLiteralsRawBytes);
        is_tag!(is_zb_rle_block, ZstdBlockLiteralsRleBytes);
        is_tag!(is_zb_fse_code, ZstdBlockFseCode);
        is_tag!(is_zb_huffman_code, ZstdBlockHuffmanCode);
        is_tag!(is_zb_jump_table, ZstdBlockJumpTable);
        is_tag!(is_zb_lstream, ZstdBlockLstream);
        is_tag!(_is_zb_sequence_header, ZstdBlockSequenceHeader);

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

            cb.require_boolean(
                "is_last_block is boolean",
                meta.query_advice(block_gadget.is_last_block, Rotation::cur()),
            );

            cb.require_equal(
                "degree reduction: is_block_header check",
                is_block_header(meta),
                meta.query_advice(tag_gadget.is_block_header, Rotation::cur()),
            );

            cb.require_equal(
                "degree reduction: is_literals_header check",
                is_zb_literals_header(meta),
                meta.query_advice(tag_gadget.is_literals_header, Rotation::cur()),
            );

            cb.require_equal(
                "degree reduction: is_fse_code check",
                is_zb_fse_code(meta),
                meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
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
                select::expr(
                    meta.query_advice(tag_gadget.is_reverse, Rotation::cur()),
                    bits[7].expr()
                        + bits[6].expr() * 2.expr()
                        + bits[5].expr() * 4.expr()
                        + bits[4].expr() * 8.expr()
                        + bits[3].expr() * 16.expr()
                        + bits[2].expr() * 32.expr()
                        + bits[1].expr() * 64.expr()
                        + bits[0].expr() * 128.expr(),
                    bits[0].expr()
                        + bits[1].expr() * 2.expr()
                        + bits[2].expr() * 4.expr()
                        + bits[3].expr() * 8.expr()
                        + bits[4].expr() * 16.expr()
                        + bits[5].expr() * 32.expr()
                        + bits[6].expr() * 64.expr()
                        + bits[7].expr() * 128.expr(),
                ),
            );
            for bit in bits {
                cb.require_boolean("every value bit is boolean", bit.expr());
            }

            let is_new_byte = meta.query_advice(byte_idx, Rotation::next())
                - meta.query_advice(byte_idx, Rotation::cur());
            cb.require_boolean(
                "byte_idx' == byte_idx or byte_idx' == byte_idx + 1",
                is_new_byte.expr(),
            );

            cb.require_equal(
                "encoded length remains the same",
                meta.query_advice(encoded_len, Rotation::cur()),
                meta.query_advice(encoded_len, Rotation::next()),
            );

            cb.require_equal(
                "decoded length remains the same",
                meta.query_advice(decoded_len, Rotation::cur()),
                meta.query_advice(decoded_len, Rotation::next()),
            );

            cb.require_boolean(
                "is_tag_change is boolean",
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
            );

            // We also need to validate that ``is_tag_change`` was assigned correctly. Tag changes
            // on the next row iff:
            // - tag_idx == tag_len
            // - byte_idx' == byte_idx + 1
            let (_, tidx_eq_tlen) = tag_gadget.idx_cmp_len.expr(meta, None);
            cb.condition(and::expr([tidx_eq_tlen, is_new_byte]), |cb| {
                cb.require_equal(
                    "is_tag_change should be set",
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::next()),
                    1.expr(),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::cur())),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("DecompressionCircuit: start processing a new tag", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Whether the previous tag was processed from back-to-front.
            let was_reverse = meta.query_advice(tag_gadget.is_reverse, Rotation::prev());

            // Validations for the end of the previous tag:
            //
            // - tag_idx::prev == tag_len::prev
            // - tag_value::prev == tag_value_acc::prev
            // - tag::cur == tag_next::prev
            // - if was_reverse: tag_rlc_acc::prev == value_byte::prev
            // - if was_not_reverse: tag_rlc_acc::prev == tag_rlc::prev
            cb.require_equal(
                "tag_idx::prev == tag_len::prev",
                meta.query_advice(tag_gadget.tag_idx, Rotation::prev()),
                meta.query_advice(tag_gadget.tag_len, Rotation::prev()),
            );
            cb.require_equal(
                "tag_value::prev == tag_value_acc::prev",
                meta.query_advice(tag_gadget.tag_value, Rotation::prev()),
                meta.query_advice(tag_gadget.tag_value_acc, Rotation::prev()),
            );
            cb.require_equal(
                "tag == tag_next::prev",
                meta.query_advice(tag_gadget.tag, Rotation::cur()),
                meta.query_advice(tag_gadget.tag_next, Rotation::prev()),
            );
            cb.condition(was_reverse.expr(), |cb| {
                cb.require_equal(
                    "tag_rlc_acc on the last row for tag processed back-to-front",
                    meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::prev()),
                    meta.query_advice(value_byte, Rotation::prev()),
                );
            });
            cb.condition(not::expr(was_reverse), |cb| {
                cb.require_equal(
                    "tag_rlc_acc == tag_rlc on the last row of tag if tag processed front-to-back",
                    meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::prev()),
                    meta.query_advice(tag_gadget.tag_rlc, Rotation::prev()),
                );
            });

            // Whether the new tag is processed from back-to-front.
            let is_reverse = meta.query_advice(tag_gadget.is_reverse, Rotation::cur());

            // Validations for the new tag:
            //
            // - tag_idx == 1
            // - tag_len <= max_len(tag)
            // - tag_value_acc == value_byte
            // - value_rlc == value_rlc::prev * rand_pow_tag_len::prev + tag_rlc::prev
            // - if is_reverse: tag_rlc_acc == tag_rlc on the first row
            // - if is_not_reverse: tag_rlc_acc == value_byte
            cb.require_equal(
                "tag_idx == 1",
                meta.query_advice(tag_gadget.tag_idx, Rotation::cur()),
                1.expr(),
            );
            let (lt, eq) = tag_gadget.len_cmp_max.expr(meta, None);
            cb.require_equal("tag_len <= max_len", lt + eq, 1.expr());
            cb.require_equal(
                "tag_value_acc == value_byte",
                meta.query_advice(tag_gadget.tag_value_acc, Rotation::cur()),
                meta.query_advice(value_byte, Rotation::cur()),
            );
            cb.require_equal(
                "value_rlc calculation",
                meta.query_advice(value_rlc, Rotation::cur()),
                meta.query_advice(value_rlc, Rotation::prev())
                    * meta.query_advice(tag_gadget.rand_pow_tag_len, Rotation::prev())
                    + meta.query_advice(tag_gadget.tag_rlc, Rotation::prev()),
            );
            cb.condition(is_reverse.expr(), |cb| {
                cb.require_equal(
                    "tag_rlc_acc == tag_rlc on the first row of tag processed back-to-front",
                    meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::cur()),
                    meta.query_advice(tag_gadget.tag_rlc, Rotation::cur()),
                );
            });
            cb.condition(not::expr(is_reverse), |cb| {
                cb.require_equal(
                    "tag_rlc_acc on the first row for tag processed from front-to-back",
                    meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::cur()),
                    meta.query_advice(value_byte, Rotation::cur()),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::cur())),
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
            ]))
        });
        meta.create_gate(
            "DecompressionCircuit: processing bytes within a tag",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // The fields tag, tag_len, tag_value and value_rlc remain the same while we are
                // processing the same tag.
                for col in [
                    tag_gadget.tag,
                    tag_gadget.tag_len,
                    tag_gadget.tag_value,
                    tag_gadget.rand_pow_tag_len,
                    tag_gadget.tag_rlc,
                    value_rlc,
                ] {
                    cb.require_equal(
                        "column remains the same",
                        meta.query_advice(col, Rotation::cur()),
                        meta.query_advice(col, Rotation::prev()),
                    );
                }

                // tag_idx incremental check.
                let byte_idx_curr = meta.query_advice(byte_idx, Rotation::cur());
                let byte_idx_prev = meta.query_advice(byte_idx, Rotation::prev());
                let is_new_byte = byte_idx_curr - byte_idx_prev;
                cb.require_equal(
                    "tag_idx increments if byte_idx increments",
                    meta.query_advice(tag_gadget.tag_idx, Rotation::cur()),
                    meta.query_advice(tag_gadget.tag_idx, Rotation::prev()) + is_new_byte.expr(),
                );

                // tag_value_acc calculation.
                let tag_value_acc_prev =
                    meta.query_advice(tag_gadget.tag_value_acc, Rotation::prev());
                let value_byte_curr = meta.query_advice(value_byte, Rotation::cur());
                cb.require_equal(
                    "tag_value calculation depending on whether new byte",
                    meta.query_advice(tag_gadget.tag_value_acc, Rotation::cur()),
                    select::expr(
                        is_new_byte.expr(),
                        tag_value_acc_prev.expr() * 256.expr() + value_byte_curr.expr(),
                        tag_value_acc_prev,
                    ),
                );

                // tag_rlc_acc calculation depending on whether is_reverse or not.
                let is_reverse = meta.query_advice(tag_gadget.is_reverse, Rotation::cur());
                cb.condition(not::expr(is_new_byte.expr()), |cb| {
                    cb.require_equal(
                        "tag_rlc_acc remains the same if not a new byte",
                        meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::next()),
                        meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::cur()),
                    );
                });
                cb.condition(
                    and::expr([is_new_byte.expr(), not::expr(is_reverse.expr())]),
                    |cb| {
                        cb.require_equal(
                            "tag_rlc_acc == tag_rlc_acc::prev * r + byte",
                            meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::cur()),
                            meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::prev())
                                * challenges.keccak_input()
                                + value_byte_curr,
                        );
                    },
                );
                let value_byte_prev = meta.query_advice(value_byte, Rotation::prev());
                cb.condition(and::expr([is_new_byte, is_reverse]), |cb| {
                    cb.require_equal(
                        "tag_rlc_acc::prev = tag_rlc_acc * r + byte::prev",
                        meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::prev()),
                        meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::cur())
                            * challenges.keccak_input()
                            + value_byte_prev,
                    );
                });

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(is_padding, Rotation::cur())),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                ]))
            },
        );
        meta.lookup_any("DecompressionCircuit: randomness power tag_len", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::cur())),
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
            ]);
            [
                1.expr(),                                                        // enabled
                meta.query_advice(tag_gadget.tag_len, Rotation::cur()),          // exponent
                meta.query_advice(tag_gadget.rand_pow_tag_len, Rotation::cur()), // exponentiation
            ]
            .into_iter()
            .zip(pow_rand_table.table_exprs(meta))
            .map(|(value, table)| (condition.expr() * value, table))
            .collect()
        });

        debug_assert!(meta.degree() <= 9);

        meta.create_gate(
            "DecompressionCircuit: decoded byte when tag is output",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // TODO: There can be scenarios when ``is_output`` is set, but there may be no
                // decoded byte on that row.
                //
                // One such scenario is: If the first byte in the ZstdBlockLstream tag is
                // 0b00000001, i.e. 7 leading 0s followed by the sentinel 1 bit. Even though we
                // expect ``is_output`` to be set for the ZstdBlockLstream tag, this row itself
                // wouldn't output any decoded byte.

                cb.require_equal(
                    "decoded length accumulator increments",
                    meta.query_advice(decoded_len_acc, Rotation::cur()),
                    meta.query_advice(decoded_len_acc, Rotation::prev()) + 1.expr(),
                );

                cb.require_equal(
                    "decoded bytes RLC calculated correctly",
                    meta.query_advice(decoded_rlc, Rotation::cur()),
                    meta.query_advice(decoded_rlc, Rotation::prev()) * challenges.keccak_input()
                        + meta.query_advice(decoded_byte, Rotation::cur()),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(is_padding, Rotation::cur())),
                    meta.query_advice(tag_gadget.is_output, Rotation::cur()),
                ]))
            },
        );

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
                    range256.into(),
                )]
            },
        );

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("DecompressionCircuit: first row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "byte_idx == 1",
                meta.query_advice(byte_idx, Rotation::cur()),
                1.expr(),
            );

            cb.require_equal(
                "tag == FrameHeaderDescriptor",
                meta.query_advice(tag_gadget.tag, Rotation::cur()),
                ZstdTag::FrameHeaderDescriptor.expr(),
            );

            cb.require_zero(
                "value_rlc starts at 0",
                meta.query_advice(value_rlc, Rotation::cur()),
            );

            cb.require_zero(
                "decoded_rlc initialises at 0",
                meta.query_advice(decoded_rlc, Rotation::cur()),
            );
            cb.require_zero(
                "decoded_len_acc initialises at 0",
                meta.query_advice(decoded_len_acc, Rotation::cur()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_fixed(q_first, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::cur())),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        meta.lookup_any(
            "DecompressionCircuit: lookup for tuple (tag, tag_next, max_len, is_output)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(is_padding, Rotation::next())),
                ]);
                [
                    meta.query_advice(tag_gadget.tag, Rotation::cur()),
                    meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                    meta.query_advice(tag_gadget.max_len, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_output, Rotation::cur()),
                    meta.query_advice(block_gadget.is_block, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_reverse, Rotation::cur()),
                ]
                .into_iter()
                .zip(tag_rom_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////// ZstdTag::FrameHeaderDescriptor /////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecompressionCircuit: FrameHeaderDescriptor", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // FrameHeaderDescriptor is a single byte.
            cb.require_equal(
                "tag_idx == 1",
                meta.query_advice(tag_gadget.tag_idx, Rotation::cur()),
                1.expr(),
            );
            cb.require_equal(
                "tag_len == 1",
                meta.query_advice(tag_gadget.tag_len, Rotation::cur()),
                1.expr(),
            );
            cb.require_equal(
                "tag_value_acc == value_byte",
                meta.query_advice(tag_gadget.tag_value_acc, Rotation::cur()),
                meta.query_advice(value_byte, Rotation::cur()),
            );
            cb.require_equal(
                "tag_rlc_acc == value_byte",
                meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::cur()),
                meta.query_advice(value_byte, Rotation::cur()),
            );

            // Structure of the Frame's header descriptor.
            //
            // | Bit number | Field Name              | Expected Value |
            // |------------|-------------------------|----------------|
            // | 7-6        | Frame_Content_Size_Flag | ?              |
            // | 5          | Single_Segment_Flag     | 1              |
            // | 4          | Unused_Bit              | 0              |
            // | 3          | Reserved_Bit            | 0              |
            // | 2          | Content_Checksum_Flag   | 0              |
            // | 1-0        | Dictionary_ID_Flag      | 0              |
            cb.require_equal(
                "FHD: Single_Segment_Flag",
                meta.query_advice(value_bits[5], Rotation::cur()),
                1.expr(),
            );
            cb.require_zero(
                "FHD: Unused_Bit",
                meta.query_advice(value_bits[4], Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Reserved_Bit",
                meta.query_advice(value_bits[3], Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Content_Checksum_Flag",
                meta.query_advice(value_bits[2], Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Dictionary_ID_Flag",
                meta.query_advice(value_bits[1], Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Dictionary_ID_Flag",
                meta.query_advice(value_bits[0], Rotation::cur()),
            );

            // Checks for the next tag, i.e. FrameContentSize.
            let fcs_flag0 = meta.query_advice(value_bits[7], Rotation::cur());
            let fcs_flag1 = meta.query_advice(value_bits[6], Rotation::cur());
            let fcs_field_size = select::expr(
                fcs_flag0.expr() * fcs_flag1.expr(),
                8.expr(),
                select::expr(
                    not::expr(fcs_flag0.expr() + fcs_flag1.expr()),
                    1.expr(),
                    select::expr(fcs_flag0, 4.expr(), 2.expr()),
                ),
            );
            cb.require_equal(
                "tag_len' == fcs_field_size",
                meta.query_advice(tag_gadget.tag_len, Rotation::next()),
                fcs_field_size,
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                is_frame_header_descriptor(meta),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////// ZstdTag::FrameContentSize ////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate(
            "DecompressionCircuit: FrameContentSize (first byte)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // The previous row is FrameHeaderDescriptor.
                let fcs_flag0 = meta.query_advice(value_bits[7], Rotation::prev());
                let fcs_flag1 = meta.query_advice(value_bits[6], Rotation::prev());
                let fcs_tag_value = meta.query_advice(tag_gadget.tag_value, Rotation::cur());
                let frame_content_size = select::expr(
                    and::expr([fcs_flag0, not::expr(fcs_flag1)]),
                    256.expr() + fcs_tag_value.expr(),
                    fcs_tag_value,
                );
                cb.require_equal(
                    "decoded_len == frame_content_size",
                    frame_content_size,
                    meta.query_advice(decoded_len, Rotation::cur()),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    is_frame_content_size(meta),
                ]))
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// ZstdTag::BlockHeader ///////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////

        // Note: We only verify the 1st row of BlockHeader for tag_value.
        meta.create_gate("DecompressionCircuit: BlockHeader", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "tag_len == 3",
                meta.query_advice(tag_gadget.tag_len, Rotation::cur()),
                N_BLOCK_HEADER_BYTES.expr(),
            );

            // The lowest bit (as per little-endian representation) is whether the block is the
            // last block in the frame or not.
            //
            // The next 2 bits denote the block type.
            //
            // But block header is expressed in the reverse order, which helps us in calculating
            // the tag_value appropriately.
            cb.require_equal(
                "last block check",
                meta.query_advice(value_bits[7], Rotation(N_BLOCK_HEADER_BYTES as i32 - 1)),
                meta.query_advice(
                    block_gadget.is_last_block,
                    Rotation(N_BLOCK_HEADER_BYTES as i32),
                ),
            );
            let block_type_bit0 =
                meta.query_advice(value_bits[6], Rotation(N_BLOCK_HEADER_BYTES as i32 - 1));
            let block_type_bit1 =
                meta.query_advice(value_bits[5], Rotation(N_BLOCK_HEADER_BYTES as i32 - 1));
            cb.require_zero(
                "block type cannot be RESERVED, i.e. block_type == 3 not possible",
                block_type_bit0.expr() * block_type_bit1.expr(),
            );
            cb.require_equal(
                "block_idx == 1",
                meta.query_advice(block_gadget.idx, Rotation(N_BLOCK_HEADER_BYTES as i32)),
                1.expr(),
            );

            // For Raw/RLE blocks, the block_len is equal to the tag_len. These blocks appear with
            // block type 00 or 01, i.e. the block_type_bit1 is 0.
            cb.condition(not::expr(block_type_bit1), |cb| {
                cb.require_equal(
                    "Raw/RLE blocks: tag_len == block_len",
                    meta.query_advice(tag_gadget.tag_len, Rotation(N_BLOCK_HEADER_BYTES as i32)),
                    meta.query_advice(
                        block_gadget.block_len,
                        Rotation(N_BLOCK_HEADER_BYTES as i32),
                    ),
                );
            });

            // Validate that for an RLE block: value_byte == decoded_byte.
            cb.condition(block_type_bit0, |cb| {
                cb.require_equal(
                    "for RLE block, value_byte == decoded_byte",
                    meta.query_advice(value_byte, Rotation(N_BLOCK_HEADER_BYTES as i32)),
                    meta.query_advice(decoded_byte, Rotation(N_BLOCK_HEADER_BYTES as i32)),
                );
            });

            // If this wasn't the first block, then the previous block's last byte should have
            // block's idx == block length.
            //
            // This block is the first block iff the FrameContentSize tag precedes it. However we
            // assume that the block_idx and block_len will be set to 0 for FrameContentSize as it
            // is not part of a "block".
            cb.require_equal(
                "block_idx::prev == block_len::prev",
                meta.query_advice(block_gadget.idx, Rotation::prev()),
                meta.query_advice(block_gadget.block_len, Rotation::prev()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                meta.query_advice(tag_gadget.is_block_header, Rotation::cur()),
            ]))
        });
        meta.create_gate("DecompressionCircuit: while processing a block", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // If byte_idx increments, then block_gadet.idx should also increment.
            cb.require_equal(
                "idx in block increments if byte_idx increments",
                meta.query_advice(block_gadget.idx, Rotation::next())
                    - meta.query_advice(block_gadget.idx, Rotation::cur()),
                meta.query_advice(byte_idx, Rotation::next())
                    - meta.query_advice(byte_idx, Rotation::cur()),
            );

            cb.require_equal(
                "block_len remains unchanged",
                meta.query_advice(block_gadget.block_len, Rotation::next()),
                meta.query_advice(block_gadget.block_len, Rotation::cur()),
            );

            cb.require_equal(
                "is_last_block remains unchanged",
                meta.query_advice(block_gadget.is_last_block, Rotation::next()),
                meta.query_advice(block_gadget.is_last_block, Rotation::cur()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(block_gadget.is_block, Rotation::cur()),
                meta.query_advice(block_gadget.is_block, Rotation::next()),
            ]))
        });
        meta.create_gate("DecompressionCircuit: handle end of other blocks", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "tag_next depending on whether or not this is the last block",
                meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                ZstdTag::BlockHeader.expr(),
            );

            cb.require_equal(
                "block_idx == block_len",
                meta.query_advice(block_gadget.idx, Rotation::cur()),
                meta.query_advice(block_gadget.block_len, Rotation::cur()),
            );

            let (_, idx_eq_len) = block_gadget.idx_cmp_len.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::cur())),
                idx_eq_len,
                not::expr(meta.query_advice(block_gadget.is_last_block, Rotation::cur())),
            ]))
        });
        meta.create_gate("DecompressionCircuit: handle end of last block", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "tag_next depending on whether or not this is the last block",
                meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                ZstdTag::Null.expr(),
            );

            cb.require_equal(
                "decoded_len has been reached if last block",
                meta.query_advice(decoded_len_acc, Rotation::cur()),
                meta.query_advice(decoded_len, Rotation::cur()),
            );

            cb.require_equal(
                "byte idx has reached the encoded len",
                meta.query_advice(byte_idx, Rotation::cur()),
                meta.query_advice(encoded_len, Rotation::cur()),
            );

            cb.require_equal(
                "block can end only on Raw/Rle/TODO tag",
                sum::expr([
                    is_raw_block(meta),
                    is_rle_block(meta),
                    // TODO: there will be other tags where a block ends
                ]),
                1.expr(),
            );

            cb.require_equal(
                "block_idx == block_len",
                meta.query_advice(block_gadget.idx, Rotation::cur()),
                meta.query_advice(block_gadget.block_len, Rotation::cur()),
            );

            let (_, idx_eq_len) = block_gadget.idx_cmp_len.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::cur())),
                meta.query_advice(block_gadget.is_last_block, Rotation::cur()),
                idx_eq_len,
            ]))
        });
        meta.lookup(
            "DecompressionCircuit: BlockHeader (BlockSize == BlockHeader >> 3)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_block_header, Rotation::cur()),
                ]);
                let range_value = meta.query_advice(tag_gadget.tag_value, Rotation::cur())
                    - (meta.query_advice(
                        block_gadget.block_len,
                        Rotation(N_BLOCK_HEADER_BYTES as i32),
                    ) * 8.expr());
                vec![(condition * range_value, range8.into())]
            },
        );
        meta.lookup_any(
            "DecompressionCircuit: lookup for tuple (block_type, tag_next)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_block_header, Rotation::cur()),
                ]);
                [
                    meta.query_advice(tag_gadget.tag, Rotation::cur()),
                    meta.query_advice(value_bits[6], Rotation(N_BLOCK_HEADER_BYTES as i32 - 1)),
                    meta.query_advice(value_bits[5], Rotation(N_BLOCK_HEADER_BYTES as i32 - 1)),
                    meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                ]
                .into_iter()
                .zip(block_type_rom_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////// ZstdTag::RawBlock ////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecompressionCircuit: RawBlock", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "value byte == decoded byte",
                meta.query_advice(value_byte, Rotation::cur()),
                meta.query_advice(decoded_byte, Rotation::cur()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                is_raw_block(meta),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////// ZstdTag::RleBlock ////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////

        // Note: We do not constrain the first row of RLE block, as it is handled from the
        // BlockHeader tag.
        meta.create_gate("DecompressionCircuit: RleBlock", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "value byte == decoded byte",
                meta.query_advice(value_byte, Rotation::cur()),
                meta.query_advice(decoded_byte, Rotation::cur()),
            );

            cb.require_equal(
                "decoded byte remains the same",
                meta.query_advice(decoded_byte, Rotation::cur()),
                meta.query_advice(decoded_byte, Rotation::prev()),
            );

            cb.require_equal(
                "byte idx remains the same",
                meta.query_advice(byte_idx, Rotation::cur()),
                meta.query_advice(byte_idx, Rotation::prev()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                is_rle_block(meta),
                not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////// ZstdTag::ZstdBlockLiteralsHeader ////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate(
            "DecompressionCircuit: ZstdBlockLiteralsHeader (first byte)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                let block_type_bit0 = meta.query_advice(value_bits[7], Rotation::cur());
                let block_type_bit1 = meta.query_advice(value_bits[6], Rotation::cur());
                cb.require_zero(
                    "block type cannot be TREELESS, i.e. block_type == 3 not possible",
                    block_type_bit0 * block_type_bit1,
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_literals_header, Rotation::cur()),
                ]))
            },
        );
        meta.create_gate(
            "DecompressionCircuit: ZstdBlockLiteralsHeader (other bytes)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                for col in [
                    aux_fields.aux1,
                    aux_fields.aux2,
                    aux_fields.aux3,
                    aux_fields.aux4,
                ] {
                    cb.require_equal(
                        "aux fields remain the same",
                        meta.query_advice(col, Rotation::cur()),
                        meta.query_advice(col, Rotation::prev()),
                    );
                }

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    meta.query_advice(tag_gadget.is_literals_header, Rotation::cur()),
                ]))
            },
        );
        meta.lookup_any(
            "DecompressionCircuit: lookup for tuple (zstd_block_type, tag_next)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_literals_header, Rotation::cur()),
                ]);
                [
                    meta.query_advice(tag_gadget.tag, Rotation::cur()),
                    meta.query_advice(value_bits[7], Rotation::cur()),
                    meta.query_advice(value_bits[6], Rotation::cur()),
                    meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                ]
                .into_iter()
                .zip(block_type_rom_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );
        meta.lookup_any(
            "DecompressionCircuit: lookup for LiteralsHeader decomposition",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_literals_header, Rotation::cur()),
                ]);
                [
                    meta.query_advice(value_bits[7], Rotation::cur()), // block type bit0
                    meta.query_advice(value_bits[6], Rotation::cur()), // block type bit1
                    meta.query_advice(value_bits[5], Rotation::cur()), // size format bit0
                    meta.query_advice(value_bits[4], Rotation::cur()), // size format bit1
                    meta.query_advice(tag_gadget.tag_len, Rotation::cur()), // num bytes header
                    meta.query_advice(aux_fields.aux3, Rotation::cur()), // num of lstreams
                    meta.query_advice(aux_fields.aux4, Rotation::cur()), // branch to take
                    meta.query_advice(aux_fields.aux5, Rotation::cur()), // size_format == 0b11?
                ]
                .into_iter()
                .zip(literals_header_rom_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );
        meta.lookup_any(
            "DecompressionCircuit: lookup for LiteralsHeader regen/compr size",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_literals_header, Rotation::cur()),
                ]);

                // Which branch are we taking in the literals header decomposition.
                let branch = meta.query_advice(aux_fields.aux4, Rotation::cur());

                // Is it the case of zstd compressed block, i.e. block type == 0b10. Since we
                // already know that block type == 0b11 (TREELESS) will not occur, we can skip the
                // check for not::expr(value_bits[7]).
                let is_compressed = meta.query_advice(value_bits[6], Rotation::cur());

                // Is the size format == 0b11.
                let is_size_format_0b11 = meta.query_advice(aux_fields.aux5, Rotation::cur());

                let byte0 = meta.query_advice(value_byte, Rotation::cur());
                let byte1 = select::expr(
                    is_compressed.expr(),
                    meta.query_advice(value_byte, Rotation(1)),
                    select::expr(
                        meta.query_advice(value_bits[5], Rotation::cur()),
                        meta.query_advice(value_byte, Rotation(1)),
                        0.expr(),
                    ),
                );
                let byte2 = select::expr(
                    is_compressed.expr(),
                    meta.query_advice(value_byte, Rotation(2)),
                    select::expr(
                        meta.query_advice(value_bits[5], Rotation::cur()),
                        meta.query_advice(value_byte, Rotation(2)),
                        0.expr(),
                    ),
                );
                let byte3 = select::expr(
                    is_compressed.expr(),
                    select::expr(
                        meta.query_advice(value_bits[5], Rotation::cur()),
                        meta.query_advice(value_byte, Rotation(3)),
                        0.expr(),
                    ),
                    0.expr(),
                );
                let byte4 = select::expr(
                    is_compressed * is_size_format_0b11,
                    meta.query_advice(value_byte, Rotation(4)),
                    0.expr(),
                );

                [
                    meta.query_advice(byte_idx, Rotation::cur()), // byte offset
                    branch,                                       // branch
                    byte0,                                        // byte0
                    byte1,                                        // byte1
                    byte2,                                        // byte2
                    byte3,                                        // byte3
                    byte4,                                        // byte4
                    meta.query_advice(aux_fields.aux1, Rotation::cur()), // regenerated size
                    meta.query_advice(aux_fields.aux2, Rotation::cur()), // compressed size
                ]
                .into_iter()
                .zip(literals_header_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////// ZstdTag::ZstdBlockLiteralsRawBytes ////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecompressionCircuit: ZstdBlock Raw bytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "value_byte == decoded_byte",
                meta.query_advice(value_byte, Rotation::cur()),
                meta.query_advice(decoded_byte, Rotation::cur()),
            );

            cb.condition(
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "tag_len == regen_size",
                        meta.query_advice(tag_gadget.tag_len, Rotation::cur()),
                        meta.query_advice(aux_fields.aux1, Rotation::prev()),
                    );
                },
            );

            cb.require_equal(
                "byte_idx increments",
                meta.query_advice(byte_idx, Rotation::cur()),
                meta.query_advice(byte_idx, Rotation::prev()) + 1.expr(),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                is_zb_raw_block(meta),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////// ZstdTag::ZstdBlockLiteralsRleBytes ////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecompressionCircuit: ZstdBlock RLE bytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "value_byte == decoded_byte",
                meta.query_advice(value_byte, Rotation::cur()),
                meta.query_advice(decoded_byte, Rotation::cur()),
            );

            let is_tag_change = meta.query_advice(tag_gadget.is_tag_change, Rotation::cur());
            cb.condition(is_tag_change.expr(), |cb| {
                cb.require_equal(
                    "tag_len == regen_size",
                    meta.query_advice(tag_gadget.tag_len, Rotation::cur()),
                    meta.query_advice(aux_fields.aux1, Rotation::prev()),
                );
            });

            cb.condition(not::expr(is_tag_change), |cb| {
                cb.require_equal(
                    "byte_idx remains the same",
                    meta.query_advice(byte_idx, Rotation::cur()),
                    meta.query_advice(byte_idx, Rotation::prev()),
                );
                cb.require_equal(
                    "decoded byte remains the same",
                    meta.query_advice(decoded_byte, Rotation::cur()),
                    meta.query_advice(decoded_byte, Rotation::prev()),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                is_zb_rle_block(meta),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////// ZstdTag::ZstdBlockFseCode ///////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate(
            "DecompressionCircuit: ZstdBlockFseCode (huffman header)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // The huffman header is a single byte, which we have included as a part of the
                // FSE code tag. We expect value_byte < 128 because the huffman code is encoded
                // using an FSE code. The value of this byte is actually the number of bytes taken
                // to represent the huffman data.
                //
                // In our case, this means the tag length of FSE code and the tag length of Huffman
                // code together should equate to the value of this byte.
                //
                // Note: tag_len + tag_len::tag_next == value_byte + 1. The added 1 includes this
                // byte (huffman header) itself.
                let tag_len_fse_code = meta.query_advice(tag_gadget.tag_len, Rotation::cur());
                let tag_len_huffman_code = meta.query_advice(aux_fields.aux1, Rotation::cur());
                cb.require_equal(
                    "huffman header value byte check",
                    meta.query_advice(value_byte, Rotation::cur()) + 1.expr(),
                    tag_len_fse_code + tag_len_huffman_code,
                );

                // The huffman tree description starts at this byte index. We identify the FSE and
                // Huffman tables using this byte index. We store this in auxiliary field aux3.
                cb.require_equal(
                    "huffman header byte offset assignment",
                    meta.query_advice(byte_idx, Rotation::cur()),
                    meta.query_advice(aux_fields.aux3, Rotation::cur()),
                );

                // We know that the next byte is the start of processing bitstream to construct the
                // FSE table. The first 4 bits are used to calculate the accuracy log (and the
                // table size) of the table. So the first bitstring that's decoded starts from
                // bit_index 4 (considering that it is 0-indexed).
                cb.require_equal(
                    "bit_index_start of the first bitstring",
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::next()),
                    4.expr(),
                );

                // At every row, a new symbol is decoded. This symbol stands for the weight in the
                // canonical Huffman code representation. So we start at symbol == S0, i.e. 0 and
                // increment until we've decoded the last symbol that has a weight. Any symbols
                // beyond that will have a weight of 0.
                cb.require_zero(
                    "first symbol that is decoded in FSE is S0, i.e. 0",
                    meta.query_advice(bitstream_decoder.decoded_symbol, Rotation::next()),
                );
                // We use the aux5 column as an accumulator for the number of times each symbol
                // appears. At the end of decoding the accumulator should match the table size.
                //
                // The number of times a symbol appears is R - 1, where R is the binary value read
                // from the bitstring.
                cb.require_equal(
                    "symbol count accumulator",
                    meta.query_advice(aux_fields.aux5, Rotation::next()) + 1.expr(),
                    meta.query_advice(bitstream_decoder.bit_value, Rotation::next()),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                ]))
            },
        );
        meta.lookup("DecompressionCircuit: huffman header byte value", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
            ]);
            let range_value = meta.query_advice(value_byte, Rotation::cur());
            vec![(condition * range_value, range128.into())]
        });
        meta.lookup_any(
            "DecompressionCircuit: table size == 1 << accuracy log",
            |meta| {
                // We know that the next byte is the first byte of the FSE code. The first 4 bits
                // contribute to the accuracy log of the FSE table.
                //
                // We use aux2 to hold the table size of the FSE table, i.e. 1 << accuracy_log.
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                ]);
                let accuracy_log = meta.query_advice(value_bits[0], Rotation::next())
                    + meta.query_advice(value_bits[1], Rotation::next()) * 2.expr()
                    + meta.query_advice(value_bits[2], Rotation::next()) * 4.expr()
                    + meta.query_advice(value_bits[3], Rotation::next()) * 8.expr()
                    + 5.expr();
                [
                    accuracy_log,
                    meta.query_advice(aux_fields.aux2, Rotation::next()),
                ]
                .into_iter()
                .zip(pow2_table.table_exprs(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );
        meta.create_gate(
            "DecompressionCircuit: ZstdBlockFseCode (fse code)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // - The auxiliary field aux1 is used to mark the tag length of the next tag
                // (ZstdBlockHuffmanCode). We want to make sure it remains the same throughout this
                // tag.
                //
                // - aux2 is used to denote the table size of the FSE table, i.e. 1 << AL.
                //
                // - aux3 is used to denote the byte offset at which the huffman tree description
                // started, i.e. the byte offset of the huffman header.
                for col in [aux_fields.aux1, aux_fields.aux2, aux_fields.aux3] {
                    cb.require_equal(
                        "aux fields remains the same",
                        meta.query_advice(col, Rotation::cur()),
                        meta.query_advice(col, Rotation::prev()),
                    );
                }

                // The decoded symbol keeps incrementing in the FSE code reconstruction. Since
                // we've already done the check for the first symbol in the huffman header gate, we
                // only check for increments.
                let is_last = meta.query_advice(tag_gadget.is_tag_change, Rotation::next());
                cb.condition(not::expr(is_last.expr()), |cb| {
                    cb.require_equal(
                        "fse table reconstruction: decoded symbol increments",
                        meta.query_advice(bitstream_decoder.decoded_symbol, Rotation::cur())
                            + 1.expr(),
                        meta.query_advice(bitstream_decoder.decoded_symbol, Rotation::next()),
                    );
                    cb.require_equal(
                        "number of times a symbol appears is accumulated correctly",
                        meta.query_advice(aux_fields.aux5, Rotation::next()) + 1.expr(),
                        meta.query_advice(aux_fields.aux5, Rotation::cur())
                            + meta.query_advice(bitstream_decoder.bit_value, Rotation::next()),
                    );
                });
                cb.condition(is_last, |cb| {
                    cb.require_equal(
                        "on the last row, accumulated number of symbols is the table size of FSE table",
                        meta.query_advice(aux_fields.aux5, Rotation::cur()),
                        meta.query_advice(aux_fields.aux2, Rotation::cur()),
                    );
                });

                // The next bitstring to be decoded should start right after the current bitstring
                // ends, i.e. bit_index_start' == bit_index_end + 1.
                //
                // However, we have 0 <= bit_index_end < 16. So we want to check:
                // - bit_index_start' == (bit_index_end % 8) + 1.
                let bit_index_end =
                    meta.query_advice(bitstream_decoder.bit_index_end, Rotation::cur());
                let bit_index_end_mod8 = select::expr(
                    bitstream_decoder.bitstream_contained.is_lt(meta, None),
                    bit_index_end.expr(),
                    bit_index_end - 8.expr(),
                );
                cb.require_equal(
                    "start of next bitstring is right after the end of the current",
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::next()),
                    bit_index_end_mod8 + 1.expr(),
                );

                // The check that bit_index_end >= bit_index_start is indirectly verified through
                // the lookup to the HuffmanCodesBitstringAccumulationTable, since the bit_index in
                // that table is a fixed column.

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                ]))
            },
        );
        meta.lookup_any(
            "DecompressionCircuit: ZstdBlockFseCode (contained bitstream start)",
            |meta| {
                let (huffman_tree_byte_offset, start, bit_value) = (
                    meta.query_advice(aux_fields.aux3, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()),
                );
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    bitstream_decoder.bitstream_contained.is_lt(meta, None),
                ]);
                [
                    huffman_tree_byte_offset,                       // huffman tree byte offset
                    meta.query_advice(byte_idx, Rotation::cur()),   // byte index
                    meta.query_advice(value_byte, Rotation::cur()), // byte value
                    bit_value,                                      // bitstring value
                    1.expr(), // bitstring length accumulator, starts at 1
                    start,    // bit index start
                    1.expr(), // denotes that this bit index is a part of the bitstring
                    1.expr(), // denotes that this bit index is a part of the bitstring
                    meta.query_advice(tag_gadget.is_reverse, Rotation::cur()), // is reverse
                ]
                .into_iter()
                .zip(bs_acc_table.table_exprs_contained(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );
        meta.lookup_any(
            "DecompressionCircuit: ZstdBlockFseCode (contained bitstream end)",
            |meta| {
                let (start, end, bit_value) = (
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.bit_index_end, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()),
                );
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    bitstream_decoder.bitstream_contained.is_lt(meta, None),
                ]);
                [
                    meta.query_advice(aux_fields.aux3, Rotation::cur()), // huffman byte offset
                    meta.query_advice(byte_idx, Rotation::cur()),        // byte index
                    meta.query_advice(value_byte, Rotation::cur()),      // byte value
                    bit_value,                                           // bitstring value
                    end.expr() - start + 1.expr(),                       // bitstring length
                    end,                                                 // bit index at end
                    1.expr(),                                            // from start
                    1.expr(),                                            // to end
                    meta.query_advice(tag_gadget.is_reverse, Rotation::cur()), // is reverse
                ]
                .into_iter()
                .zip(bs_acc_table.table_exprs_contained(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );
        meta.lookup_any(
            "DecompressionCircuit: ZstdBlockFseCode (spanned bitstream start)",
            |meta| {
                let (start, bit_value) = (
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()),
                );
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    not::expr(bitstream_decoder.bitstream_contained.is_lt(meta, None)),
                ]);
                [
                    meta.query_advice(aux_fields.aux3, Rotation::cur()), // huffman byte offset
                    meta.query_advice(byte_idx, Rotation::cur()),        // byte index
                    meta.query_advice(byte_idx, Rotation::next()),       // byte index'
                    meta.query_advice(value_byte, Rotation::cur()),      // byte value
                    meta.query_advice(value_byte, Rotation::next()),     // byte value'
                    bit_value,                                           // bitstring value
                    1.expr(),                                            // bitstring len acc
                    start,                                               // bit index start
                    1.expr(),                                            // from start
                    1.expr(),                                            // to end
                    meta.query_advice(tag_gadget.is_reverse, Rotation::cur()), //  is reverse
                ]
                .into_iter()
                .zip(bs_acc_table.table_exprs_spanned(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );
        meta.lookup_any(
            "DecompressionCircuit: ZstdBlockFseCode (spanned bitstring end)",
            |meta| {
                let (start, end, bit_value) = (
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.bit_index_end, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()),
                );
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    not::expr(bitstream_decoder.bitstream_contained.is_lt(meta, None)),
                ]);
                [
                    meta.query_advice(aux_fields.aux3, Rotation::cur()), // huffman byte offset
                    meta.query_advice(byte_idx, Rotation::cur()),        // byte index
                    meta.query_advice(byte_idx, Rotation::next()),       // byte index'
                    meta.query_advice(value_byte, Rotation::cur()),      // byte value
                    meta.query_advice(value_byte, Rotation::next()),     // byte value'
                    bit_value,                                           // bitstring value
                    end.expr() - start + 1.expr(),                       // bitstring length
                    end,                                                 // bit index at end
                    1.expr(),                                            // from start
                    1.expr(),                                            // to end
                    meta.query_advice(tag_gadget.is_reverse, Rotation::cur()), // is reverse
                ]
                .into_iter()
                .zip(bs_acc_table.table_exprs_spanned(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );
        meta.lookup_any(
            "DecompressionCircuit: ZstdBlockFseCode (symbol count check)",
            |meta| {
                let (bit_value, decoded_symbol) = (
                    meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.decoded_symbol, Rotation::cur()),
                );
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                ]);
                // The FSE table reconstruction follows a variable bit packing. However we know the
                // start and end bit index for the bitstring that was read. We read a value in the
                // range 0..=R+1 and then subtract 1 from it to get N, i.e. the number of slots
                // that were allocated to that symbol in the FSE table. This is also the count of
                // the symbol in the FseAuxiliaryTable.
                [
                    meta.query_advice(aux_fields.aux3, Rotation::cur()), // huffman byte offset
                    meta.query_advice(aux_fields.aux2, Rotation::cur()), // table size
                    decoded_symbol,                                      // decoded symbol.
                    bit_value - 1.expr(),                                // symbol count
                ]
                .into_iter()
                .zip(fse_aux_table.table_exprs_symbol_count_check(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////// ZstdTag::ZstdBlockHuffmanCode /////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate(
            "DecompressionCircuit: ZstdBlockHuffmanCode (huffman code bitstream)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // Check that the aux1 field was assigned correctly for the FseCode tag. This field
                // should equal the tag length of the HuffmanCode tag.
                cb.condition(
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    |cb| {
                        cb.require_equal(
                            "aux field aux1 is the tag_len of the next tag",
                            meta.query_advice(aux_fields.aux1, Rotation::prev()),
                            meta.query_advice(tag_gadget.tag_len, Rotation::cur()),
                        );
                    },
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    is_zb_huffman_code(meta),
                ]))
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////// ZstdTag::ZstdBlockJumpTable ///////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecompressionCircuit: ZstdBlockJumpTable", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "tag_len == 6",
                meta.query_advice(tag_gadget.tag_len, Rotation::cur()),
                N_JUMP_TABLE_BYTES.expr(),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                is_zb_jump_table(meta),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////// ZstdTag::ZstdBlockLstream ////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecompressionCircuit: ZstdBlockLstream", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero("dummy constraint", 0.expr());

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                is_zb_lstream(meta),
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
            decoded_len_acc,
            decoded_byte,
            decoded_rlc,
            block_gadget,
            tag_gadget,
            aux_fields,
            bitstream_decoder,
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
