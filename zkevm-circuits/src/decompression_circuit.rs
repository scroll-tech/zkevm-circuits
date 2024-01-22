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
        decompression::{BlockTypeRomTable, LiteralsHeaderRomTable, TagRomTable},
        KeccakTable, LookupTable, Pow2Table, RangeTable, U8Table,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{Block, ZstdTag, N_BITS_PER_BYTE, N_BITS_ZSTD_TAG, N_BLOCK_HEADER_BYTES},
};

/// Tables, challenge API used to configure the Decompression circuit.
pub struct DecompressionCircuitConfigArgs<F> {
    /// Challenge API.
    pub challenges: Challenges<Expression<F>>,
    /// U8 table, i.e. RangeTable for [0, 1 << 8).
    pub u8_table: U8Table,
    /// RangeTable for [0, 8).
    pub range_table_0x08: RangeTable<8>,
    /// Power of 2 table.
    pub pow2_table: Pow2Table,
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
    block_gadget: BlockGadget,
    /// All zstd tag related columns.
    tag_gadget: TagGadget<F>,
    /// Columns used to process bytes back-to-front.
    reverse_chunk: ReverseChunk,
    /// Auxiliary columns, multi-purpose depending on the current tag.
    aux_fields: AuxFields,

    /// The range table to check value is byte.
    u8_table: U8Table,
}

/// Block level details are specified in these columns.
#[derive(Clone, Debug)]
pub struct BlockGadget {
    /// Boolean column to indicate that we are processing a block.
    is_block: Column<Advice>,
    /// The incremental index of the byte within this block.
    idx: Column<Advice>,
    /// The number of compressed bytes in the block.
    block_len: Column<Advice>,
    /// Boolean column to mark whether or not this is the last block.
    is_last_block: Column<Advice>,
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
    /// Helper gadget to check whether max_len < 0x20.
    mlen_lt_0x20: LtConfig<F, 1>,
    /// A boolean column to indicate that tag has been changed on this row.
    is_tag_change: Column<Advice>,
    /// Check: tag_idx <= tag_len.
    idx_cmp_len: ComparatorConfig<F, 1>,
    /// Check: tag_len <= max_len.
    len_cmp_max: ComparatorConfig<F, 1>,
}

/// Columns related to processing little-endian chunk of bytes.
#[derive(Clone, Debug)]
pub struct ReverseChunk {
    /// Boolean indicator whether we are processing a chunk of bytes in back-to-front order, i.e.
    /// little endian representation.
    is_reverse: Column<Advice>,
    /// The number of bytes in this reverse chunk.
    r_len: Column<Advice>,
    /// The reverse index within this chunk, that starts at r_len and decrements to 1 on the final
    /// byte of the chunk.
    r_idx: Column<Advice>,
    /// Stores the value_rlc that was seen just before the start of the reverse chunk.
    value_rlc_before: Column<Advice>,
    /// Stores the value_rlc for bytes in this chunk.
    value_rlc_chunk: Column<Advice>,
    /// Stores the value for randomness ^ (r_len + 1).
    rand_pow: Column<Advice>,
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
            u8_table,
            range_table_0x08,
            pow2_table,
            keccak_table: _,
        }: Self::ConfigArgs,
    ) -> Self {
        // Create the fixed columns read-only memory table for zstd (tag, tag_next, max_len).
        let tag_rom_table = TagRomTable::construct(meta);
        let block_type_rom_table = BlockTypeRomTable::construct(meta);
        let literals_header_rom_table = LiteralsHeaderRomTable::construct(meta);

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
        let block_gadget = BlockGadget {
            is_block: meta.advice_column(),
            idx: meta.advice_column(),
            block_len: meta.advice_column(),
            is_last_block: meta.advice_column(),
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
                max_len,
                is_output: meta.advice_column(),
                mlen_lt_0x20: LtChip::configure(
                    meta,
                    |meta| meta.query_fixed(q_enable, Rotation::cur()),
                    |meta| meta.query_advice(max_len, Rotation::cur()),
                    |_meta| 0x20.expr(),
                    u8_table.into(),
                ),
                is_tag_change: meta.advice_column(),
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
        let reverse_chunk = ReverseChunk {
            is_reverse: meta.advice_column(),
            r_len: meta.advice_column(),
            r_idx: meta.advice_column(),
            value_rlc_before: meta.advice_column_in(SecondPhase),
            value_rlc_chunk: meta.advice_column_in(SecondPhase),
            rand_pow: meta.advice_column(),
        };
        let aux_fields = AuxFields {
            aux1: meta.advice_column(),
            aux2: meta.advice_column(),
            aux3: meta.advice_column(),
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

        is_tag!(is_null, Null);
        is_tag!(is_frame_header_descriptor, FrameHeaderDescriptor);
        is_tag!(is_frame_content_size, FrameContentSize);
        is_tag!(is_block_header, BlockHeader);
        is_tag!(is_raw_block, RawBlockBytes);
        is_tag!(is_rle_block, RleBlockBytes);
        is_tag!(is_zb_literals_header, ZstdBlockLiteralsHeader);
        is_tag!(is_zb_raw_block, ZstdBlockLiteralsRawBytes);
        is_tag!(is_zb_rle_block, ZstdBlockLiteralsRleBytes);
        is_tag!(is_zb_huffman_code, ZstdBlockHuffmanCode);
        is_tag!(is_zb_jump_table, ZstdBlockJumpTable);
        is_tag!(is_zb_lstream, ZstdBlockLstream);
        is_tag!(is_zb_sequence_header, ZstdBlockSequenceHeader);

        let constrain_value_rlc =
            |meta: &mut VirtualCells<F>, cb: &mut BaseConstraintBuilder<F>, is_reverse: bool| {
                let byte_idx_curr = meta.query_advice(byte_idx, Rotation::cur());
                let byte_idx_next = meta.query_advice(byte_idx, Rotation::next());
                let is_new_byte = byte_idx_next - byte_idx_curr;

                let value_rlc_curr = meta.query_advice(value_rlc, Rotation::cur());
                let value_rlc_next = meta.query_advice(value_rlc, Rotation::next());

                if is_reverse {
                    let value_byte_curr = meta.query_advice(value_byte, Rotation::cur());
                    cb.require_equal(
                        "value_rlc' in reverse chunk",
                        value_rlc_curr,
                        select::expr(
                            is_new_byte.expr(),
                            value_rlc_next.expr() * challenges.keccak_input() + value_byte_curr,
                            value_rlc_next,
                        ),
                    );
                } else {
                    let value_byte_next = meta.query_advice(value_byte, Rotation::next());
                    cb.require_equal(
                        "value_rlc' in normal chunk",
                        value_rlc_next,
                        select::expr(
                            is_new_byte,
                            value_rlc_curr.expr() * challenges.keccak_input() + value_byte_next,
                            value_rlc_curr,
                        ),
                    );
                }
            };

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
                "reverse is boolean",
                meta.query_advice(reverse_chunk.is_reverse, Rotation::cur()),
            );

            cb.require_boolean(
                "is_block is boolean",
                meta.query_advice(block_gadget.is_block, Rotation::cur()),
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

            cb.require_equal(
                "decoded length remains the same",
                meta.query_advice(decoded_len, Rotation::cur()),
                meta.query_advice(decoded_len, Rotation::next()),
            );

            cb.condition(
                and::expr([
                    not::expr(meta.query_advice(reverse_chunk.is_reverse, Rotation::cur())),
                    not::expr(meta.query_advice(reverse_chunk.is_reverse, Rotation::next())),
                ]),
                |cb| {
                    constrain_value_rlc(meta, cb, false);
                },
            );

            let is_tag_change = meta.query_advice(tag_gadget.is_tag_change, Rotation::cur());
            cb.require_boolean("is_tag_change is boolean", is_tag_change.expr());
            cb.condition(is_tag_change, |cb| {
                cb.require_equal(
                    "tag_idx == 1",
                    meta.query_advice(tag_gadget.tag_idx, Rotation::cur()),
                    1.expr(),
                );
                cb.require_equal(
                    "tag_value_acc == byte value",
                    meta.query_advice(tag_gadget.tag_value_acc, Rotation::cur()),
                    meta.query_advice(value_byte, Rotation::cur()),
                );
                cb.require_equal(
                    "tag == tag_next::prev",
                    meta.query_advice(tag_gadget.tag, Rotation::cur()),
                    meta.query_advice(tag_gadget.tag_next, Rotation::prev()),
                );
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
                let (lt, eq) = tag_gadget.len_cmp_max.expr(meta, None);
                cb.require_equal("tag_len <= max_len", lt + eq, 1.expr());
            });

            // We also ensure that is_tag_change was in fact assigned True when the tag changed.
            // The tag changes on the next row iff tag_idx == tag_len.
            //
            // And validate tag_value_acc calculation.
            let (tidx_lt_tlen, tidx_eq_tlen) = tag_gadget.idx_cmp_len.expr(meta, None);
            cb.require_equal(
                "is_tag_change' == True",
                meta.query_advice(tag_gadget.is_tag_change, Rotation::next()),
                tidx_eq_tlen,
            );
            cb.condition(tidx_lt_tlen, |cb| {
                // tag_value_acc changes only when byte_idx increments.
                let tag_value_acc_curr =
                    meta.query_advice(tag_gadget.tag_value_acc, Rotation::cur());
                let tag_value_acc_next =
                    meta.query_advice(tag_gadget.tag_value_acc, Rotation::next());
                let byte_idx_curr = meta.query_advice(byte_idx, Rotation::cur());
                let byte_idx_next = meta.query_advice(byte_idx, Rotation::next());
                let is_new_byte = byte_idx_next - byte_idx_curr;

                // tag_value_acc is accumulated using either 256 or keccak_randomness, depending on
                // the max_len of this tag.
                let multiplier = select::expr(
                    tag_gadget.mlen_lt_0x20.is_lt(meta, None),
                    256.expr(),
                    challenges.keccak_input(),
                );
                cb.require_equal(
                    "tag_value_acc' check",
                    tag_value_acc_next,
                    select::expr(
                        is_new_byte,
                        tag_value_acc_curr.expr() * multiplier
                            + meta.query_advice(value_byte, Rotation::next()),
                        tag_value_acc_curr,
                    ),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::cur())),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        meta.create_gate(
            "DecompressionCircuit: decoded byte when tag is output",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

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

            cb.require_equal(
                "tag == FrameHeaderDescriptor",
                meta.query_advice(tag_gadget.tag, Rotation::cur()),
                ZstdTag::FrameHeaderDescriptor.expr(),
            );

            cb.require_zero(
                "is_reverse == 0 on first compressed byte",
                meta.query_advice(reverse_chunk.is_reverse, Rotation::cur()),
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

        meta.lookup_any(
            "DecompressionCircuit: lookup for tuple (tag, tag_next, max_len, is_output)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(is_padding, Rotation::next())),
                ]);
                vec![
                    meta.query_advice(tag_gadget.tag, Rotation::cur()),
                    meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                    meta.query_advice(tag_gadget.max_len, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_output, Rotation::cur()),
                ]
                .into_iter()
                .zip(tag_rom_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////// Processing bytes back-to-front ///////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate(
            "DecompressionCircuit: reverse chunk boundary begin",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                cb.require_equal(
                    "value_rlc' == value_rlc_chunk'",
                    meta.query_advice(value_rlc, Rotation::next()),
                    meta.query_advice(reverse_chunk.value_rlc_chunk, Rotation::next()),
                );

                cb.require_equal(
                    "value_rlc_before' == value_rlc",
                    meta.query_advice(reverse_chunk.value_rlc_before, Rotation::next()),
                    meta.query_advice(value_rlc, Rotation::cur()),
                );

                cb.require_equal(
                    "r_idx' == r_len'",
                    meta.query_advice(reverse_chunk.r_idx, Rotation::next()),
                    meta.query_advice(reverse_chunk.r_len, Rotation::next()),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(is_padding, Rotation::next())),
                    not::expr(meta.query_advice(reverse_chunk.is_reverse, Rotation::cur())),
                    meta.query_advice(reverse_chunk.is_reverse, Rotation::next()),
                ]))
            },
        );

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("DecompressionCircuit: reverse chunk boundary end", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "r_idx == 1",
                meta.query_advice(reverse_chunk.r_idx, Rotation::cur()),
                1.expr(),
            );

            cb.require_equal(
                "value_rlc == value_byte",
                meta.query_advice(value_rlc, Rotation::cur()),
                meta.query_advice(value_byte, Rotation::cur()),
            );

            let rlc_before_chunk =
                meta.query_advice(reverse_chunk.value_rlc_before, Rotation::cur());
            let rand_pow = meta.query_advice(reverse_chunk.rand_pow, Rotation::cur());
            let rlc_chunk = meta.query_advice(reverse_chunk.value_rlc_chunk, Rotation::cur());
            cb.require_equal(
                "value_rlc' at reverse boundary end",
                meta.query_advice(value_rlc, Rotation::next()),
                rlc_before_chunk * rand_pow
                    + rlc_chunk * challenges.keccak_input()
                    + meta.query_advice(value_byte, Rotation::next()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::next())),
                meta.query_advice(reverse_chunk.is_reverse, Rotation::cur()),
                not::expr(meta.query_advice(reverse_chunk.is_reverse, Rotation::next())),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        meta.lookup_any(
            "DecompressionCircuit: rand ^ (r_len + 1) check at boundary end",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(is_padding, Rotation::next())),
                    meta.query_advice(reverse_chunk.is_reverse, Rotation::cur()),
                    not::expr(meta.query_advice(reverse_chunk.is_reverse, Rotation::next())),
                ]);

                [
                    meta.query_advice(reverse_chunk.r_len, Rotation::cur()) + 1.expr(),
                    meta.query_advice(reverse_chunk.rand_pow, Rotation::cur()),
                ]
                .into_iter()
                .zip(pow2_table.table_exprs(meta))
                .map(|(input, table)| (input * condition.clone(), table))
                .collect::<Vec<_>>()
            },
        );

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("DecompressionCircuit: reverse chunk", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "value_rlc_before unchanged",
                meta.query_advice(reverse_chunk.value_rlc_before, Rotation::cur()),
                meta.query_advice(reverse_chunk.value_rlc_before, Rotation::next()),
            );

            cb.require_equal(
                "value_rlc_chunk unchanged",
                meta.query_advice(reverse_chunk.value_rlc_chunk, Rotation::cur()),
                meta.query_advice(reverse_chunk.value_rlc_chunk, Rotation::next()),
            );

            cb.require_equal(
                "r_len unchanged",
                meta.query_advice(reverse_chunk.r_len, Rotation::cur()),
                meta.query_advice(reverse_chunk.r_len, Rotation::next()),
            );

            // value_rlc updates only if byte_idx' == byte_idx + 1.
            constrain_value_rlc(meta, &mut cb, true /* reverse */);

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::next())),
                meta.query_advice(reverse_chunk.is_reverse, Rotation::cur()),
                meta.query_advice(reverse_chunk.is_reverse, Rotation::next()),
            ]))
        });

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

        // Note: We only verify the 1st row of FrameContentSize for tag_value.
        meta.create_gate("DecompressionCircuit: FrameContentSize", |meta| {
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
        });

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
            cb.require_equal(
                "last block check",
                meta.query_advice(value_bits[7], Rotation::cur()),
                meta.query_advice(
                    block_gadget.is_last_block,
                    Rotation(N_BLOCK_HEADER_BYTES as i32),
                ),
            );
            let block_type_bit0 = meta.query_advice(value_bits[6], Rotation::cur());
            let block_type_bit1 = meta.query_advice(value_bits[5], Rotation::cur());
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
            // This block is the first block iff the FrameContentSize tag precedes it.
            cb.condition(
                not::expr(tag_gadget
                    .tag_bits
                    .value_equals(ZstdTag::FrameContentSize, Rotation::prev())(
                    meta
                )),
                |cb| {
                    cb.require_equal(
                        "block_idx::prev == block_len::prev",
                        meta.query_advice(block_gadget.idx, Rotation::prev()),
                        meta.query_advice(block_gadget.block_len, Rotation::prev()),
                    );
                },
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                is_block_header(meta),
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
        meta.create_gate("DecompressionCircuit: handle last block", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_last_block = meta.query_advice(block_gadget.is_last_block, Rotation::cur());
            cb.require_equal(
                "tag_next depending on whether or not this is the last block",
                meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                select::expr(
                    is_last_block.expr(),
                    ZstdTag::Null.expr(),
                    ZstdTag::BlockHeader.expr(),
                ),
            );
            cb.condition(is_last_block, |cb| {
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
            });

            let (_lt, tidx_eq_tlen) = tag_gadget.idx_cmp_len.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding, Rotation::cur())),
                tidx_eq_tlen,
                sum::expr([
                    is_raw_block(meta),
                    is_rle_block(meta),
                    // TODO: block can end after ZstdSequence also
                ]),
            ]))
        });
        meta.lookup(
            "DecompressionCircuit: BlockHeader (BlockSize == BlockHeader >> 3)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    is_block_header(meta),
                ]);
                let range_value = meta.query_advice(tag_gadget.tag_value, Rotation::cur())
                    - (meta.query_advice(
                        block_gadget.block_len,
                        Rotation(N_BLOCK_HEADER_BYTES as i32),
                    ) * 8.expr());
                vec![(condition * range_value, range_table_0x08.into())]
            },
        );
        meta.lookup_any(
            "DecompressionCircuit: lookup for tuple (block_type, tag_next)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    is_block_header(meta),
                ]);
                vec![
                    meta.query_advice(tag_gadget.tag, Rotation::cur()),
                    meta.query_advice(value_bits[6], Rotation::cur()),
                    meta.query_advice(value_bits[5], Rotation::cur()),
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
                "is_block == True",
                meta.query_advice(block_gadget.is_block, Rotation::cur()),
                1.expr(),
            );

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
                "is_block == True",
                meta.query_advice(block_gadget.is_block, Rotation::cur()),
                1.expr(),
            );

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
        meta.create_gate("DecompressionCircuit: ZstdBlockLiteralsHeader", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_block == True",
                meta.query_advice(block_gadget.is_block, Rotation::cur()),
                1.expr(),
            );

            let block_type_bit0 = meta.query_advice(value_bits[7], Rotation::cur());
            let block_type_bit1 = meta.query_advice(value_bits[6], Rotation::cur());
            cb.require_zero(
                "block type cannot be TREELESS, i.e. block_type == 3 not possible",
                block_type_bit0 * block_type_bit1,
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                is_zb_literals_header(meta),
            ]))
        });
        meta.lookup_any(
            "DecompressionCircuit: lookup for tuple (zstd_block_type, tag_next)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    is_zb_literals_header(meta),
                ]);
                vec![
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
                    is_zb_literals_header(meta),
                ]);
                vec![
                    meta.query_advice(value_bits[7], Rotation::cur()), // block type bit0
                    meta.query_advice(value_bits[6], Rotation::cur()), // block type bit1
                    meta.query_advice(value_bits[5], Rotation::cur()), // size format bit0
                    meta.query_advice(value_bits[4], Rotation::cur()), // size format bit1
                    meta.query_advice(aux_fields.aux1, Rotation::cur()), // regenerated size
                    meta.query_advice(aux_fields.aux2, Rotation::cur()), // compressed size
                    meta.query_advice(tag_gadget.tag_len, Rotation::cur()), /* size of literals
                                                                             * header */
                    meta.query_advice(aux_fields.aux3, Rotation::cur()), // number of lstreams
                ]
                .into_iter()
                .zip(literals_header_rom_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////// ZstdTag::ZstdBlockHuffmanCode /////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecompressionCircuit: ZstdBlockHuffmanCode", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_block == True",
                meta.query_advice(block_gadget.is_block, Rotation::cur()),
                1.expr(),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                is_zb_huffman_code(meta),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////// ZstdTag::ZstdBlockJumpTable ///////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecompressionCircuit: ZstdBlockJumpTable", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_block == True",
                meta.query_advice(block_gadget.is_block, Rotation::cur()),
                1.expr(),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                is_zb_jump_table(meta),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////// ZstdTag::ZstdBlockLstream ////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecompressionCircuit: ZstdBlockLstream", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_block == True",
                meta.query_advice(block_gadget.is_block, Rotation::cur()),
                1.expr(),
            );

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
            reverse_chunk,
            aux_fields,
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
