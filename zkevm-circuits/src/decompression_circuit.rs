//! This circuit decodes zstd compressed data.

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;

#[cfg(any(feature = "test", test))]
mod test;

use std::marker::PhantomData;

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{
        decompression::{
            BitstringAccumulationTable, BlockTypeRomTable, DecodedLiteralsTable, FseTable,
            HuffmanCodesTable, LiteralsHeaderRomTable, LiteralsHeaderTable, TagRomTable,
        },
        BitwiseOpTable, KeccakTable, LookupTable, Pow2Table, PowOfRandTable, RangeTable,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::{
        process, value_bits_le, Block, FseAuxiliaryTableData, HuffmanCodesData, LstreamNum,
        ZstdTag, ZstdWitnessRow, N_BITS_PER_BYTE, N_BITS_ZSTD_TAG, N_BLOCK_HEADER_BYTES,
        N_JUMP_TABLE_BYTES,
    },
};
use array_init::array_init;
use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig, ComparatorInstruction},
    less_than::{LtChip, LtConfig, LtInstruction},
    util::{and, not, select, sum, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, VirtualCells,
    },
    poly::Rotation,
};

/// Tables, challenge API used to configure the Decompression circuit.
pub struct DecompressionCircuitConfigArgs<F> {
    /// Challenge API.
    pub challenges: Challenges<Expression<F>>,
    /// Lookup table for FSE table by symbol.
    pub fse_table: FseTable<F>,
    /// Lookup table for Huffman codes, to check the canonical weight and the decoded symbol.
    pub huffman_codes_table: HuffmanCodesTable<F>,
    /// Lookup table to validate bitstring values within or spanned over bytes.
    pub bs_acc_table: BitstringAccumulationTable,
    /// Lookup table to get regenerated and compressed size from LiteralsHeader.
    pub literals_header_table: LiteralsHeaderTable,
    /// Lookup table to validate decoded literal bytes.
    pub decoded_literals_table: DecodedLiteralsTable<F>,
    /// Bitwise OP table.
    pub bitwise_op_table: BitwiseOpTable,
    /// RangeTable for [0, 4).
    pub range4: RangeTable<4>,
    /// RangeTable for [0, 8).
    pub range8: RangeTable<8>,
    /// RangeTable for [0, 16).
    pub range16: RangeTable<16>,
    /// RangeTable for [0, 64).
    pub range64: RangeTable<64>,
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
    /// The byte value decoded at the current row. We don't decode a byte at every row.
    /// And we might end up decoding more than one bytes while the byte_idx remains the
    /// same, for instance, while processing bits and decoding the Huffman Codes.
    decoded_byte: Column<Advice>,
    /// Holds the number of bytes in the decoded data.
    decoded_len: Column<Advice>,
    /// An accumulator for the number of decoded bytes. For every byte decoded, we expect the
    /// accumulator to be incremented.
    decoded_len_acc: Column<Advice>,
    /// The random linear combination of all decoded bytes up to and including the current one.
    decoded_rlc: Column<Advice>,
    /// Block level details are specified in these columns.
    block_gadget: BlockGadget<F>,
    /// All zstd tag related columns.
    tag_gadget: TagGadget<F>,
    /// Decomposition of the Literals Header.
    literals_header: LiteralsHeaderDecomposition,
    /// Huffman tree's config.
    huffman_tree_config: HuffmanConfig,
    /// Fields used to decode from bitstream.
    bitstream_decoder: BitstreamDecoder<F>,
    /// Fields related to the application of FSE table to bitstream.
    fse_decoder: FseDecoder,
    /// Literal stream tag related configs.
    lstream_config: LstreamConfig,

    /// Internal Tables
    bitwise_op_table: BitwiseOpTable,
    range4: RangeTable<4>,
    range8: RangeTable<8>,
    range16: RangeTable<16>,
    range64: RangeTable<64>,
    range128: RangeTable<128>,
    range256: RangeTable<256>,
    tag_rom_table: TagRomTable,
    pow_rand_table: PowOfRandTable,
    block_type_rom_table: BlockTypeRomTable,
    pow2_table: Pow2Table,
    literals_header_rom_table: LiteralsHeaderRomTable,
    literals_header_table: LiteralsHeaderTable,
    bitstring_accumulation_table: BitstringAccumulationTable,
    fse_table: FseTable<F>,
    huffman_codes_table: HuffmanCodesTable<F>,
    decoded_literals_table: DecodedLiteralsTable<F>,
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
    // Check: block_idx <= block_len.
    idx_cmp_len: ComparatorConfig<F, 1>,
}

/// All tag related columns are placed in this type.
#[derive(Clone, Debug)]
pub struct TagGadget<F> {
    /// The zstd tag at the current row.
    tag: Column<Advice>,
    // Helper gadget to construct equality constraints against the current tag.
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
    mlen_lt_0x20: LtConfig<F, 3>,
    /// A boolean column to indicate that tag has been changed on this row.
    is_tag_change: Column<Advice>,
    // Check: tag_idx <= tag_len.
    idx_cmp_len: ComparatorConfig<F, 3>,
    // Check: tag_len <= max_len.
    len_cmp_max: ComparatorConfig<F, 3>,
    /// Helper column to reduce the circuit degree. Set when tag == BlockHeader.
    is_block_header: Column<Advice>,
    /// Helper column to reduce the circuit degree. Set when tag == LiteralsHeader.
    is_literals_header: Column<Advice>,
    /// Helper column to reduce the circuit degree. Set when tag == FseCode.
    is_fse_code: Column<Advice>,
    /// Helper column to reduce the circuit degree. Set when tag == HuffmanCode.
    is_huffman_code: Column<Advice>,
    /// Helper column to reduce the circuit degree. Set when tag == Lstream.
    is_lstream: Column<Advice>,
    /// Helper column to reduce the circuit degree. Set when we are in the Literals section, i.e.
    /// for all tags in [LiteralsHeader, FseCode, HuffmanCode, JumpTable, Lstream].
    is_literals_section: Column<Advice>,
    /// Helper column to reduce the circuit degree. Set when we are in the Huffman tree section,
    /// i.e. for all tags in [FseCode, HuffmanCode, Jumptable, Lstream].
    is_huffman_tree_section: Column<Advice>,
}

/// Columns that hold values decomposed from the Literals Header.
#[derive(Clone, Debug)]
struct LiteralsHeaderDecomposition {
    /// The branch we take while decomposing the Literals Header. We compare this value against the
    /// Read-only memory table for Literals Header.
    branch: Column<Advice>,
    /// A helper column to mark whether the size format (sf) for Literals Header is 0b_11. We need
    /// this column to keep the circuit degree in check.
    sf_max: Column<Advice>,
    /// The regenerated size decoded from the Literals Header.
    regen_size: Column<Advice>,
    /// The compressed size decoded from the Literals Header.
    compr_size: Column<Advice>,
}

impl LiteralsHeaderDecomposition {
    fn columns(&self) -> Vec<Column<Advice>> {
        vec![self.branch, self.sf_max, self.regen_size, self.compr_size]
    }
}

/// Huffman tree description.
#[derive(Clone, Debug)]
struct HuffmanConfig {
    /// Column to save the byte offset at which the huffman header is described.
    huffman_tree_idx: Column<Advice>,
    /// The table size of the FSE table.
    fse_table_size: Column<Advice>,
    /// The accuracy log of the FSE table.
    fse_table_al: Column<Advice>,
    /// The number of bytes used to specify canonical huffman code representation.
    huffman_code_len: Column<Advice>,
}

/// Fields used while decoding from bitstream while not being byte-aligned, i.e. the bitstring
/// could span over two bytes.
#[derive(Clone, Debug)]
pub struct BitstreamDecoder<F> {
    /// Boolean that is set for the special case that we don't read from the bitstream, i.e. we
    /// read 0 number of bits. This case can only occur while processing the
    /// tag=ZstdBlockHuffmanCode.
    is_nil: Column<Advice>,
    /// The bit-index where the bittsring begins. 0 <= bit_index_start < 8.
    bit_index_start: Column<Advice>,
    /// The bit-index where the bitstring ends. 0 <= bit_index_end < 16.
    bit_index_end: Column<Advice>,
    /// Helper gadget to know if the bitstring was contained in a single byte. We compare
    /// bit_index_end with 8 and if bit_index_end < 8 then the bitstring is contained. Otherwise it
    /// spans over two bytes.
    bitstring_contained: ComparatorConfig<F, 1>,
    /// The accumulated binary value of the bitstring.
    bit_value: Column<Advice>,
    /// The symbol that this bitstring decodes to. We are using this for decoding using FSE table
    /// or a Huffman Tree. So this symbol represents the decoded value that the bitstring maps to.
    decoded_symbol: Column<Advice>,
}

impl<F: Field> BitstreamDecoder<F> {
    fn is_contained(
        &self,
        meta: &mut VirtualCells<F>,
        rotation: Option<Rotation>,
    ) -> Expression<F> {
        let (lt, eq) = self.bitstring_contained.expr(meta, rotation);
        sum::expr([lt, eq])
    }

    fn is_strictly_contained(
        &self,
        meta: &mut VirtualCells<F>,
        rotation: Option<Rotation>,
    ) -> Expression<F> {
        let (lt, _eq) = self.bitstring_contained.expr(meta, rotation);
        lt
    }

    fn is_byte_aligned(
        &self,
        meta: &mut VirtualCells<F>,
        rotation: Option<Rotation>,
    ) -> Expression<F> {
        let (_lt, eq) = self.bitstring_contained.expr(meta, rotation);
        eq
    }

    fn is_spanned(&self, meta: &mut VirtualCells<F>, rotation: Option<Rotation>) -> Expression<F> {
        not::expr(self.is_contained(meta, rotation))
    }
}

/// Fields related to application of the FSE table.
#[derive(Clone, Debug)]
pub struct FseDecoder {
    /// The FSE state we are at.
    state: Column<Advice>,
    /// The baseline value at ``state``.
    baseline: Column<Advice>,
    /// The symbol emitted while transitioning from ``state`` to a new state.
    symbol: Column<Advice>,
    /// Number of symbols we have emitted.
    num_emitted: Column<Advice>,
    /// An accumulator that keeps a count of the number of states assigned for each symbol,
    /// including the symbol that is decoded on the current row.
    n_acc: Column<Advice>,
}

/// Configuration related to literal streams.
#[derive(Clone, Debug)]
struct LstreamConfig {
    /// A boolean used to identify whether we will have a single literal stream or 4 literal
    /// streams. It is set when we have 4 literal streams.
    lstream_kind: Column<Advice>,
    /// The Lstream type we are currently processing.
    lstream: Column<Advice>,
    /// The Lstream type we are currently processing.
    lstream_num: BinaryNumberConfig<LstreamNum, 2>,
    /// Number of bytes in Lstream1.
    len_lstream1: Column<Advice>,
    /// Number of bytes in Lstream2.
    len_lstream2: Column<Advice>,
    /// Number of bytes in Lstream3.
    len_lstream3: Column<Advice>,
    /// Number of bytes in Lstream4.
    len_lstream4: Column<Advice>,
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
    /// | ZstdBlockFseCode        | ?        | ?             |
    /// | ZstdBlockHuffmanCode    | ?        | ?             |
    /// | ZstdBlockJumpTable      | ?        | ?             |
    /// | ZstdBlockLstream        | ?        | ?             |
    /// | ZstdBlockLstream        | ?        | ?             |
    /// | ZstdBlockLstream        | ?        | ?             |
    /// | ZstdBlockLstream        | ?        | ?             |
    /// | ZstdBlockSequenceHeader | ?        | ?             |
    ///
    /// The above layout is for a frame that consists of 3 blocks:
    /// - Raw Block
    /// - RLE Block
    /// - Zstd Compressed Literals Block
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            challenges,
            fse_table,
            huffman_codes_table,
            bs_acc_table,
            literals_header_table,
            decoded_literals_table,
            bitwise_op_table,
            range4,
            range8,
            range16,
            range64,
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
        let decoded_byte = meta.advice_column();
        let decoded_len = meta.advice_column();
        let decoded_len_acc = meta.advice_column();
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
                is_huffman_code: meta.advice_column(),
                is_lstream: meta.advice_column(),
                is_literals_section: meta.advice_column(),
                is_huffman_tree_section: meta.advice_column(),
            }
        };
        let literals_header = LiteralsHeaderDecomposition {
            branch: meta.advice_column(),
            sf_max: meta.advice_column(),
            regen_size: meta.advice_column(),
            compr_size: meta.advice_column(),
        };
        let huffman_tree_config = HuffmanConfig {
            huffman_tree_idx: meta.advice_column(),
            fse_table_size: meta.advice_column(),
            fse_table_al: meta.advice_column(),
            huffman_code_len: meta.advice_column(),
        };
        let bitstream_decoder = {
            let bit_index_end = meta.advice_column();
            BitstreamDecoder {
                is_nil: meta.advice_column(),
                bit_index_start: meta.advice_column(),
                bit_index_end,
                bitstring_contained: ComparatorChip::configure(
                    meta,
                    |meta| meta.query_fixed(q_enable, Rotation::cur()),
                    |meta| meta.query_advice(bit_index_end, Rotation::cur()),
                    |_| 7.expr(),
                    range256.into(),
                ),
                bit_value: meta.advice_column(),
                decoded_symbol: meta.advice_column(),
            }
        };
        let fse_decoder = FseDecoder {
            state: meta.advice_column(),
            baseline: meta.advice_column(),
            symbol: meta.advice_column(),
            num_emitted: meta.advice_column(),
            n_acc: meta.advice_column(),
        };
        let lstream = meta.advice_column();
        let lstream_config = LstreamConfig {
            lstream_kind: meta.advice_column(),
            lstream,
            lstream_num: BinaryNumberChip::configure(meta, q_enable, Some(lstream.into())),
            len_lstream1: meta.advice_column(),
            len_lstream2: meta.advice_column(),
            len_lstream3: meta.advice_column(),
            len_lstream4: meta.advice_column(),
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

            // Boolean columns.
            for col in [
                is_padding,
                block_gadget.is_last_block,
                bitstream_decoder.is_nil,
            ] {
                cb.require_boolean(
                    "Boolean column check",
                    meta.query_advice(col, Rotation::cur()),
                );
            }

            cb.require_boolean(
                "is_padding transitions from 0 -> 1 only once",
                meta.query_advice(is_padding, Rotation::next())
                    - meta.query_advice(is_padding, Rotation::cur()),
            );

            // Degree reduction columns.
            macro_rules! degree_reduction_check {
                ($column:expr, $expr:expr) => {
                    cb.require_equal(
                        "Degree reduction column check",
                        meta.query_advice($column, Rotation::cur()),
                        $expr,
                    );
                };
            }
            degree_reduction_check!(tag_gadget.is_block_header, is_block_header(meta));
            degree_reduction_check!(tag_gadget.is_literals_header, is_zb_literals_header(meta));
            degree_reduction_check!(tag_gadget.is_fse_code, is_zb_fse_code(meta));
            degree_reduction_check!(tag_gadget.is_huffman_code, is_zb_huffman_code(meta));
            degree_reduction_check!(tag_gadget.is_lstream, is_zb_lstream(meta));
            degree_reduction_check!(
                tag_gadget.is_literals_section,
                sum::expr([
                    meta.query_advice(tag_gadget.is_literals_header, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_huffman_code, Rotation::cur()),
                    is_zb_jump_table(meta),
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                ])
            );
            degree_reduction_check!(
                tag_gadget.is_huffman_tree_section,
                sum::expr([
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_huffman_code, Rotation::cur()),
                    is_zb_jump_table(meta),
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                ])
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

            let is_new_byte = meta.query_advice(byte_idx, Rotation::cur())
                - meta.query_advice(byte_idx, Rotation::prev());

            cb.require_boolean(
                "byte_idx' == byte_idx or byte_idx' == byte_idx + 1",
                is_new_byte.expr(),
            );

            cb.require_equal(
                "encoded length remains the same",
                meta.query_advice(encoded_len, Rotation::cur()),
                meta.query_advice(encoded_len, Rotation::prev()),
            );

            cb.require_equal(
                "decoded length remains the same",
                meta.query_advice(decoded_len, Rotation::cur()),
                meta.query_advice(decoded_len, Rotation::prev()),
            );

            cb.require_boolean(
                "is_tag_change is boolean",
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
            );

            // If we don't encounter a new byte, the byte value should stay the same.
            cb.condition(not::expr(is_new_byte.expr()), |cb| {
                cb.require_equal(
                    "value_byte' == value_byte if not a new byte",
                    meta.query_advice(value_byte, Rotation::prev()),
                    meta.query_advice(value_byte, Rotation::cur()),
                );
            });

            // We also need to validate that ``is_tag_change`` was assigned correctly. Tag changes
            // on the next row iff:
            // - tag_idx == tag_len
            // - byte_idx' == byte_idx + 1
            let is_next_new_byte = meta.query_advice(byte_idx, Rotation::next())
                - meta.query_advice(byte_idx, Rotation::cur());
            let (_, tidx_eq_tlen) = tag_gadget.idx_cmp_len.expr(meta, None);
            cb.condition(and::expr([tidx_eq_tlen, is_next_new_byte]), |cb| {
                cb.require_equal(
                    "is_tag_change should be set",
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::next()),
                    1.expr(),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(q_first, Rotation::cur())),
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
                not::expr(meta.query_fixed(q_first, Rotation::cur())),
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
                let multiplier = select::expr(
                    tag_gadget.mlen_lt_0x20.is_lt(meta, None),
                    256.expr(),
                    challenges.keccak_input(),
                );
                let tag_value_acc_prev =
                    meta.query_advice(tag_gadget.tag_value_acc, Rotation::prev());
                let value_byte_curr = meta.query_advice(value_byte, Rotation::cur());

                cb.require_equal(
                    "tag_value calculation depending on whether new byte",
                    meta.query_advice(tag_gadget.tag_value_acc, Rotation::cur()),
                    select::expr(
                        is_new_byte.expr(),
                        tag_value_acc_prev.expr() * multiplier + value_byte_curr.expr(),
                        tag_value_acc_prev,
                    ),
                );

                // tag_rlc_acc calculation depending on whether is_reverse or not.
                let is_reverse = meta.query_advice(tag_gadget.is_reverse, Rotation::cur());
                cb.condition(not::expr(is_new_byte.expr()), |cb| {
                    cb.require_equal(
                        "tag_rlc_acc remains the same if not a new byte",
                        meta.query_advice(tag_gadget.tag_rlc_acc, Rotation::prev()),
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
                    not::expr(meta.query_fixed(q_first, Rotation::cur())),
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

                // There can be scenarios when ``is_output`` is set, but there may be no decoded
                // byte on that row.
                //
                // One such scenario is the first row of the Lstream tag, which is used to mark the
                // leading 0s and sentinel bit.
                let is_sentinel = and::expr([
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                ]);

                cb.require_equal(
                    "decoded length accumulator increments",
                    meta.query_advice(decoded_len_acc, Rotation::cur()),
                    meta.query_advice(decoded_len_acc, Rotation::prev())
                        + not::expr(is_sentinel.expr()),
                );

                cb.require_equal(
                    "decoded bytes RLC calculated correctly",
                    meta.query_advice(decoded_rlc, Rotation::cur()),
                    select::expr(
                        is_sentinel,
                        meta.query_advice(decoded_rlc, Rotation::prev()),
                        meta.query_advice(decoded_rlc, Rotation::prev())
                            * challenges.keccak_input()
                            + meta.query_advice(decoded_byte, Rotation::cur()),
                    ),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(is_padding, Rotation::cur())),
                    meta.query_advice(tag_gadget.is_output, Rotation::cur()),
                ]))
            },
        );

        debug_assert!(meta.degree() <= 9);

        meta.lookup("DecompressionCircuit: value byte is in U8 range", |meta| {
            vec![(
                meta.query_fixed(q_enable, Rotation::cur())
                    * meta.query_advice(value_byte, Rotation::cur()),
                range256.into(),
            )]
        });
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
                    and::expr([not::expr(fcs_flag0), fcs_flag1]),
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

        // TODO: Block constraints will be examined later
        // Note: We only verify the 1st row of BlockHeader for tag_value.

        /*
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
            // For Raw/RLE blocks, the block_len is equal to the tag_len. These blocks appear
            // with block type 00 or 01, i.e. the block_type_bit1 is 0.
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
            // assume that the block_idx and block_len will be set to 0 for FrameContentSize as
            // it is not part of a "block".
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
        */

        /*
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
        */

        /*
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
        */

        /*
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
        */

        /*
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
        */

        meta.lookup_any(
            "DecompressionCircuit: lookup for tuple (block_type, tag_next)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_block_header, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                ]);
                [
                    meta.query_advice(tag_gadget.tag, Rotation::cur()),
                    meta.query_advice(value_bits[5], Rotation(N_BLOCK_HEADER_BYTES as i32 - 1)),
                    meta.query_advice(value_bits[6], Rotation(N_BLOCK_HEADER_BYTES as i32 - 1)),
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

                let block_type_bit0 = meta.query_advice(value_bits[0], Rotation::cur());
                let block_type_bit1 = meta.query_advice(value_bits[1], Rotation::cur());
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

        meta.lookup_any(
            "DecompressionCircuit: lookup for tuple (zstd_block_type, tag_next)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_literals_header, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                ]);
                [
                    meta.query_advice(tag_gadget.tag, Rotation::cur()),
                    meta.query_advice(value_bits[1], Rotation::cur()),
                    meta.query_advice(value_bits[0], Rotation::cur()),
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
                    meta.query_advice(value_bits[0], Rotation::cur()), // block type bit0
                    meta.query_advice(value_bits[1], Rotation::cur()), // block type bit1
                    meta.query_advice(value_bits[2], Rotation::cur()), // size format bit0
                    meta.query_advice(value_bits[3], Rotation::cur()), // size format bit1
                    meta.query_advice(tag_gadget.tag_len, Rotation::cur()), // num bytes header
                    meta.query_advice(lstream_config.lstream_kind, Rotation::cur()), // 1 or 4
                    meta.query_advice(literals_header.branch, Rotation::cur()), // branch
                    meta.query_advice(literals_header.sf_max, Rotation::cur()), // size format 0b11
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
                    meta.query_advice(tag_gadget.is_literals_header, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                ]);

                // Which branch are we taking in the literals header decomposition.
                let branch = meta.query_advice(literals_header.branch, Rotation::cur());

                // Is it the case of zstd compressed block, i.e. block type == 0b10. Since we
                // already know that block type == 0b11 (TREELESS) will not occur, we can skip
                // the check for not::expr(value_bits[0]).
                let is_compressed = meta.query_advice(value_bits[1], Rotation::cur());

                // Is the size format == 0b11.
                let is_size_format_0b11 =
                    meta.query_advice(literals_header.sf_max, Rotation::cur());
                let size_format_bit0 = meta.query_advice(value_bits[2], Rotation::cur());
                let size_format_bit1 = meta.query_advice(value_bits[3], Rotation::cur());

                // Literals header is at least 1 byte for all branches.
                let byte0 = meta.query_advice(value_byte, Rotation::cur());
                // Literals header is at least 2 bytes for:
                // - zstd compressed block
                // - size format 01 / 11 for Raw/RLE block
                let byte1 = select::expr(
                    is_compressed.expr(),
                    meta.query_advice(value_byte, Rotation(1)),
                    select::expr(
                        size_format_bit0.expr(),
                        meta.query_advice(value_byte, Rotation(1)),
                        0.expr(),
                    ),
                );
                // Literals header is at least 3 bytes for:
                // - zstd compressed block
                // - size format 11 for Raw/RLE block
                let byte2 = select::expr(
                    is_compressed.expr(),
                    meta.query_advice(value_byte, Rotation(2)),
                    select::expr(
                        is_size_format_0b11.expr(),
                        meta.query_advice(value_byte, Rotation(2)),
                        0.expr(),
                    ),
                );
                // Literals header is at least 4 bytes for:
                // - zstd compressed block with size format 10 / 11
                let byte3 = select::expr(
                    is_compressed.expr() * size_format_bit1.expr(),
                    meta.query_advice(value_byte, Rotation(3)),
                    0.expr(),
                );
                // Literals header is 5 bytes for:
                // - zstd compressed block with size format 11
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
                    meta.query_advice(literals_header.regen_size, Rotation::cur()),
                    meta.query_advice(literals_header.compr_size, Rotation::cur()),
                ]
                .into_iter()
                .zip(literals_header_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        meta.create_gate("DecompressionCircuit: LiteralsSection", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Since these values are assigned at the LiteralsHeader row, we skip the check on that
            // row itself.
            let is_literals_header = and::expr([
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                meta.query_advice(tag_gadget.is_literals_header, Rotation::cur()),
            ]);
            cb.condition(not::expr(is_literals_header), |cb| {
                for col in literals_header.columns() {
                    cb.require_equal(
                        "literals header helper columns unchanged",
                        meta.query_advice(col, Rotation::cur()),
                        meta.query_advice(col, Rotation::prev()),
                    );
                }
                cb.require_equal(
                    "lstream kind remains unchanged",
                    meta.query_advice(lstream_config.lstream_kind, Rotation::cur()),
                    meta.query_advice(lstream_config.lstream_kind, Rotation::prev()),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(tag_gadget.is_literals_section, Rotation::cur()),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////// ZstdTag::ZstdBlockLiteralsRawBytes ////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecompressionCircuit: ZstdBlock Raw bytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_first = meta.query_advice(tag_gadget.is_tag_change, Rotation::cur());
            cb.condition(is_first, |cb| {
                cb.require_equal(
                    "tag_len == regen_size",
                    meta.query_advice(tag_gadget.tag_len, Rotation::cur()),
                    meta.query_advice(literals_header.regen_size, Rotation::prev()),
                );
            });
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

            let is_first = meta.query_advice(tag_gadget.is_tag_change, Rotation::cur());
            cb.condition(is_first.expr(), |cb| {
                cb.require_equal(
                    "tag_len == regen_size",
                    meta.query_advice(tag_gadget.tag_len, Rotation::cur()),
                    meta.query_advice(literals_header.regen_size, Rotation::prev()),
                );
            });
            cb.condition(not::expr(is_first), |cb| {
                cb.require_equal(
                    "byte_idx remains the same",
                    meta.query_advice(byte_idx, Rotation::cur()),
                    meta.query_advice(byte_idx, Rotation::prev()),
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
                let tag_len_huffman_code =
                    meta.query_advice(huffman_tree_config.huffman_code_len, Rotation::cur());

                cb.require_equal(
                    "huffman header value byte check",
                    meta.query_advice(value_byte, Rotation::cur()) + 1.expr(),
                    tag_len_fse_code + tag_len_huffman_code,
                );

                // The huffman tree description starts at this byte index. We identify the FSE and
                // Huffman tables using this byte index.
                cb.require_equal(
                    "huffman header byte offset assignment",
                    meta.query_advice(byte_idx, Rotation::cur()),
                    meta.query_advice(huffman_tree_config.huffman_tree_idx, Rotation::cur()),
                );

                // We know that the next byte is the start of processing bitstream to construct the
                // FSE table. The first 4 bits are used to calculate the accuracy log (and the
                // table size) of the table. So the first bitstring that's decoded starts from
                // bit_index 4 (considering that it is 0-indexed).
                cb.require_equal(
                    "accuracy log read from bits [0, 4)",
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::next()),
                    0.expr(),
                );
                cb.require_equal(
                    "accuracy log read from bits [0, 4)",
                    meta.query_advice(bitstream_decoder.bit_index_end, Rotation::next()),
                    3.expr(),
                );

                // At every row, a new symbol is decoded. This symbol stands for the weight in the
                // canonical Huffman code representation. So we start at symbol == S0, i.e. 0 and
                // increment until we've decoded the last symbol that has a weight. Any symbols
                // beyond that will have a weight of 0.
                cb.require_zero(
                    "first symbol that is decoded in FSE is S0, i.e. 0",
                    meta.query_advice(bitstream_decoder.decoded_symbol, Rotation::next()),
                );
                // We use an accumulator for the number of times each symbol appears. At the end of
                // decoding the accumulator should match the table size.
                //
                // The number of times a symbol appears is R - 1, where R is the binary value read
                // from the bitstring.
                cb.require_zero(
                    "symbol count accumulator initialisation",
                    meta.query_advice(fse_decoder.n_acc, Rotation::cur()),
                );

                // Check that the decoded accuracy log is correct.
                cb.require_equal(
                    "accuracy log check",
                    meta.query_advice(huffman_tree_config.fse_table_al, Rotation::next()),
                    meta.query_advice(bitstream_decoder.bit_value, Rotation::next()) + 5.expr(),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
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
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                ]);
                [
                    meta.query_advice(huffman_tree_config.fse_table_al, Rotation::next()),
                    meta.query_advice(huffman_tree_config.fse_table_size, Rotation::next()),
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

                // The decoded symbol keeps incrementing in the FSE code reconstruction. Since
                // we've already done the check for the first symbol in the huffman header gate, we
                // only check for increments.
                let is_last = meta.query_advice(tag_gadget.is_tag_change, Rotation::next());

                cb.condition(not::expr(is_last.clone()), |cb| {
                    cb.require_equal(
                        "number of states assigned so far is accumulated correctly",
                        meta.query_advice(fse_decoder.n_acc, Rotation::cur()),
                        meta.query_advice(fse_decoder.n_acc, Rotation::prev())
                            + (meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()) - 1.expr()),
                    );
                });
                cb.condition(is_last, |cb| {
                    cb.require_equal(
                        "on the last row, accumulated number of symbols is the table size of FSE table",
                        meta.query_advice(fse_decoder.n_acc, Rotation::cur()),
                        meta.query_advice(huffman_tree_config.fse_table_size, Rotation::cur()),
                    );
                });

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::prev())),
                ]))
            },
        );

        meta.lookup_any(
            "DecompressionCircuit: ZstdBlockFseCode (symbol count check)",
            |meta| {
                let (huffman_byte_offset, bit_value, decoded_symbol) = (
                    meta.query_advice(huffman_tree_config.huffman_tree_idx, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.decoded_symbol, Rotation::cur()),
                );
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())), // Exclude huffman header byte
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::prev())), // Exclude accuracy log bits
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::next())), // Exclude trailing bits
                ]);
                // The FSE table reconstruction follows a variable bit packing. However we know the
                // start and end bit index for the bitstring that was read. We read a value in the
                // range 0..=R+1 and then subtract 1 from it to get N, i.e. the number of slots
                // that were allocated to that symbol in the FSE table. This is also the count of
                // the symbol in the FseTable.
                [
                    huffman_byte_offset,                                           // huffman ID
                    meta.query_advice(huffman_tree_config.fse_table_size, Rotation::cur()), // table size
                    decoded_symbol,       // decoded symbol.
                    bit_value - 1.expr(), // symbol count
                ]
                .into_iter()
                .zip(fse_table.table_exprs_symbol_count_check(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );

        meta.create_gate("DecompressionCircuit: HuffmanTreeSection", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Since these values are assigned at the Huffman header row, we skip check on that
            // row.
            let is_huffman_header = and::expr([
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
            ]);
            cb.condition(not::expr(is_huffman_header), |cb| {
                for col in [
                    huffman_tree_config.huffman_tree_idx,
                    huffman_tree_config.huffman_code_len,
                    huffman_tree_config.fse_table_al,
                    huffman_tree_config.fse_table_size,
                ] {
                    cb.require_equal(
                        "huffman tree helper columns unchanged",
                        meta.query_advice(col, Rotation::cur()),
                        meta.query_advice(col, Rotation::prev()),
                    );
                }
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(tag_gadget.is_huffman_tree_section, Rotation::cur()),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////// ZstdTag::ZstdBlockHuffmanCode /////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////

        meta.create_gate(
            "DecompressionCircuit: ZstdBlockHuffmanCode (first row)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // - The first row of the HuffmanCode tag is the leading 0s and sentinel bit.
                // - The second row of the HuffmanCode tag is the reading of AL number of bits from
                // the bitstream to find the initial state in the FSE table and emit the first
                // symbol.
                cb.require_equal(
                    "num_emitted starts at 1 from the second row",
                    meta.query_advice(fse_decoder.num_emitted, Rotation::next()),
                    1.expr(),
                );

                // On the second row we read AL number of bits.
                cb.require_equal(
                    "AL number of bits read on the second row",
                    meta.query_advice(huffman_tree_config.fse_table_al, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.bit_index_end, Rotation::next())
                        - meta.query_advice(bitstream_decoder.bit_index_start, Rotation::next())
                        + 1.expr(),
                );
                // Whatever bitstring we read, is also the initial state in the FSE table, where we
                // start applying the FSE table.
                cb.require_equal(
                    "init state of FSE table",
                    meta.query_advice(bitstream_decoder.bit_value, Rotation::next()),
                    meta.query_advice(fse_decoder.state, Rotation::next()),
                );

                // Baseline conditions for FSE state transition
                cb.require_zero(
                    "Current row baseline",
                    meta.query_advice(fse_decoder.baseline, Rotation::cur()),
                );
                cb.require_zero(
                    "Previous row baseline",
                    meta.query_advice(fse_decoder.baseline, Rotation::prev()),
                );

                let lstream_kind = meta.query_advice(lstream_config.lstream_kind, Rotation::cur());
                cb.require_equal(
                    "tag_next after Huffman code depending on Lstream kind",
                    meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                    select::expr(
                        lstream_kind,
                        ZstdTag::ZstdBlockJumpTable.expr(),
                        ZstdTag::ZstdBlockLstream.expr(),
                    ),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_huffman_code, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                ]))
            },
        );
        meta.create_gate(
            "DecompressionCircuit: ZstdBlockHuffmanCode (wherever we emit a symbol)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                cb.require_equal(
                    "num_emitted increments",
                    meta.query_advice(fse_decoder.num_emitted, Rotation::cur()),
                    meta.query_advice(fse_decoder.num_emitted, Rotation::prev()) + 1.expr(),
                );

                let baseline = meta.query_advice(fse_decoder.baseline, Rotation(-2)); // baseline at state
                let bit_value = meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()); // bits read

                cb.require_equal(
                    "state' == baseline(state) + bit_value (every other row)",
                    meta.query_advice(fse_decoder.state, Rotation::cur()),
                    baseline + bit_value,
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_huffman_code, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                ]))
            },
        );

        // 1. We first read AL number of bits from the bitstream (say bit_value_init) and transition
        //    to the state == bit_value_init.
        // 2. We then follow the FSE table:
        //      - a. Emit symbol at state::cur. This is the canonical Huffman weight
        //      - b. Read nb(state::cur) number of bits from the bitstream, say bit_value::cur
        //      - c. Transition to state' == baseline(state::cur) + bit_value::cur
        //
        // We have already verified that the ``bit_value`` read from the bitstream is correct by
        // doing lookups to the BitstringAccumulationTable.
        //
        // We want to do a lookup to the FseTable to verify that the following tuple is correct:
        // - (huffman_tree_byte_offset, state, fse_symbol, baseline, nb)
        //
        // The first time we emit an FSE symbol, it represents the weight of Huffman symbol 0
        // (i.e. decoded_value == 0) as per the canonical Huffman code. Subsequent FSE symbol
        // emissions are the weights for the subsequent decoded values. We verify the weight of a
        // Huffman symbol (i.e. decoded_value) by doing a lookup to the HuffmanCodesTable:
        // - (huffman_tree_byte_offset, huffman_symbol, weight)
        //
        // Lastly, on the last row of HuffmanCode tag, we want to make sure we have emitted N - 1
        // symbols (weights), where N is the total number of huffman symbols that are being encoded
        // in that Huffman table. As per the canonical Huffman code representation, we only need to
        // emit N - 1 weights and the weight of the last symbol can be calculated.

        meta.lookup_any(
            "DecompressionCircuit: ZstdBlockHuffmanCode (fse table lookup)",
            |meta| {
                let condition = and::expr([
                    // TODO: Degree > 9
                    // Comment q_enable out for now with the assumption that when is_huffman_code is on, q_enable must also be on. (perhaps constrain this?)
                    // meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_huffman_code, Rotation::cur()),
                    // TODO: Verify below exclusions
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())), // Exclude leading 0s and sentinel 1 bit
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::next())), // Exclude the last row
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation(2))), // Exclude the second last row as max rotation is 2

                ]);

                // TODO: Verify that acquiring data for num_bits from bitstream_decoder targets 2 rows down, not the current row

                // let start = meta.query_advice(bitstream_decoder.bit_index_start, Rotation::cur());
                // let end = meta.query_advice(bitstream_decoder.bit_index_end, Rotation::cur());
                // let num_bits = select::expr(
                //     meta.query_advice(bitstream_decoder.is_nil, Rotation::cur()),
                //     0.expr(),
                //     end - start + 1.expr(),
                // );

                let start = meta.query_advice(bitstream_decoder.bit_index_start, Rotation(2));
                let end = meta.query_advice(bitstream_decoder.bit_index_end, Rotation(2));
                let num_bits = select::expr(
                    meta.query_advice(bitstream_decoder.is_nil, Rotation(2)),
                    0.expr(),
                    end - start + 1.expr(),
                );

                [
                    meta.query_advice(huffman_tree_config.huffman_tree_idx, Rotation::cur()),
                    meta.query_advice(huffman_tree_config.fse_table_size, Rotation::cur()),
                    meta.query_advice(fse_decoder.state, Rotation::cur()),
                    meta.query_advice(fse_decoder.symbol, Rotation::cur()),
                    meta.query_advice(fse_decoder.baseline, Rotation::cur()),
                    num_bits,
                ]
                .into_iter()
                .zip(fse_table.table_exprs_state_check(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );

        meta.lookup_any(
            "DecompressionCircuit: ZstdBlockHuffmanCode (huffman codes table lookup)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_huffman_code, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::prev())),
                ]);
                [
                    meta.query_advice(huffman_tree_config.huffman_tree_idx, Rotation::cur()),
                    meta.query_advice(fse_decoder.num_emitted, Rotation::cur()) - 1.expr(),
                    meta.query_advice(fse_decoder.symbol, Rotation::cur()),
                ]
                .into_iter()
                .zip(huffman_codes_table.table_exprs_canonical_weight(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );

        meta.lookup_any(
            "DecompressionCircuit: ZstdBlockHuffmanCode (num symbols in huffman code)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_huffman_code, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::next()),
                ]);
                [
                    meta.query_advice(huffman_tree_config.huffman_tree_idx, Rotation::cur()),
                    meta.query_advice(fse_decoder.num_emitted, Rotation::cur()),
                    1.expr(), // is_last
                ]
                .into_iter()
                .zip(huffman_codes_table.table_exprs_weights_count(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
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

            // Length of Lstream1.
            let len1 = meta.query_advice(value_byte, Rotation(0))
                + 256.expr() * meta.query_advice(value_byte, Rotation(1));
            // Length of Lstream 2.
            let len2 = meta.query_advice(value_byte, Rotation(2))
                + 256.expr() * meta.query_advice(value_byte, Rotation(3));
            // Length of Lstream3.
            let len3 = meta.query_advice(value_byte, Rotation(4))
                + 256.expr() * meta.query_advice(value_byte, Rotation(5));

            cb.require_equal(
                "length of Lstream1",
                meta.query_advice(lstream_config.len_lstream1, Rotation::cur()),
                len1.expr(),
            );
            cb.require_equal(
                "length of lstream2",
                meta.query_advice(lstream_config.len_lstream2, Rotation::cur()),
                len2.expr(),
            );
            cb.require_equal(
                "length of lstream3",
                meta.query_advice(lstream_config.len_lstream3, Rotation::cur()),
                len3.expr(),
            );
            // To calculate the size of Lstream4, we have:
            // - TotalStreamsSize == CompressedSize - HuffmanTreeDescriptionSize
            // - Stream4_Size == TotalStreamsSize - Stream1_Size - Stream2_Size - Stream3_Size
            //
            // The HuffmanTreeDescriptionSize can be calculated as:
            // - HuffmanTreeDescriptionSize == byte_idx(JumpTable) - byte_idx(HuffmanTree)

            cb.require_equal(
                "length of lstream4",
                meta.query_advice(lstream_config.len_lstream4, Rotation::cur())
                    + len1
                    + len2
                    + len3
                    + meta.query_advice(byte_idx, Rotation::cur())
                    + 6.expr(),
                meta.query_advice(literals_header.compr_size, Rotation::cur())
                    + meta.query_advice(huffman_tree_config.huffman_tree_idx, Rotation::cur()),
            );

            for col in [
                lstream_config.len_lstream1,
                lstream_config.len_lstream2,
                lstream_config.len_lstream3,
                lstream_config.len_lstream4,
            ] {
                cb.require_equal(
                    "Lstream config gets transferred to Lstream section",
                    meta.query_advice(col, Rotation::cur()),
                    meta.query_advice(col, Rotation(N_JUMP_TABLE_BYTES as i32)),
                );
            }

            cb.require_equal(
                "first lstream that follows jump table is Lstream1",
                meta.query_advice(lstream_config.lstream, Rotation(N_JUMP_TABLE_BYTES as i32)),
                LstreamNum::Lstream1.expr(),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                is_zb_jump_table(meta),
            ]))
        });
        meta.create_gate(
            "DecompressionCircuit: LstreamConfig data unchanged",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                for col in [
                    lstream_config.len_lstream1,
                    lstream_config.len_lstream2,
                    lstream_config.len_lstream3,
                    lstream_config.len_lstream4,
                ] {
                    cb.require_equal(
                        "Lstream config remains unchanged",
                        meta.query_advice(col, Rotation::cur()),
                        meta.query_advice(col, Rotation::prev()),
                    );
                }

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                ]))
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////// ZstdTag::ZstdBlockLstream ////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate(
            "DecompressionCircuit: ZstdBlockLstream (first row)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                macro_rules! constrain_tag_len {
                    ($curr_lstream:ident, $col:ident) => {
                        cb.condition(
                            lstream_config
                                .lstream_num
                                .value_equals(LstreamNum::$curr_lstream, Rotation::cur())(
                                meta
                            ),
                            |cb| {
                                cb.require_equal(
                                    "tag length of the current lstream",
                                    meta.query_advice(tag_gadget.tag_len, Rotation::cur()),
                                    meta.query_advice(lstream_config.$col, Rotation::cur()),
                                )
                            },
                        );
                    };
                }
                constrain_tag_len!(Lstream1, len_lstream1);
                constrain_tag_len!(Lstream2, len_lstream2);
                constrain_tag_len!(Lstream3, len_lstream3);
                constrain_tag_len!(Lstream4, len_lstream4);

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                ]))
            },
        );
        meta.create_gate(
            "DecompressionCircuit: ZstdBlockLstream (other than the first row)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                cb.require_equal(
                    "lstream type does not change",
                    meta.query_advice(lstream_config.lstream, Rotation::cur()),
                    meta.query_advice(lstream_config.lstream, Rotation::prev()),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                ]))
            },
        );
        meta.create_gate(
            "DecompressionCircuit: ZstdBlockLstream (last row)",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                macro_rules! constrain_next_lstream {
                    ($curr_lstream:ident, $next_lstream:ident, $next_tag:ident) => {
                        cb.condition(
                            lstream_config
                                .lstream_num
                                .value_equals(LstreamNum::$curr_lstream, Rotation::cur())(
                                meta
                            ),
                            |cb| {
                                cb.require_equal(
                                    "lstream that follows the current lstream",
                                    meta.query_advice(lstream_config.lstream, Rotation::next()),
                                    LstreamNum::$next_lstream.expr(),
                                );
                                cb.require_equal(
                                    "tag_next after this lstream is processed",
                                    meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                                    ZstdTag::$next_tag.expr(),
                                );
                            },
                        );
                    };
                }
                constrain_next_lstream!(Lstream2, Lstream3, ZstdBlockLstream);
                constrain_next_lstream!(Lstream3, Lstream4, ZstdBlockLstream);

                let lstream_kind = meta.query_advice(lstream_config.lstream_kind, Rotation::cur());
                let is_lstream1 = lstream_config
                    .lstream_num
                    .value_equals(LstreamNum::Lstream1, Rotation::cur())(
                    meta
                );
                let is_lstream4 = lstream_config
                    .lstream_num
                    .value_equals(LstreamNum::Lstream4, Rotation::cur())(
                    meta
                );

                cb.condition(is_lstream1, |cb| {
                    cb.require_equal(
                        "tag that follows lstream1",
                        meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                        select::expr(
                            lstream_kind.expr(),
                            ZstdTag::ZstdBlockLstream.expr(),
                            ZstdTag::ZstdBlockSequenceHeader.expr(),
                        ),
                    );
                    cb.require_equal(
                        "lstream that follows lstream1",
                        meta.query_advice(lstream_config.lstream, Rotation::next()),
                        select::expr(lstream_kind, LstreamNum::Lstream2.expr(), 0.expr()),
                    );
                });

                cb.condition(is_lstream4, |cb| {
                    cb.require_equal(
                        "tag that follows lstream4",
                        meta.query_advice(tag_gadget.tag_next, Rotation::cur()),
                        ZstdTag::ZstdBlockSequenceHeader.expr(),
                    );
                });

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::next()),
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                ]))
            },
        );

        // TODO: to be enabled once DecodedLiteralsTable has been assigned witness to.
        /*
        meta.lookup_any(
            "DecompressionCircuit: ZstdBlockLstream (decoded literal byte)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                    not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                ]);
                [
                    meta.query_advice(huffman_tree_config.huffman_tree_idx, Rotation::cur()),
                    meta.query_advice(byte_idx, Rotation::cur()),
                    meta.query_advice(bitstream_decoder.decoded_symbol, Rotation::cur()),
                ]
                .into_iter()
                .zip(decoded_literals_table.table_exprs(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );
        */

        meta.lookup_any("DecompressionCircuit: bitstring (start)", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                // TODO: Make sure that both rows must be active witness rows and not paddings.
                // This condition also excludes the last row from lookup
                meta.query_fixed(q_enable, Rotation::next()),
                sum::expr([
                    and::expr([
                        meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                        not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    ]),
                    meta.query_advice(tag_gadget.is_huffman_code, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                ]),
                not::expr(meta.query_advice(bitstream_decoder.is_nil, Rotation::cur())),
            ]);
            let (huffman_byte_offset, bit_index_start, bit_value) = (
                meta.query_advice(huffman_tree_config.huffman_tree_idx, Rotation::cur()),
                meta.query_advice(bitstream_decoder.bit_index_start, Rotation::cur()),
                meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()),
            );
            [
                huffman_byte_offset,
                meta.query_advice(byte_idx, Rotation::cur()),
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(value_byte, Rotation::cur()),
                meta.query_advice(value_byte, Rotation::next()),
                bit_value,
                1.expr(), // bitstring_len at start
                bit_index_start,
                1.expr(), // from_start
                1.expr(), // until_end
                meta.query_advice(tag_gadget.is_reverse, Rotation::cur()),
            ]
            .into_iter()
            .zip(bs_acc_table.table_exprs(meta))
            .map(|(value, table)| (condition.expr() * value, table))
            .collect()
        });
        meta.lookup_any("DecompressionCircuit: bitstring (end)", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                // TODO: Make sure that both rows must be active witness rows and not paddings.
                // This condition also excludes the last row from lookup
                meta.query_fixed(q_enable, Rotation::next()),
                sum::expr([
                    and::expr([
                        meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                        not::expr(meta.query_advice(tag_gadget.is_tag_change, Rotation::cur())),
                    ]),
                    meta.query_advice(tag_gadget.is_huffman_code, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                ]),
                not::expr(meta.query_advice(bitstream_decoder.is_nil, Rotation::cur())),
            ]);
            let (huffman_byte_offset, bit_index_start, bit_index_end, bit_value) = (
                meta.query_advice(huffman_tree_config.huffman_tree_idx, Rotation::cur()),
                meta.query_advice(bitstream_decoder.bit_index_start, Rotation::cur()),
                meta.query_advice(bitstream_decoder.bit_index_end, Rotation::cur()),
                meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()),
            );
            [
                huffman_byte_offset,
                meta.query_advice(byte_idx, Rotation::cur()),
                meta.query_advice(byte_idx, Rotation::next()),
                meta.query_advice(value_byte, Rotation::cur()),
                meta.query_advice(value_byte, Rotation::next()),
                bit_value,
                bit_index_end.expr() - bit_index_start + 1.expr(), // bitstring_len at end
                bit_index_end,
                1.expr(), // from_start
                1.expr(), // until_end
                meta.query_advice(tag_gadget.is_reverse, Rotation::cur()),
            ]
            .into_iter()
            .zip(bs_acc_table.table_exprs(meta))
            .map(|(value, table)| (condition.expr() * value, table))
            .collect()
        });
        meta.create_gate("DecompressionCircuit: bitstream reader", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Note: for tag=FseCode, the first row of the bitstream read is in fact the second row
            // of the tag. The first row of the tag is taken by the Huffman header descriptor.
            let is_fse_code = meta.query_advice(tag_gadget.is_fse_code, Rotation::cur());
            let is_first = sum::expr([
                and::expr([
                    is_fse_code,
                    meta.query_advice(tag_gadget.is_tag_change, Rotation::prev()),
                ]),
                meta.query_advice(tag_gadget.is_tag_change, Rotation::cur()),
            ]);
            let is_last = meta.query_advice(tag_gadget.is_tag_change, Rotation::next());
            let is_not_last = not::expr(is_last.expr());

            // bitstream decoder starts at index=0.
            cb.condition(is_first.expr(), |cb| {
                cb.require_equal(
                    "bitstream decoder starts at index=0",
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::cur()),
                    0.expr(),
                );
            });

            // bitstream decoder ends at index=7.
            cb.condition(is_last, |cb| {
                cb.require_equal(
                    "bitstream decoder ends at index=7",
                    meta.query_advice(bitstream_decoder.bit_index_end, Rotation::cur()),
                    7.expr(),
                );
            });

            // for all rows except the last.
            let is_strictly_contained = and::expr([
                is_not_last.expr(),
                bitstream_decoder.is_strictly_contained(meta, None),
                not::expr(meta.query_advice(bitstream_decoder.is_nil, Rotation::cur())),
            ]);
            let is_byte_aligned = and::expr([
                is_not_last.expr(),
                bitstream_decoder.is_byte_aligned(meta, None),
                not::expr(meta.query_advice(bitstream_decoder.is_nil, Rotation::cur())),
            ]);
            let is_spanned =
                and::expr([is_not_last.expr(), bitstream_decoder.is_spanned(meta, None)]);
            // if bitstring is strictly contained.
            cb.condition(is_strictly_contained, |cb| {
                cb.require_equal(
                    "strictly contained bitstring: bit_index_start",
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::next()),
                    meta.query_advice(bitstream_decoder.bit_index_end, Rotation::cur()) + 1.expr(),
                );
                cb.require_equal(
                    "strictly contained bitstring: byte_idx",
                    meta.query_advice(byte_idx, Rotation::next()),
                    meta.query_advice(byte_idx, Rotation::cur()),
                );
            });

            // if bitstring is byte-aligned.
            cb.condition(is_byte_aligned, |cb| {
                cb.require_equal(
                    "byte-aligned bitstring: bit_index_start",
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::next()),
                    0.expr(),
                );
                cb.require_equal(
                    "byte-aligned bitstring: byte_idx",
                    meta.query_advice(byte_idx, Rotation::next()),
                    meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
                );
            });

            // Special case where we are reading no bits from the bitstream. This can only occur in
            // case we are processing tag=ZstdBlockHuffmanCode.
            cb.condition(
                meta.query_advice(bitstream_decoder.is_nil, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "0 # of bits read can only happen in ZstdBlockHuffmanCode",
                        meta.query_advice(tag_gadget.tag, Rotation::cur()),
                        ZstdTag::ZstdBlockHuffmanCode.expr(),
                    );
                    cb.require_equal(
                        "bit_index_start == bit_index_end since no bit is read",
                        meta.query_advice(bitstream_decoder.bit_index_start, Rotation::cur()),
                        meta.query_advice(bitstream_decoder.bit_index_end, Rotation::cur()),
                    );
                    cb.require_equal(
                        "bit_value == 0 since no bit is read",
                        meta.query_advice(bitstream_decoder.bit_value, Rotation::cur()),
                        0.expr(),
                    );
                    cb.require_equal(
                        "byte_idx' == byte_idx since no bit is read",
                        meta.query_advice(byte_idx, Rotation::next()),
                        meta.query_advice(byte_idx, Rotation::cur()),
                    );
                    cb.require_equal(
                        "bit_index_start' == bit_index_start since no bit is read",
                        meta.query_advice(bitstream_decoder.bit_index_start, Rotation::next()),
                        meta.query_advice(bitstream_decoder.bit_index_start, Rotation::cur()),
                    );
                },
            );

            // if bitstring is spanned.
            cb.condition(is_spanned, |cb| {
                cb.require_equal(
                    "spanned bitstring: bit_index_start",
                    meta.query_advice(bitstream_decoder.bit_index_start, Rotation::next()),
                    meta.query_advice(bitstream_decoder.bit_index_end, Rotation::cur()) - 7.expr(),
                );
                cb.require_equal(
                    "spanned bitstring: byte_idx",
                    meta.query_advice(byte_idx, Rotation::next()),
                    meta.query_advice(byte_idx, Rotation::cur()) + 1.expr(),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                sum::expr([
                    meta.query_advice(tag_gadget.is_fse_code, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_huffman_code, Rotation::cur()),
                    meta.query_advice(tag_gadget.is_lstream, Rotation::cur()),
                ]),
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
            literals_header,
            huffman_tree_config,
            bitstream_decoder,
            fse_decoder,
            lstream_config,
            bitwise_op_table,
            range4,
            range8,
            range16,
            range64,
            range128,
            range256,
            tag_rom_table,
            pow_rand_table,
            block_type_rom_table,
            pow2_table,
            literals_header_rom_table,
            literals_header_table,
            bitstring_accumulation_table: bs_acc_table,
            fse_table,
            huffman_codes_table,
            decoded_literals_table,
        }
    }
}

impl<F: Field> DecompressionCircuitConfig<F> {
    /// Assign witness to the decompression circuit.
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness_rows: Vec<ZstdWitnessRow<F>>,
        aux_data: Vec<u64>,
        fse_aux_tables: Vec<FseAuxiliaryTableData>,
        huffman_codes: Vec<HuffmanCodesData>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let mut rand_pow: Vec<Value<F>> = vec![Value::known(F::one())];

        self.bitstring_accumulation_table
            .assign(layouter, &witness_rows)?;
        self.fse_table.assign(layouter, fse_aux_tables)?;
        self.huffman_codes_table.assign(layouter, huffman_codes)?;

        let literal_header_offset = witness_rows
            .iter()
            .find(|r| r.state.tag == ZstdTag::ZstdBlockLiteralsHeader)
            .unwrap()
            .encoded_data
            .byte_idx;
        let literal_bytes = witness_rows
            .iter()
            .filter(|&r| r.state.tag == ZstdTag::ZstdBlockLiteralsHeader)
            .map(|r| r.encoded_data.value_byte)
            .collect::<Vec<u8>>();

        self.literals_header_table.assign(
            layouter,
            &[(
                literal_header_offset,
                literal_bytes.as_slice(),
                aux_data[10],
                aux_data[4],
                aux_data[5],
            )],
        )?;

        // TODO: pass decoded literals along with boundaries (literal lengths calculated while
        // applying the Sequences FSE tables).
        // self.decoded_literals_table.assign(layouter)?;

        layouter.assign_region(
            || "Decompression table region",
            |mut region| {
                let mut last_byte_idx: usize = 0;
                let mut value_rlc = Value::known(F::zero());

                for (i, row) in witness_rows.iter().enumerate() {
                    let tag_len = row.state.tag_len as usize;
                    assert!(tag_len > 0);

                    last_byte_idx = row.encoded_data.byte_idx as usize;

                    while tag_len >= rand_pow.len() {
                        let tail = *rand_pow.last().expect("Tail exists");
                        rand_pow.push(tail * challenges.keccak_input());
                    }

                    region.assign_fixed(
                        || "q_enable",
                        self.q_enable,
                        i,
                        || Value::known(F::one()),
                    )?;
                    region.assign_fixed(
                        || "q_first",
                        self.q_first,
                        i,
                        || Value::known(F::from((i == 0) as u64)),
                    )?;
                    region.assign_advice(
                        || "is_padding",
                        self.is_padding,
                        i,
                        || Value::known(F::zero()),
                    )?;
                    region.assign_advice(
                        || "byte_idx",
                        self.byte_idx,
                        i,
                        || Value::known(F::from(row.encoded_data.byte_idx)),
                    )?;
                    region.assign_advice(
                        || "encoded_len",
                        self.encoded_len,
                        i,
                        || Value::known(F::from(row.encoded_data.encoded_len)),
                    )?;

                    if i > 0 && row.state.is_tag_change {
                        let prev_row = &witness_rows[i - 1];
                        value_rlc = value_rlc * rand_pow[prev_row.state.tag_len as usize]
                            + prev_row.state.tag_rlc;
                    }

                    region.assign_advice(
                        || "value_rlc",
                        self.value_rlc,
                        i,
                        || {
                            if i == 0 {
                                Value::known(F::zero())
                            } else {
                                value_rlc
                            }
                        },
                    )?;

                    // Byte value and bits decomposition
                    region.assign_advice(
                        || "value_byte",
                        self.value_byte,
                        i,
                        || Value::known(F::from(row.encoded_data.value_byte as u64)),
                    )?;
                    let bits = value_bits_le(row.encoded_data.value_byte);
                    let is_reverse = row.encoded_data.reverse;
                    for (idx, col) in self.value_bits.iter().rev().enumerate() {
                        region.assign_advice(
                            || "value_bits",
                            *col,
                            i,
                            || {
                                Value::known(F::from(
                                    (if is_reverse {
                                        bits[idx]
                                    } else {
                                        bits[N_BITS_PER_BYTE - idx - 1]
                                    }) as u64,
                                ))
                            },
                        )?;
                    }

                    // Decoded Data
                    region.assign_advice(
                        || "decoded_len",
                        self.decoded_len,
                        i,
                        || Value::known(F::from(row.decoded_data.decoded_len)),
                    )?;
                    region.assign_advice(
                        || "decoded_len_acc",
                        self.decoded_len_acc,
                        i,
                        || Value::known(F::from(row.decoded_data.decoded_len_acc)),
                    )?;
                    region.assign_advice(
                        || "decoded_byte",
                        self.decoded_byte,
                        i,
                        || Value::known(F::from(row.decoded_data.decoded_byte as u64)),
                    )?;
                    region.assign_advice(
                        || "decoded_rlc",
                        self.decoded_rlc,
                        i,
                        || row.decoded_data.decoded_value_rlc,
                    )?;

                    // Block Gadget
                    let is_block = !(row.state.tag == ZstdTag::FrameHeaderDescriptor
                        || row.state.tag == ZstdTag::FrameContentSize
                        || row.state.tag == ZstdTag::BlockHeader)
                        as u64;
                    region.assign_advice(
                        || "block_gadget.is_block",
                        self.block_gadget.is_block,
                        i,
                        || Value::known(F::from(is_block)),
                    )?;
                    region.assign_advice(
                        || "block_gadget.block_idx",
                        self.block_gadget.idx,
                        i,
                        || Value::known(F::one()),
                    )?;
                    region.assign_advice(
                        || "block_gadget.block_len",
                        self.block_gadget.block_len,
                        i,
                        || Value::known(F::one()),
                    )?;
                    region.assign_advice(
                        || "block_gadget.is_last_block",
                        self.block_gadget.is_last_block,
                        i,
                        || Value::known(F::one()),
                    )?;

                    let idx_cmp_len_chip =
                        ComparatorChip::construct(self.block_gadget.idx_cmp_len.clone());
                    idx_cmp_len_chip.assign(&mut region, i, F::one(), F::one())?;

                    // Tag Gadget
                    region.assign_advice(
                        || "tag_gadget.tag",
                        self.tag_gadget.tag,
                        i,
                        || Value::known(F::from(row.state.tag as u64)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.tag_next",
                        self.tag_gadget.tag_next,
                        i,
                        || Value::known(F::from(row.state.tag_next as u64)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.max_len",
                        self.tag_gadget.max_len,
                        i,
                        || Value::known(F::from(row.state.max_tag_len)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.tag_idx",
                        self.tag_gadget.tag_idx,
                        i,
                        || Value::known(F::from(row.state.tag_idx)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.tag_len",
                        self.tag_gadget.tag_len,
                        i,
                        || Value::known(F::from(row.state.tag_len)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.is_reverse",
                        self.tag_gadget.is_reverse,
                        i,
                        || Value::known(F::from(row.encoded_data.reverse as u64)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.is_tag_change",
                        self.tag_gadget.is_tag_change,
                        i,
                        || Value::known(F::from(row.state.is_tag_change as u64)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.tag_value",
                        self.tag_gadget.tag_value,
                        i,
                        || row.state.tag_value,
                    )?;
                    region.assign_advice(
                        || "tag_gadget.tag_value_acc",
                        self.tag_gadget.tag_value_acc,
                        i,
                        || row.state.tag_value_acc,
                    )?;
                    region.assign_advice(
                        || "tag_gadget.tag_rlc",
                        self.tag_gadget.tag_rlc,
                        i,
                        || row.state.tag_rlc,
                    )?;
                    region.assign_advice(
                        || "tag_gadget.tag_rlc_acc",
                        self.tag_gadget.tag_rlc_acc,
                        i,
                        || row.state.tag_rlc_acc,
                    )?;
                    region.assign_advice(
                        || "tag_gadget.rand_pow_tag_len",
                        self.tag_gadget.rand_pow_tag_len,
                        i,
                        || rand_pow[tag_len],
                    )?;

                    let tag_bits = BinaryNumberChip::construct(self.tag_gadget.tag_bits);
                    tag_bits.assign(&mut region, i, &row.state.tag)?;

                    let idx_cmp_len_chip =
                        ComparatorChip::construct(self.tag_gadget.idx_cmp_len.clone());
                    idx_cmp_len_chip.assign(
                        &mut region,
                        i,
                        F::from(row.state.tag_idx),
                        F::from(row.state.tag_len),
                    )?;

                    let len_cmp_max_chip =
                        ComparatorChip::construct(self.tag_gadget.len_cmp_max.clone());
                    len_cmp_max_chip.assign(
                        &mut region,
                        i,
                        F::from(row.state.tag_len),
                        F::from(row.state.max_tag_len),
                    )?;

                    let max_tag_len = row.state.max_tag_len;
                    let mlen_lt_0x20_chip = LtChip::construct(self.tag_gadget.mlen_lt_0x20);
                    mlen_lt_0x20_chip.assign(
                        &mut region,
                        i,
                        F::from(max_tag_len),
                        F::from(0x20),
                    )?;

                    let is_block_header = (row.state.tag == ZstdTag::BlockHeader) as u64;
                    let is_literals_header =
                        (row.state.tag == ZstdTag::ZstdBlockLiteralsHeader) as u64;
                    let is_fse_code = (row.state.tag == ZstdTag::ZstdBlockFseCode) as u64;
                    let is_huffman_code = (row.state.tag == ZstdTag::ZstdBlockHuffmanCode) as u64;
                    let is_lstream = (row.state.tag == ZstdTag::ZstdBlockLstream) as u64;
                    let is_jumptable = (row.state.tag == ZstdTag::ZstdBlockJumpTable) as u64;
                    let is_literals_section = is_literals_header
                        + is_fse_code
                        + is_huffman_code
                        + is_lstream
                        + is_jumptable;
                    let is_huffman_tree_section =
                        is_fse_code + is_huffman_code + is_jumptable + is_lstream;

                    let is_output = row.state.tag.is_output() as u64;
                    region.assign_advice(
                        || "tag_gadget.is_output",
                        self.tag_gadget.is_output,
                        i,
                        || Value::known(F::from(is_output)),
                    )?;

                    region.assign_advice(
                        || "tag_gadget.is_block_header",
                        self.tag_gadget.is_block_header,
                        i,
                        || Value::known(F::from(is_block_header)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.is_literals_header",
                        self.tag_gadget.is_literals_header,
                        i,
                        || Value::known(F::from(is_literals_header)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.is_lstream",
                        self.tag_gadget.is_lstream,
                        i,
                        || Value::known(F::from(is_lstream)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.is_fse_code",
                        self.tag_gadget.is_fse_code,
                        i,
                        || Value::known(F::from(is_fse_code)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.is_huffman_code",
                        self.tag_gadget.is_huffman_code,
                        i,
                        || Value::known(F::from(is_huffman_code)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.is_literals_section",
                        self.tag_gadget.is_literals_section,
                        i,
                        || Value::known(F::from(is_literals_section)),
                    )?;
                    region.assign_advice(
                        || "tag_gadget.is_huffman_tree_section",
                        self.tag_gadget.is_huffman_tree_section,
                        i,
                        || Value::known(F::from(is_huffman_tree_section)),
                    )?;

                    // Literals Header
                    region.assign_advice(
                        || "literals_header.branch",
                        self.literals_header.branch,
                        i,
                        || Value::known(F::from(aux_data[10])),
                    )?;
                    region.assign_advice(
                        || "literals_header.sf_max",
                        self.literals_header.sf_max,
                        i,
                        || Value::known(F::from(aux_data[11])),
                    )?;
                    region.assign_advice(
                        || "literals_header.regen_size",
                        self.literals_header.regen_size,
                        i,
                        || Value::known(F::from(aux_data[4])),
                    )?;
                    region.assign_advice(
                        || "literals_header.compr_size",
                        self.literals_header.compr_size,
                        i,
                        || Value::known(F::from(aux_data[5])),
                    )?;

                    // Huffman Tree Config
                    region.assign_advice(
                        || "huffman_tree_config.huffman_tree_idx",
                        self.huffman_tree_config.huffman_tree_idx,
                        i,
                        || Value::known(F::from(aux_data[6])),
                    )?;
                    region.assign_advice(
                        || "huffman_tree_config.fse_table_size",
                        self.huffman_tree_config.fse_table_size,
                        i,
                        || Value::known(F::from(aux_data[7])),
                    )?;
                    region.assign_advice(
                        || "huffman_tree_config.fse_table_al",
                        self.huffman_tree_config.fse_table_al,
                        i,
                        || Value::known(F::from(aux_data[8])),
                    )?;
                    region.assign_advice(
                        || "huffman_tree_config.huffman_code_len",
                        self.huffman_tree_config.huffman_code_len,
                        i,
                        || Value::known(F::from(aux_data[9])),
                    )?;

                    // Bitstream Decoder
                    region.assign_advice(
                        || "bitstream_decoder.bit_index_start",
                        self.bitstream_decoder.bit_index_start,
                        i,
                        || Value::known(F::from(row.bitstream_read_data.bit_start_idx as u64)),
                    )?;
                    region.assign_advice(
                        || "bitstream_decoder.bit_index_end",
                        self.bitstream_decoder.bit_index_end,
                        i,
                        || Value::known(F::from(row.bitstream_read_data.bit_end_idx as u64)),
                    )?;
                    region.assign_advice(
                        || "bitstream_decoder.bit_value",
                        self.bitstream_decoder.bit_value,
                        i,
                        || Value::known(F::from(row.bitstream_read_data.bit_value)),
                    )?;
                    region.assign_advice(
                        || "bitstream_decoder.is_nil",
                        self.bitstream_decoder.is_nil,
                        i,
                        || Value::known(F::from(row.bitstream_read_data.is_zero_bit_read as u64)),
                    )?;

                    let bitstring_contained_chip = ComparatorChip::construct(
                        self.bitstream_decoder.bitstring_contained.clone(),
                    );
                    bitstring_contained_chip.assign(
                        &mut region,
                        i,
                        F::from(row.bitstream_read_data.bit_end_idx as u64),
                        F::from(7u64),
                    )?;

                    region.assign_advice(
                        || "bitstream_decoder.decoded_symbol",
                        self.bitstream_decoder.decoded_symbol,
                        i,
                        || Value::known(F::from(row.decoded_data.decoded_byte as u64)),
                    )?;

                    // FSE Gadget
                    region.assign_advice(
                        || "fse_decoder.num_emitted",
                        self.fse_decoder.num_emitted,
                        i,
                        || Value::known(F::from(row.fse_data.num_emitted)),
                    )?;
                    region.assign_advice(
                        || "fse_decoder.n_acc",
                        self.fse_decoder.n_acc,
                        i,
                        || Value::known(F::from(row.fse_data.n_acc)),
                    )?;
                    region.assign_advice(
                        || "fse_decoder.state",
                        self.fse_decoder.state,
                        i,
                        || Value::known(F::from(row.fse_data.state)),
                    )?;
                    region.assign_advice(
                        || "fse_decoder.baseline",
                        self.fse_decoder.baseline,
                        i,
                        || Value::known(F::from(row.fse_data.baseline)),
                    )?;
                    region.assign_advice(
                        || "fse_decoder.symbol",
                        self.fse_decoder.symbol,
                        i,
                        || Value::known(F::from(row.fse_data.symbol)),
                    )?;

                    // Lstream Config
                    let is_four_streams: u64 = if aux_data[2] > 0 { 1 } else { 0 };
                    region.assign_advice(
                        || "lstream_config.lstream_kind",
                        self.lstream_config.lstream_kind,
                        i,
                        || Value::known(F::from(is_four_streams)),
                    )?;
                    region.assign_advice(
                        || "lstream_config.lstream",
                        self.lstream_config.lstream,
                        i,
                        || Value::known(F::from(row.huffman_data.stream_idx as u64)),
                    )?;

                    let lstream_num_chip =
                        BinaryNumberChip::construct(self.lstream_config.lstream_num);
                    lstream_num_chip.assign(&mut region, i, &row.huffman_data.stream_idx.into())?;

                    region.assign_advice(
                        || "lstream_config.len_lstream1",
                        self.lstream_config.len_lstream1,
                        i,
                        || Value::known(F::from(aux_data[0])),
                    )?;
                    region.assign_advice(
                        || "lstream_config.len_lstream2",
                        self.lstream_config.len_lstream2,
                        i,
                        || Value::known(F::from(aux_data[1])),
                    )?;
                    region.assign_advice(
                        || "lstream_config.len_lstream3",
                        self.lstream_config.len_lstream3,
                        i,
                        || Value::known(F::from(aux_data[2])),
                    )?;
                    region.assign_advice(
                        || "lstream_config.len_lstream4",
                        self.lstream_config.len_lstream4,
                        i,
                        || Value::known(F::from(aux_data[3])),
                    )?;
                }

                // TODO: Should assign sequence section. Dummy row for sequencing section header as
                // of now
                region.assign_advice(
                    || "byte_idx",
                    self.byte_idx,
                    witness_rows.len(),
                    || Value::known(F::from((last_byte_idx + 1) as u64)),
                )?;
                region.assign_advice(
                    || "tag_gadget.is_tag_change",
                    self.tag_gadget.is_tag_change,
                    witness_rows.len(),
                    || Value::known(F::one()),
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

/// The Decompression circuit decodes an instance of zstd compressed data.
#[derive(Clone, Debug, Default)]
pub struct DecompressionCircuit<F> {
    compressed_frames: Vec<Vec<u8>>,
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
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut witness_rows: Vec<ZstdWitnessRow<F>> = vec![];
        let mut data: Vec<u64> = vec![];
        let mut fse_aux_tables = vec![];
        let mut huffman_aux_data = vec![];

        for idx in 0..self.compressed_frames.len() {
            let (rows, _decoded_literals, aux_data, f_fse_aux_tables, huffman_codes) =
                process::<F>(&self.compressed_frames[idx], challenges.keccak_input());
            witness_rows.extend_from_slice(&rows);
            data.extend_from_slice(&aux_data);
            fse_aux_tables.extend_from_slice(&f_fse_aux_tables);
            huffman_aux_data.extend_from_slice(&huffman_codes);
        }

        config.assign(
            layouter,
            witness_rows,
            data,
            fse_aux_tables,
            huffman_aux_data,
            challenges,
        )
    }
}
