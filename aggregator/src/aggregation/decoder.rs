mod tables;
mod witgen;

use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    is_equal::{IsEqualChip, IsEqualConfig},
    util::{and, not, select, Expr},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    halo2curves::bn256::Fr,
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use witgen::{ZstdTag, N_BITS_PER_BYTE, N_BITS_ZSTD_TAG};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, PowOfRandTable, RangeTable, U8Table},
    util::Challenges,
};

use crate::aggregation::decoder::witgen::N_BLOCK_HEADER_BYTES;

use self::tables::{LiteralsHeaderTable, RomTagTable};

#[derive(Clone, Debug)]
pub struct DecoderConfig {
    /// Fixed column to mark the first row in the layout.
    q_first: Column<Fixed>,
    /// The byte index in the encoded data. At the first byte, byte_idx = 1.
    byte_idx: Column<Advice>,
    /// The byte value at this byte index in the encoded data.
    byte: Column<Advice>,
    /// The byte value decomposed in its bits. The endianness of bits depends on whether or not we
    /// are processing a chunk of bytes from back-to-front or not. The bits follow
    /// little-endianness if bytes are processed from back-to-front, otherwise big-endianness.
    bits: [Column<Advice>; N_BITS_PER_BYTE],
    /// The RLC of the zstd encoded bytes.
    encoded_rlc: Column<Advice>,
    /// The byte that is (possibly) decoded at the current row.
    decoded_byte: Column<Advice>,
    /// The RLC of the bytes decoded.
    decoded_rlc: Column<Advice>,
    /// The size of the final decoded bytes.
    decoded_len: Column<Advice>,
    /// An incremental accumulator of the number of bytes decoded so far.
    decoded_len_acc: Column<Advice>,
    /// Once all the encoded bytes are decoded, we append the layout with padded rows.
    is_padding: Column<Advice>,
    /// Zstd tag related config.
    tag_config: TagConfig,
    /// Block related config.
    block_config: BlockConfig,
    /// Range Table for [0, 8).
    range8: RangeTable<8>,
    /// Range Table for [0, 16).
    range16: RangeTable<16>,
    /// Helper tables for decoding the regenerated size from LiteralsHeader.
    literals_header_table: LiteralsHeaderTable,
    /// ROM table for validating tag transition.
    rom_tag_table: RomTagTable,
}

#[derive(Clone, Debug)]
struct TagConfig {
    /// The ZstdTag being processed at the current row.
    tag: Column<Advice>,
    /// Tag decomposed as bits. This is useful in constructing conditional checks against the tag
    /// value.
    tag_bits: BinaryNumberConfig<ZstdTag, N_BITS_ZSTD_TAG>,
    /// The Zstd tag that will be processed after processing the current tag.
    tag_next: Column<Advice>,
    /// The number of bytes in the current tag.
    tag_len: Column<Advice>,
    /// The byte index within the current tag. At the first tag byte, tag_idx = 1.
    tag_idx: Column<Advice>,
    /// A utility gadget to identify the row where tag_idx == tag_len.
    tag_idx_eq_tag_len: IsEqualConfig<Fr>,
    /// The maximum number bytes that the current tag may occupy. This is an upper bound on the
    /// number of bytes required to encode this tag. For instance, the LiteralsHeader is variable
    /// sized, ranging from 1-5 bytes. The max_len for LiteralsHeader would be 5.
    max_len: Column<Advice>,
    /// The RLC of bytes in the tag.
    tag_rlc: Column<Advice>,
    /// Represents keccak randomness exponentiated by the tag len.
    rpow_tag_len: Column<Advice>,
    /// Whether this tag outputs decoded bytes or not.
    is_output: Column<Advice>,
    /// Whether this tag is processed from back-to-front or not.
    is_reverse: Column<Advice>,
    /// Whether this row represents the first byte in a new tag. Effectively this also means that
    /// the previous row represented the last byte of the tag processed previously.
    ///
    /// The only exception is the first row in the layout where for the FrameHeaderDescriptor we do
    /// not set this boolean value. We instead use the q_first fixed column to conditionally
    /// constrain the first row.
    is_change: Column<Advice>,
    /// Degree reduction: FrameContentSize
    is_frame_content_size: Column<Advice>,
    /// Degree reduction: BlockHeader
    is_block_header: Column<Advice>,
}

impl TagConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let q_enable = meta.fixed_column();
        let tag = meta.advice_column();
        let tag_idx = meta.advice_column();
        let tag_len = meta.advice_column();

        Self {
            tag,
            tag_bits: BinaryNumberChip::configure(meta, q_enable, Some(tag.into())),
            tag_next: meta.advice_column(),
            tag_len,
            tag_idx,
            tag_idx_eq_tag_len: IsEqualChip::configure(
                meta,
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
                |meta| meta.query_advice(tag_idx, Rotation::cur()),
                |meta| meta.query_advice(tag_len, Rotation::cur()),
            ),
            max_len: meta.advice_column(),
            tag_rlc: meta.advice_column_in(SecondPhase),
            rpow_tag_len: meta.advice_column_in(SecondPhase),
            is_output: meta.advice_column(),
            is_reverse: meta.advice_column(),
            is_change: meta.advice_column(),
            // degree reduction.
            is_frame_content_size: meta.advice_column(),
            is_block_header: meta.advice_column(),
        }
    }
}

#[derive(Clone, Debug)]
struct BlockConfig {
    /// The number of bytes in this block.
    block_len: Column<Advice>,
    /// The index within the zstd block of the current byte.
    block_idx: Column<Advice>,
    /// Whether this block is the last block in the zstd encoded data.
    is_last_block: Column<Advice>,
    /// Helper boolean column to tell us whether we are in the block's contents. This field is not
    /// set for FrameHeaderDescriptor, FrameContentSize and BlockHeader. For the tags that occur
    /// while decoding the block's contents, this field is set.
    is_block: Column<Advice>,
}

impl BlockConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            block_len: meta.advice_column(),
            block_idx: meta.advice_column(),
            is_last_block: meta.advice_column(),
            is_block: meta.advice_column(),
        }
    }
}

pub struct AssignedDecoderConfigExports {
    /// The RLC of the zstd encoded bytes, i.e. blob bytes.
    pub encoded_rlc: AssignedCell<Fr, Fr>,
    /// The RLC of the decoded bytes, i.e. batch bytes.
    pub decoded_rlc: AssignedCell<Fr, Fr>,
}

impl DecoderConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        challenges: &Challenges<Expression<Fr>>,
        pow_rand_table: PowOfRandTable,
        u8_table: U8Table,
        range8: RangeTable<8>,
        range16: RangeTable<16>,
    ) -> Self {
        // Fixed tables
        let rom_tag_table = RomTagTable::construct(meta);

        // Helper tables
        let literals_header_table = LiteralsHeaderTable::configure(meta, range8, range16);

        // Peripheral configs
        let tag_config = TagConfig::configure(meta);
        let block_config = BlockConfig::configure(meta);

        // Main config
        let config = Self {
            q_first: meta.fixed_column(),
            byte_idx: meta.advice_column(),
            byte: meta.advice_column(),
            bits: (0..N_BITS_PER_BYTE)
                .map(|_| meta.advice_column())
                .collect::<Vec<_>>()
                .try_into()
                .expect("N_BITS_PER_BYTE advice columns into array"),
            encoded_rlc: meta.advice_column_in(SecondPhase),
            decoded_byte: meta.advice_column(),
            decoded_rlc: meta.advice_column_in(SecondPhase),
            decoded_len: meta.advice_column(),
            decoded_len_acc: meta.advice_column(),
            is_padding: meta.advice_column(),
            tag_config,
            block_config,
            range8,
            range16,
            literals_header_table,
            rom_tag_table,
        };

        macro_rules! is_tag {
            ($var:ident, $tag_variant:ident) => {
                let $var = |meta: &mut VirtualCells<Fr>| {
                    config
                        .tag_config
                        .tag_bits
                        .value_equals(ZstdTag::$tag_variant, Rotation::cur())(meta)
                };
            };
        }

        is_tag!(_is_null, Null);
        is_tag!(is_frame_header_descriptor, FrameHeaderDescriptor);
        is_tag!(is_frame_content_size, FrameContentSize);
        is_tag!(is_block_header, BlockHeader);
        is_tag!(is_zb_literals_header, ZstdBlockLiteralsHeader);
        is_tag!(is_zb_raw_block, ZstdBlockLiteralsRawBytes);
        is_tag!(_is_zb_sequence_header, ZstdBlockSequenceHeader);

        meta.lookup("DecoderConfig: 0 <= encoded byte < 256", |meta| {
            vec![(
                meta.query_advice(config.byte, Rotation::cur()),
                u8_table.into(),
            )]
        });

        meta.lookup("DecoderConfig: 0 <= decoded byte < 256", |meta| {
            vec![(
                meta.query_advice(config.decoded_byte, Rotation::cur()),
                u8_table.into(),
            )]
        });

        meta.create_gate("DecoderConfig: first row", |meta| {
            let condition = meta.query_fixed(config.q_first, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            // byte_idx initialises at 1.
            cb.require_equal(
                "byte_idx == 1",
                meta.query_advice(config.byte_idx, Rotation::cur()),
                1.expr(),
            );

            // tag_idx is initialised correctly.
            cb.require_equal(
                "tag_idx == 1",
                meta.query_advice(config.tag_config.tag_idx, Rotation::cur()),
                1.expr(),
            );

            // The first tag we process is the FrameHeaderDescriptor.
            cb.require_equal(
                "tag == FrameHeaderDescriptor",
                meta.query_advice(config.tag_config.tag, Rotation::cur()),
                ZstdTag::FrameHeaderDescriptor.expr(),
            );

            // encoded_rlc initialises at 0.
            cb.require_zero(
                "encoded_rlc == 0",
                meta.query_advice(config.encoded_rlc, Rotation::cur()),
            );

            // decoded_rlc iniialises at 0.
            cb.require_zero(
                "decoded_rlc == 0",
                meta.query_advice(config.decoded_rlc, Rotation::cur()),
            );

            // decoded_len accumulator initialises at 0.
            cb.require_zero(
                "decoded_len_acc == 0",
                meta.query_advice(config.decoded_len_acc, Rotation::cur()),
            );

            cb.gate(condition)
        });

        meta.create_gate("DecoderConfig: all non-padded rows", |meta| {
            let condition = not::expr(meta.query_advice(config.is_padding, Rotation::cur()));

            let mut cb = BaseConstraintBuilder::default();

            // byte decomposed into bits.
            let bits = config
                .bits
                .map(|bit| meta.query_advice(bit, Rotation::cur()));
            for bit in bits.iter() {
                cb.require_boolean("bit in [0, 1]", bit.expr());
            }
            cb.require_equal(
                "bits are the binary decomposition of byte",
                meta.query_advice(config.byte, Rotation::cur()),
                select::expr(
                    meta.query_advice(config.tag_config.is_reverse, Rotation::cur()),
                    // LE if reverse
                    bits[7].expr()
                        + bits[6].expr() * 2.expr()
                        + bits[5].expr() * 4.expr()
                        + bits[4].expr() * 8.expr()
                        + bits[3].expr() * 16.expr()
                        + bits[2].expr() * 32.expr()
                        + bits[1].expr() * 64.expr()
                        + bits[0].expr() * 128.expr(),
                    // BE if not reverse
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

            // Constrain boolean columns.
            cb.require_boolean(
                "TagConfig::is_change in [0, 1]",
                meta.query_advice(config.tag_config.is_change, Rotation::cur()),
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
            degree_reduction_check!(
                config.tag_config.is_frame_content_size,
                is_frame_content_size(meta)
            );
            degree_reduction_check!(config.tag_config.is_block_header, is_block_header(meta));

            cb.gate(condition)
        });

        meta.create_gate("DecoderConfig: all except the first row", |meta| {
            let condition = and::expr([
                not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // byte_idx either remains the same or increments by 1.
            let byte_idx_delta = meta.query_advice(config.byte_idx, Rotation::cur())
                - meta.query_advice(config.byte_idx, Rotation::prev());
            cb.require_boolean(
                "(byte_idx::cur - byte_idx::prev) in [0, 1]",
                byte_idx_delta.expr(),
            );

            // If byte_idx has not incremented, we see the same byte.
            cb.condition(not::expr(byte_idx_delta.expr()), |cb| {
                cb.require_equal(
                    "if byte_idx::cur == byte_idx::prev then byte::cur == byte::prev",
                    meta.query_advice(config.byte, Rotation::cur()),
                    meta.query_advice(config.byte, Rotation::prev()),
                );
            });

            // If the previous tag was done processing, verify that the is_change boolean was set.
            let tag_idx_eq_tag_len = config.tag_config.tag_idx_eq_tag_len.expr();
            cb.condition(and::expr([byte_idx_delta, tag_idx_eq_tag_len]), |cb| {
                cb.require_equal(
                    "is_change is set",
                    meta.query_advice(config.tag_config.is_change, Rotation::cur()),
                    1.expr(),
                );
            });

            // decoded_len is unchanged.
            cb.require_equal(
                "decoded_len::cur == decoded_len::prev",
                meta.query_advice(config.decoded_len, Rotation::cur()),
                meta.query_advice(config.decoded_len, Rotation::prev()),
            );

            cb.gate(condition)
        });

        meta.lookup_any("DecoderConfig: lookup RomTagTable", |meta| {
            let condition = meta.query_fixed(config.q_first, Rotation::cur())
                + meta.query_advice(config.tag_config.is_change, Rotation::cur());

            [
                meta.query_advice(config.tag_config.tag, Rotation::cur()),
                meta.query_advice(config.tag_config.tag_next, Rotation::cur()),
                meta.query_advice(config.tag_config.max_len, Rotation::cur()),
                meta.query_advice(config.tag_config.is_output, Rotation::cur()),
                meta.query_advice(config.tag_config.is_reverse, Rotation::cur()),
                meta.query_advice(config.block_config.is_block, Rotation::cur()),
            ]
            .into_iter()
            .zip_eq(config.rom_tag_table.table_exprs(meta))
            .map(|(value, table)| (condition.expr() * value, table))
            .collect()
        });

        meta.create_gate("DecoderConfig: new tag", |meta| {
            let condition = meta.query_advice(config.tag_config.is_change, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            // The previous tag was processed completely.
            cb.require_equal(
                "tag_idx::prev == tag_len::prev",
                meta.query_advice(config.tag_config.tag_idx, Rotation::prev()),
                meta.query_advice(config.tag_config.tag_len, Rotation::prev()),
            );

            // Tag change also implies that the byte_idx transition did happen.
            cb.require_equal(
                "byte_idx::prev + 1 == byte_idx::cur",
                meta.query_advice(config.byte_idx, Rotation::prev()) + 1.expr(),
                meta.query_advice(config.byte_idx, Rotation::cur()),
            );

            // The current tag is in fact the tag_next promised while processing the previous tag.
            cb.require_equal(
                "tag_next::prev == tag::cur",
                meta.query_advice(config.tag_config.tag_next, Rotation::prev()),
                meta.query_advice(config.tag_config.tag, Rotation::cur()),
            );

            // If the previous tag was processed from back-to-front, the RLC of the tag bytes had
            // initialised at the last byte.
            let prev_tag_reverse =
                meta.query_advice(config.tag_config.is_reverse, Rotation::prev());
            cb.condition(prev_tag_reverse, |cb| {
                cb.require_equal(
                    "tag_rlc::prev == byte::prev",
                    meta.query_advice(config.tag_config.tag_rlc, Rotation::prev()),
                    meta.query_advice(config.byte, Rotation::prev()),
                );
            });

            // The tag_idx is initialised correctly.
            cb.require_equal(
                "tag_idx::cur == 1",
                meta.query_advice(config.tag_config.tag_idx, Rotation::cur()),
                1.expr(),
            );

            // If the new tag is not processed from back-to-front, the RLC of the tag bytes
            // initialises at the first byte.
            let curr_tag_reverse = meta.query_advice(config.tag_config.is_reverse, Rotation::cur());
            cb.condition(not::expr(curr_tag_reverse), |cb| {
                cb.require_equal(
                    "tag_rlc::cur == byte::cur",
                    meta.query_advice(config.tag_config.tag_rlc, Rotation::cur()),
                    meta.query_advice(config.byte, Rotation::cur()),
                );
            });

            // The RLC of encoded bytes is computed correctly.
            cb.require_equal(
                "encoded_rlc::cur == encoded_rlc::prev * (r ^ tag_len::prev) + tag_rlc::prev",
                meta.query_advice(config.encoded_rlc, Rotation::cur()),
                meta.query_advice(config.encoded_rlc, Rotation::prev())
                    * meta.query_advice(config.tag_config.rpow_tag_len, Rotation::prev())
                    + meta.query_advice(config.tag_config.tag_rlc, Rotation::prev()),
            );

            cb.gate(condition)
        });

        meta.create_gate("DecoderConfig: continue same tag", |meta| {
            let condition = and::expr([
                not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
                not::expr(meta.query_advice(config.tag_config.is_change, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // Fields that are maintained while processing the same tag.
            for column in [
                config.tag_config.tag,
                config.tag_config.tag_next,
                config.tag_config.tag_len,
                config.tag_config.max_len,
                config.tag_config.rpow_tag_len,
                config.tag_config.is_output,
                config.tag_config.is_reverse,
                config.block_config.is_block,
                config.encoded_rlc,
            ] {
                cb.require_equal(
                    "tag_config field unchanged while processing same tag",
                    meta.query_advice(column, Rotation::cur()),
                    meta.query_advice(column, Rotation::prev()),
                );
            }

            // tag_idx increments with byte_idx.
            let byte_idx_delta = meta.query_advice(config.byte_idx, Rotation::cur())
                - meta.query_advice(config.byte_idx, Rotation::prev());
            cb.require_equal(
                "tag_idx::cur - tag_idx::prev == byte_idx::cur - byte_idx::prev",
                meta.query_advice(config.tag_config.tag_idx, Rotation::cur()),
                meta.query_advice(config.tag_config.tag_idx, Rotation::prev())
                    + byte_idx_delta.expr(),
            );

            // tag_rlc is computed correctly, i.e. its accumulated with byte_idx increment, however
            // remains unchanged if byte_idx remains unchanged.
            //
            // Furthermore the accumulation logic depends on whether the current tag is processed
            // from back-to-front or not.
            let byte_prev = meta.query_advice(config.byte, Rotation::prev());
            let byte_curr = meta.query_advice(config.byte, Rotation::cur());
            let tag_rlc_prev = meta.query_advice(config.tag_config.tag_rlc, Rotation::prev());
            let tag_rlc_curr = meta.query_advice(config.tag_config.tag_rlc, Rotation::cur());
            let curr_tag_reverse = meta.query_advice(config.tag_config.is_reverse, Rotation::cur());
            cb.condition(not::expr(byte_idx_delta.expr()), |cb| {
                cb.require_equal(
                    "tag_rlc::cur == tag_rlc::prev",
                    tag_rlc_curr.expr(),
                    tag_rlc_prev.expr(),
                );
            });
            cb.condition(
                and::expr([byte_idx_delta.expr(), curr_tag_reverse.expr()]),
                |cb| {
                    cb.require_equal(
                        "tag_rlc::prev == tag_rlc::cur * r + byte::prev",
                        tag_rlc_prev.expr(),
                        tag_rlc_curr.expr() * challenges.keccak_input() + byte_prev,
                    );
                },
            );
            cb.condition(
                and::expr([byte_idx_delta.expr(), not::expr(curr_tag_reverse.expr())]),
                |cb| {
                    cb.require_equal(
                        "tag_rlc::cur == tag_rlc::prev * r + byte::cur",
                        tag_rlc_curr.expr(),
                        tag_rlc_prev.expr() * challenges.keccak_input() + byte_curr,
                    );
                },
            );

            cb.gate(condition)
        });

        meta.lookup_any("DecoderConfig: keccak randomness power tag_len", |meta| {
            let condition = and::expr([
                meta.query_advice(config.tag_config.is_change, Rotation::cur()),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            [
                1.expr(),                                                           // enabled
                meta.query_advice(config.tag_config.tag_len, Rotation::cur()),      // exponent
                meta.query_advice(config.tag_config.rpow_tag_len, Rotation::cur()), // exponentiation
            ]
            .into_iter()
            .zip_eq(pow_rand_table.table_exprs(meta))
            .map(|(value, table)| (condition.expr() * value, table))
            .collect()
        });

        meta.create_gate(
            "DecoderConfig: when byte is decoded (output region)",
            |meta| {
                let condition = meta.query_advice(config.tag_config.is_output, Rotation::cur());

                let mut cb = BaseConstraintBuilder::default();

                // decoded_len increments.
                cb.require_equal(
                    "decoded_len_acc::cur == decoded_len_acc::prev + 1",
                    meta.query_advice(config.decoded_len_acc, Rotation::cur()),
                    meta.query_advice(config.decoded_len_acc, Rotation::prev()) + 1.expr(),
                );

                // decoded_rlc accumulates correctly.
                cb.require_equal(
                    "decoded_rlc::cur == decoded_rlc::prev * r + decoded_byte::cur",
                    meta.query_advice(config.decoded_rlc, Rotation::cur()),
                    meta.query_advice(config.decoded_rlc, Rotation::prev())
                        * challenges.keccak_input()
                        + meta.query_advice(config.decoded_byte, Rotation::cur()),
                );

                cb.gate(condition)
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////// ZstdTag::FrameHeaderDescriptor /////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: tag FrameHeaderDescriptor", |meta| {
            let condition = is_frame_header_descriptor(meta);

            let mut cb = BaseConstraintBuilder::default();

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
            //
            // Note: Since this is a single byte tag, it is processed normally, not back-to-front.
            // Hence is_reverse is False and we have BE bytes.
            cb.require_equal(
                "FHD: Single_Segment_Flag",
                meta.query_advice(config.bits[5], Rotation::cur()),
                1.expr(),
            );
            cb.require_zero(
                "FHD: Unused_Bit",
                meta.query_advice(config.bits[4], Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Reserved_Bit",
                meta.query_advice(config.bits[3], Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Content_Checksum_Flag",
                meta.query_advice(config.bits[2], Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Dictionary_ID_Flag",
                meta.query_advice(config.bits[1], Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Dictionary_ID_Flag",
                meta.query_advice(config.bits[0], Rotation::cur()),
            );

            // Checks for the next tag, i.e. FrameContentSize.
            let fcs_flag0 = meta.query_advice(config.bits[7], Rotation::cur());
            let fcs_flag1 = meta.query_advice(config.bits[6], Rotation::cur());
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
                "tag_len::next == fcs_field_size",
                meta.query_advice(config.tag_config.tag_len, Rotation::next()),
                fcs_field_size,
            );

            cb.gate(condition)
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////// ZstdTag::FrameContentSize ////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: tag FrameContentSize", |meta| {
            let condition = and::expr([
                meta.query_advice(config.tag_config.is_frame_content_size, Rotation::cur()),
                meta.query_advice(config.tag_config.is_change, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // The previous row is FrameHeaderDescriptor.
            let fcs_flag0 = meta.query_advice(config.bits[7], Rotation::prev());
            let fcs_flag1 = meta.query_advice(config.bits[6], Rotation::prev());

            // - [1, 1]: 8 bytes
            // - [1, 0]: 4 bytes
            // - [0, 1]: 2 bytes
            // - [0, 0]: 1 bytes
            let case1 = and::expr([fcs_flag0.expr(), fcs_flag1.expr()]);
            let case2 = fcs_flag0.expr();
            let case3 = fcs_flag1.expr();

            // FrameContentSize are LE bytes.
            let case4_value = meta.query_advice(config.byte, Rotation::cur());
            let case3_value = meta.query_advice(config.byte, Rotation::cur()) * 256.expr()
                + meta.query_advice(config.byte, Rotation::next());
            let case2_value = meta.query_advice(config.byte, Rotation(0)) * 16777216.expr()
                + meta.query_advice(config.byte, Rotation(1)) * 65536.expr()
                + meta.query_advice(config.byte, Rotation(2)) * 256.expr()
                + meta.query_advice(config.byte, Rotation(3));
            let case1_value = meta.query_advice(config.byte, Rotation(0))
                * 72057594037927936u64.expr()
                + meta.query_advice(config.byte, Rotation(1)) * 281474976710656u64.expr()
                + meta.query_advice(config.byte, Rotation(2)) * 1099511627776u64.expr()
                + meta.query_advice(config.byte, Rotation(3)) * 4294967296u64.expr()
                + meta.query_advice(config.byte, Rotation(4)) * 16777216.expr()
                + meta.query_advice(config.byte, Rotation(5)) * 65536.expr()
                + meta.query_advice(config.byte, Rotation(6)) * 256.expr()
                + meta.query_advice(config.byte, Rotation(7));

            let frame_content_size = select::expr(
                case1,
                case1_value,
                select::expr(
                    case2,
                    case2_value,
                    select::expr(case3, 256.expr() + case3_value, case4_value),
                ),
            );

            // decoded_len of the entire frame is in fact the decoded value of frame content size.
            cb.require_equal(
                "Frame_Content_Size == decoded_len",
                frame_content_size,
                meta.query_advice(config.decoded_len, Rotation::cur()),
            );

            cb.gate(condition)
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// ZstdTag::BlockHeader ///////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: tag BlockHeader", |meta| {
            let condition = and::expr([
                meta.query_advice(config.tag_config.is_block_header, Rotation::cur()),
                meta.query_advice(config.tag_config.is_change, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // BlockHeader is fixed-sized tag.
            cb.require_equal(
                "tag_len(BlockHeader) is fixed-sized",
                meta.query_advice(config.tag_config.tag_len, Rotation::cur()),
                N_BLOCK_HEADER_BYTES.expr(),
            );

            // Structure of Block_Header is as follows:
            //
            // | Last_Block | Block_Type | Block_Size |
            // |------------|------------|------------|
            // | bit 0      | bits 1-2   | bits 3-23  |
            //
            let is_last_block = meta.query_advice(config.bits[0], Rotation::cur());
            let block_type_bit1 = meta.query_advice(config.bits[1], Rotation::cur());
            let block_type_bit2 = meta.query_advice(config.bits[2], Rotation::cur());

            // We expect a Block_Type of Compressed_Block, i.e. Block_Type == 2.
            cb.require_equal(
                "Block_Type is Compressed_Block (bit 1)",
                block_type_bit1,
                0.expr(),
            );
            cb.require_equal(
                "Block_Type is Compressed_Block (bit 2)",
                block_type_bit2,
                1.expr(),
            );

            // is_last_block is assigned correctly.
            cb.require_equal(
                "is_last_block assigned correctly",
                meta.query_advice(
                    config.block_config.is_last_block,
                    Rotation(N_BLOCK_HEADER_BYTES as i32),
                ),
                is_last_block,
            );

            // block_idx initialises at 1.
            cb.require_equal(
                "block_idx == 1 after Block_Header",
                meta.query_advice(
                    config.block_config.block_idx,
                    Rotation(N_BLOCK_HEADER_BYTES as i32),
                ),
                1.expr(),
            );

            // Check that the last block ended correctly.
            //
            // Note: even if this is the first block, the below constraint would be satisfied
            // because both block_idx and block_len would be 0.
            cb.require_equal(
                "block_idx::prev == block_len::prev",
                meta.query_advice(config.block_config.block_idx, Rotation::prev()),
                meta.query_advice(config.block_config.block_len, Rotation::prev()),
            );

            cb.gate(condition)
        });

        meta.lookup("DecoderConfig: tag BlockHeader (Block_Size)", |meta| {
            let condition = and::expr([
                meta.query_advice(config.tag_config.is_block_header, Rotation::cur()),
                meta.query_advice(config.tag_config.is_change, Rotation::cur()),
            ]);

            // block_size == block_header >> 3
            //
            // i.e. block_header - (block_size * (2^3)) < 8
            let block_header_lc = meta.query_advice(config.byte, Rotation(2)) * 65536.expr()
                + meta.query_advice(config.byte, Rotation(1)) * 256.expr()
                + meta.query_advice(config.byte, Rotation(0));
            let block_size = meta.query_advice(
                config.block_config.block_len,
                Rotation(N_BLOCK_HEADER_BYTES as i32),
            );
            let diff = block_header_lc - (block_size * 8.expr());

            vec![(condition * diff, config.range8.into())]
        });

        meta.create_gate("DecoderConfig: processing block content", |meta| {
            let condition = meta.query_advice(config.block_config.is_block, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            // is_last_block remains unchanged.
            cb.require_equal(
                "is_last_block::cur == is_last_block::prev",
                meta.query_advice(config.block_config.is_last_block, Rotation::cur()),
                meta.query_advice(config.block_config.is_last_block, Rotation::prev()),
            );

            // block_len remains unchanged.
            cb.require_equal(
                "block_len::cur == block_len::prev",
                meta.query_advice(config.block_config.block_len, Rotation::cur()),
                meta.query_advice(config.block_config.block_len, Rotation::prev()),
            );

            // block_idx increments with byte_idx.
            let block_idx_delta = meta.query_advice(config.byte_idx, Rotation::cur())
                - meta.query_advice(config.byte_idx, Rotation::prev());
            cb.require_equal(
                "block_idx::cur - block_idx::prev == byte_idx::cur - byte_idx::prev",
                meta.query_advice(config.block_config.block_idx, Rotation::cur()),
                meta.query_advice(config.block_config.block_idx, Rotation::prev())
                    + block_idx_delta,
            );

            cb.gate(condition)
        });

        // TODO: handling end of blocks:
        // - next tag is BlockHeader or Null (if last block)
        // - blocks can end only on certain zstd tags
        // - decoded_len_acc has reached decoded_len

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////// ZstdTag::ZstdBlockLiteralsHeader ////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: tag ZstdBlockLiteralsHeader", |meta| {
            let condition = and::expr([
                is_zb_literals_header(meta),
                meta.query_advice(config.tag_config.is_change, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            let literals_block_type_bit0 = meta.query_advice(config.bits[0], Rotation::cur());
            let literals_block_type_bit1 = meta.query_advice(config.bits[1], Rotation::cur());

            // We expect a Raw_Literals_Block, i.e. bit0 and bit1 are both 0.
            cb.require_zero("Raw_Literals_Block: bit0", literals_block_type_bit0);
            cb.require_zero("Raw_Literals_Block: bit1", literals_block_type_bit1);

            let size_format_bit0 = meta.query_advice(config.bits[2], Rotation::cur());
            let size_format_bit1 = meta.query_advice(config.bits[3], Rotation::cur());

            // - Size_Format is 00 or 10: Size_Format uses 1 bit, literals header is 1 byte
            // - Size_Format is 01: Size_Format uses 2 bits, literals header is 2 bytes
            // - Size_Format is 10: Size_Format uses 2 bits, literals header is 3 bytes
            let expected_tag_len = select::expr(
                not::expr(size_format_bit0),
                1.expr(),
                select::expr(size_format_bit1, 3.expr(), 2.expr()),
            );
            cb.require_equal(
                "ZstdBlockLiteralsHeader: tag_len == expected_tag_len",
                meta.query_advice(config.tag_config.tag_len, Rotation::cur()),
                expected_tag_len,
            );

            cb.gate(condition)
        });

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockLiteralsHeader decomposition to regen size",
            |meta| {
                let condition = and::expr([
                    is_zb_literals_header(meta),
                    meta.query_advice(config.tag_config.is_change, Rotation::cur()),
                ]);

                let size_format_bit0 = meta.query_advice(config.bits[2], Rotation::cur());
                let size_format_bit1 = meta.query_advice(config.bits[3], Rotation::cur());

                // - byte0 is the first byte of the literals header
                // - byte1 is either the second byte of the literals header or 0
                // - byte2 is either the third byte of the literals header or 0
                let byte0 = meta.query_advice(config.byte, Rotation(0));
                let byte1 = select::expr(
                    size_format_bit0.expr(),
                    meta.query_advice(config.byte, Rotation(1)),
                    0.expr(),
                );
                let byte2 = select::expr(
                    size_format_bit1.expr() * size_format_bit1.expr(),
                    meta.query_advice(config.byte, Rotation(2)),
                    0.expr(),
                );

                // The regenerated size is in fact the tag length of the ZstdBlockLiteralsRawBytes
                // tag. But depending on how many bytes are in the literals header, we select the
                // appropriate offset to read the tag_len from.
                let regen_size = select::expr(
                    size_format_bit0.expr() * not::expr(size_format_bit1.expr()),
                    meta.query_advice(config.tag_config.tag_len, Rotation(2)),
                    select::expr(
                        size_format_bit1.expr() * not::expr(size_format_bit0.expr()),
                        meta.query_advice(config.tag_config.tag_len, Rotation(3)),
                        meta.query_advice(config.tag_config.tag_len, Rotation(1)),
                    ),
                );

                [
                    meta.query_advice(config.byte_idx, Rotation::cur()),
                    byte0,
                    byte1,
                    byte2,
                    size_format_bit0,
                    size_format_bit1,
                    regen_size,
                    0.expr(), // not padding
                ]
                .into_iter()
                .zip_eq(config.literals_header_table.table_exprs(meta))
                .map(|(value, table)| (condition.expr() * value, table))
                .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////// ZstdTag::ZstdBlockLiteralsRawBytes ////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: ZstdBlockLiteralsRawBytes", |meta| {
            let condition = is_zb_raw_block(meta);

            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "byte_idx::cur == byte_idx::prev + 1",
                meta.query_advice(config.byte_idx, Rotation::cur()),
                meta.query_advice(config.byte_idx, Rotation::prev()) + 1.expr(),
            );

            cb.gate(condition)
        });

        debug_assert!(meta.degree() <= 9);

        config
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<AssignedDecoderConfigExports, Error> {
        unimplemented!()
    }
}
