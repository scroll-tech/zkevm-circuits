mod tables;
mod witgen;

use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig},
    is_equal::{IsEqualChip, IsEqualConfig},
    less_than::{LtChip, LtConfig},
    util::{and, not, select, sum, Expr},
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter},
    halo2curves::bn256::Fr,
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{BitwiseOpTable, LookupTable, Pow2Table, PowOfRandTable, RangeTable, U8Table},
    util::Challenges,
};

use self::{
    tables::{
        BitstringTable, FseTable, FseTableKind, LiteralsHeaderTable, RomFseOrderTable,
        RomSequenceCodes, RomSequencesDataInterleavedOrder, RomTagTable,
    },
    witgen::{ZstdTag, N_BITS_PER_BYTE, N_BITS_REPEAT_FLAG, N_BITS_ZSTD_TAG, N_BLOCK_HEADER_BYTES},
};

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
    /// Decoding helpers for the sequences section header.
    sequences_header_decoder: SequencesHeaderDecoder,
    /// Config for reading and decoding bitstreams.
    bitstream_decoder: BitstreamDecoder,
    /// Config established while recovering the FSE table.
    fse_decoder: FseDecoder,
    /// Config required while applying the FSE tables on the Sequences data.
    sequences_data_decoder: SequencesDataDecoder,
    /// Range Table for [0, 8).
    range8: RangeTable<8>,
    /// Range Table for [0, 16).
    range16: RangeTable<16>,
    /// Power of 2 lookup table.
    pow2_table: Pow2Table<20>,
    /// Helper table for decoding the regenerated size from LiteralsHeader.
    literals_header_table: LiteralsHeaderTable,
    /// Helper table for decoding bitstreams.
    bitstring_table: BitstringTable,
    /// Helper table for decoding FSE tables.
    fse_table: FseTable,
    /// Helper table for sequences as instructions.
    /// TODO(enable): sequence_instruction_table: SequenceInstructionTable,
    /// ROM table for validating tag transition.
    rom_tag_table: RomTagTable,
    /// ROM table for the correct order in which FSE tables are described in the sequences section.
    rom_fse_order_table: RomFseOrderTable,
    /// ROM table for the correct interleaved order while processing tag=ZstdBlockSequencesData.
    rom_interleaved_order_table: RomSequencesDataInterleavedOrder,
    /// ROM table for sequence codes to value. LLC, MOC and MLC.
    rom_sequence_codes_table: RomSequenceCodes,
}

#[derive(Clone, Debug)]
struct TagConfig {
    /// Marks all enabled rows.
    q_enable: Column<Fixed>,
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
    /// Degree reduction: SequenceFseCode
    is_fse_code: Column<Advice>,
    /// Degree reduction: SequencesData
    is_sequence_data: Column<Advice>,
}

impl TagConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let q_enable = meta.fixed_column();
        let tag = meta.advice_column();
        let tag_idx = meta.advice_column();
        let tag_len = meta.advice_column();

        Self {
            q_enable,
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
            is_fse_code: meta.advice_column(),
            is_sequence_data: meta.advice_column(),
        }
    }
}

#[derive(Clone, Debug)]
struct BlockConfig {
    /// The number of bytes in this block.
    block_len: Column<Advice>,
    /// The index of this zstd block. The first block has a block_idx = 1.
    block_idx: Column<Advice>,
    /// Whether this block is the last block in the zstd encoded data.
    is_last_block: Column<Advice>,
    /// Helper boolean column to tell us whether we are in the block's contents. This field is not
    /// set for FrameHeaderDescriptor and FrameContentSize. For the tags that occur while decoding
    /// the block's contents, this field is set.
    is_block: Column<Advice>,
    /// Number of sequences decoded from the sequences section header in the block.
    num_sequences: Column<Advice>,
    /// For sequence decoding, the tag=ZstdBlockSequenceHeader bytes tell us the Compression_Mode
    /// utilised for Literals Lengths, Match Offsets and Match Lengths. We expect only 2
    /// possibilities:
    /// 1. Predefined_Mode (value=0)
    /// 2. Fse_Compressed_Mode (value=2)
    ///
    /// Which means a single boolean flag is sufficient to take note of which compression mode is
    /// utilised for each of the above purposes. The boolean flag will be set if we utilise the
    /// Fse_Compressed_Mode.
    compression_modes: [Column<Advice>; 3],
}

impl BlockConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            block_len: meta.advice_column(),
            block_idx: meta.advice_column(),
            is_last_block: meta.advice_column(),
            is_block: meta.advice_column(),
            num_sequences: meta.advice_column(),
            compression_modes: [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ],
        }
    }
}

impl BlockConfig {
    fn is_predefined_llt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        not::expr(meta.query_advice(self.compression_modes[0], rotation))
    }

    fn is_predefined_mot(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        not::expr(meta.query_advice(self.compression_modes[1], rotation))
    }

    fn is_predefined_mlt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        not::expr(meta.query_advice(self.compression_modes[2], rotation))
    }

    fn are_predefined_all(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Rotation,
    ) -> Expression<Fr> {
        and::expr([
            self.is_predefined_llt(meta, rotation),
            self.is_predefined_mot(meta, rotation),
            self.is_predefined_mlt(meta, rotation),
        ])
    }

    fn is_predefined(
        &self,
        meta: &mut VirtualCells<Fr>,
        fse_decoder: &FseDecoder,
        rotation: Rotation,
    ) -> Expression<Fr> {
        select::expr(
            fse_decoder.is_llt(meta, rotation),
            self.is_predefined_llt(meta, rotation),
            select::expr(
                fse_decoder.is_mlt(meta, rotation),
                self.is_predefined_mlt(meta, rotation),
                self.is_predefined_mot(meta, rotation),
            ),
        )
    }
}

#[derive(Clone, Debug)]
struct SequencesHeaderDecoder {
    /// Helper gadget to evaluate byte0 < 128.
    pub byte0_lt_0x80: LtConfig<Fr, 8>,
    /// Helper gadget to evaluate byte0 < 255.
    pub byte0_lt_0xff: LtConfig<Fr, 8>,
}

struct DecodedSequencesHeader {
    /// The number of sequences in the sequences section.
    num_sequences: Expression<Fr>,
    /// The number of bytes in the sequences section header.
    tag_len: Expression<Fr>,
    /// The compression mode's bit0 for literals length.
    comp_mode_bit0_ll: Expression<Fr>,
    /// The compression mode's bit1 for literals length.
    comp_mode_bit1_ll: Expression<Fr>,
    /// The compression mode's bit0 for offsets.
    comp_mode_bit0_om: Expression<Fr>,
    /// The compression mode's bit1 for offsets.
    comp_mode_bit1_om: Expression<Fr>,
    /// The compression mode's bit0 for match lengths.
    comp_mode_bit0_ml: Expression<Fr>,
    /// The compression mode's bit1 for match lengths.
    comp_mode_bit1_ml: Expression<Fr>,
}

impl SequencesHeaderDecoder {
    fn configure(
        meta: &mut ConstraintSystem<Fr>,
        byte: Column<Advice>,
        is_padding: Column<Advice>,
        u8_table: U8Table,
    ) -> Self {
        Self {
            byte0_lt_0x80: LtChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(byte, Rotation::cur()),
                |_| 0x80.expr(),
                u8_table.into(),
            ),
            byte0_lt_0xff: LtChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(byte, Rotation::cur()),
                |_| 0xff.expr(),
                u8_table.into(),
            ),
        }
    }

    // Decodes the sequences section header.
    fn decode(
        &self,
        meta: &mut VirtualCells<Fr>,
        byte: Column<Advice>,
        bits: &[Column<Advice>; N_BITS_PER_BYTE],
    ) -> DecodedSequencesHeader {
        let byte0_lt_0x80 = self.byte0_lt_0x80.is_lt(meta, None);
        let byte0_lt_0xff = self.byte0_lt_0xff.is_lt(meta, None);

        // - if byte0 < 128: byte0
        let branch0_num_seq = meta.query_advice(byte, Rotation(0));
        // - if byte0 < 255: ((byte0 - 0x80) << 8) + byte1
        let branch1_num_seq = ((meta.query_advice(byte, Rotation(0)) - 0x80.expr()) * 256.expr())
            + meta.query_advice(byte, Rotation(1));
        // - if byte0 == 255: byte1 + (byte2 << 8) + 0x7f00
        let branch2_num_seq = meta.query_advice(byte, Rotation(1))
            + (meta.query_advice(byte, Rotation(2)) * 256.expr())
            + 0x7f00.expr();

        let decoded_num_sequences = select::expr(
            byte0_lt_0x80.expr(),
            branch0_num_seq,
            select::expr(byte0_lt_0xff.expr(), branch1_num_seq, branch2_num_seq),
        );

        let decoded_tag_len = select::expr(
            byte0_lt_0x80.expr(),
            2.expr(),
            select::expr(byte0_lt_0xff.expr(), 3.expr(), 4.expr()),
        );

        let comp_mode_bit0_ll = select::expr(
            byte0_lt_0x80.expr(),
            meta.query_advice(bits[0], Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                meta.query_advice(bits[0], Rotation(2)),
                meta.query_advice(bits[0], Rotation(3)),
            ),
        );
        let comp_mode_bit1_ll = select::expr(
            byte0_lt_0x80.expr(),
            meta.query_advice(bits[1], Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                meta.query_advice(bits[1], Rotation(2)),
                meta.query_advice(bits[1], Rotation(3)),
            ),
        );

        let comp_mode_bit0_om = select::expr(
            byte0_lt_0x80.expr(),
            meta.query_advice(bits[2], Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                meta.query_advice(bits[2], Rotation(2)),
                meta.query_advice(bits[2], Rotation(3)),
            ),
        );
        let comp_mode_bit1_om = select::expr(
            byte0_lt_0x80.expr(),
            meta.query_advice(bits[3], Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                meta.query_advice(bits[3], Rotation(2)),
                meta.query_advice(bits[3], Rotation(3)),
            ),
        );

        let comp_mode_bit0_ml = select::expr(
            byte0_lt_0x80.expr(),
            meta.query_advice(bits[4], Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                meta.query_advice(bits[4], Rotation(2)),
                meta.query_advice(bits[4], Rotation(3)),
            ),
        );
        let comp_mode_bit1_ml = select::expr(
            byte0_lt_0x80.expr(),
            meta.query_advice(bits[5], Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                meta.query_advice(bits[5], Rotation(2)),
                meta.query_advice(bits[5], Rotation(3)),
            ),
        );

        DecodedSequencesHeader {
            num_sequences: decoded_num_sequences,
            tag_len: decoded_tag_len,
            comp_mode_bit0_ll,
            comp_mode_bit1_ll,
            comp_mode_bit0_om,
            comp_mode_bit1_om,
            comp_mode_bit0_ml,
            comp_mode_bit1_ml,
        }
    }
}

/// Fields used while decoding from bitstream while not being byte-aligned, i.e. the bitstring
/// could span over multiple bytes.
#[derive(Clone, Debug)]
pub struct BitstreamDecoder {
    /// The bit-index where the bittsring begins. 0 <= bit_index_start < 8.
    bit_index_start: Column<Advice>,
    /// The bit-index where the bitstring ends. 0 <= bit_index_end < 24.
    bit_index_end: Column<Advice>,
    /// Helper gadget to know if the bitstring was spanned over a single byte.
    bit_index_end_cmp_7: ComparatorConfig<Fr, 1>,
    /// Helper gadget to know if the bitstring was spanned over 2 bytes.
    bit_index_end_cmp_15: ComparatorConfig<Fr, 1>,
    /// Helper gadget to know if the bitstring was spanned over 3 bytes.
    bit_index_end_cmp_23: ComparatorConfig<Fr, 1>,
    /// The value of the binary bitstring.
    bitstring_value: Column<Advice>,
    /// Helper gadget to know when the bitstring value is 0. This contributes to an edge-case in
    /// decoding and reconstructing the FSE table from normalised distributions, where a value=0
    /// implies prob=-1 ("less than 1" probability). In this case, the symbol is allocated a state
    /// at the end of the FSE table, with baseline=0x00 and nb=AL, i.e. reset state.
    bitstring_value_eq_0: IsEqualConfig<Fr>,
    /// Helper gadget to know when the bitstring value is 1 or 3. This is useful in the case
    /// of decoding/reconstruction of FSE table, where a value=1 implies a special case of
    /// prob=0, where the symbol is instead followed by a 2-bit repeat flag. The repeat flag
    /// bits themselves could be followed by another 2-bit repeat flag if the repeat flag's
    /// value is 3.
    bitstring_value_eq_1: IsEqualConfig<Fr>,
    /// Helper config as per the above doc.
    bitstring_value_eq_3: IsEqualConfig<Fr>,
    /// Boolean that is set for a special case:
    /// - The bitstring that we have read in the current row is byte-aligned up to the next or the
    /// next-to-next byte. In this case, the next or the next-to-next following row(s) should have
    /// the is_nil field set.
    is_nil: Column<Advice>,
    /// Boolean that is set for a special case:
    /// - We don't read from the bitstream, i.e. we read 0 number of bits. We can witness such a
    /// case while applying an FSE table to bitstream, where the number of bits to be read from
    /// the bitstream is 0. This can happen when we decode sequences in the SequencesData tag.
    is_nb0: Column<Advice>,
    /// Helper gadget to check when bit_index_start has not changed.
    start_unchanged: IsEqualConfig<Fr>,
}

impl BitstreamDecoder {
    fn configure(
        meta: &mut ConstraintSystem<Fr>,
        is_padding: Column<Advice>,
        u8_table: U8Table,
    ) -> Self {
        let bit_index_start = meta.advice_column();
        let bit_index_end = meta.advice_column();
        let bitstring_value = meta.advice_column();
        Self {
            bit_index_start,
            bit_index_end,
            bit_index_end_cmp_7: ComparatorChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(bit_index_end, Rotation::cur()),
                |_| 7.expr(),
                u8_table.into(),
            ),
            bit_index_end_cmp_15: ComparatorChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(bit_index_end, Rotation::cur()),
                |_| 15.expr(),
                u8_table.into(),
            ),
            bit_index_end_cmp_23: ComparatorChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(bit_index_end, Rotation::cur()),
                |_| 23.expr(),
                u8_table.into(),
            ),
            bitstring_value,
            bitstring_value_eq_0: IsEqualChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(bitstring_value, Rotation::cur()),
                |_| 0.expr(),
            ),
            bitstring_value_eq_1: IsEqualChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(bitstring_value, Rotation::cur()),
                |_| 1.expr(),
            ),
            bitstring_value_eq_3: IsEqualChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(bitstring_value, Rotation::cur()),
                |_| 3.expr(),
            ),
            is_nil: meta.advice_column(),
            is_nb0: meta.advice_column(),
            start_unchanged: IsEqualChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(bit_index_start, Rotation::prev()),
                |meta| meta.query_advice(bit_index_start, Rotation::cur()),
            ),
        }
    }
}

impl BitstreamDecoder {
    /// If we skip reading any bitstring at this row, because of byte-alignment over multiple bytes
    /// from the previously read bitstring.
    fn is_nil(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.is_nil, rotation)
    }

    /// If we expect to read a bitstring at this row.
    fn is_not_nil(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        not::expr(self.is_nil(meta, rotation))
    }

    /// If the number of bits to be read from the bitstream is nb=0. This scenario occurs in the
    /// SequencesData tag section, when we are applying the FSE tables to decode sequences.
    fn is_nb0(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.is_nb0, rotation)
    }

    /// If we have read a bitstring of length > 0.
    fn is_not_nb0(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        not::expr(self.is_nb0(meta, rotation))
    }

    /// If the bitstring value is 0.
    fn is_prob_less_than1(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Rotation,
    ) -> Expression<Fr> {
        let bitstring_value = meta.query_advice(self.bitstring_value, rotation);
        self.bitstring_value_eq_0
            .expr_at(meta, rotation, bitstring_value, 1.expr())
    }

    /// While reconstructing the FSE table, indicates whether a value=1 was found, i.e. prob=0. In
    /// this case, the symbol is followed by 2-bits repeat flag instead.
    fn is_prob0(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        let bitstring_value = meta.query_advice(self.bitstring_value, rotation);
        self.bitstring_value_eq_1
            .expr_at(meta, rotation, bitstring_value, 1.expr())
    }

    /// Whether the 2-bits repeat flag was [1, 1]. In this case, the repeat flag is followed by
    /// another repeat flag.
    fn is_rb_flag3(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        let bitstream_value = meta.query_advice(self.bitstring_value, rotation);
        self.bitstring_value_eq_3
            .expr_at(meta, rotation, bitstream_value, 3.expr())
    }

    /// A bitstring strictly spans 1 byte if the bit_index at which it ends is such that:
    /// - 0 <= bit_index_end < 7.
    fn strictly_spans_one_byte(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Option<Rotation>,
    ) -> Expression<Fr> {
        let (lt, _eq) = self.bit_index_end_cmp_7.expr(meta, rotation);
        lt
    }

    /// A bitstring spans 1 byte if the bit_index at which it ends is such that:
    /// - 0 <= bit_index_end <= 7.
    fn spans_one_byte(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Option<Rotation>,
    ) -> Expression<Fr> {
        let (lt, eq) = self.bit_index_end_cmp_7.expr(meta, rotation);
        lt + eq
    }

    /// A bitstring spans 1 byte and is byte-aligned:
    /// - bit_index_end == 7.
    fn aligned_one_byte(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Option<Rotation>,
    ) -> Expression<Fr> {
        let (_lt, eq) = self.bit_index_end_cmp_7.expr(meta, rotation);
        eq
    }

    /// A bitstring strictly spans 2 bytes if the bit_index at which it ends is such that:
    /// - 8 <= bit_index_end < 15.
    fn strictly_spans_two_bytes(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Option<Rotation>,
    ) -> Expression<Fr> {
        let spans_one_byte = self.spans_one_byte(meta, rotation);
        let (lt2, _eq2) = self.bit_index_end_cmp_15.expr(meta, rotation);
        not::expr(spans_one_byte) * lt2
    }

    /// A bitstring spans 2 bytes if the bit_index at which it ends is such that:
    /// - 8 <= bit_index_end <= 15.
    #[allow(dead_code)]
    fn spans_two_bytes(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Option<Rotation>,
    ) -> Expression<Fr> {
        let spans_one_byte = self.spans_one_byte(meta, rotation);
        let (lt2, eq2) = self.bit_index_end_cmp_15.expr(meta, rotation);
        not::expr(spans_one_byte) * (lt2 + eq2)
    }

    /// A bitstring spans 2 bytes and is byte-aligned:
    /// - bit_index_end == 15.
    fn aligned_two_bytes(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Option<Rotation>,
    ) -> Expression<Fr> {
        let (_lt, eq) = self.bit_index_end_cmp_15.expr(meta, rotation);
        eq
    }

    /// A bitstring strictly spans 3 bytes if the bit_index at which it ends is such that:
    /// - 16 <= bit_index_end < 23.
    fn strictly_spans_three_bytes(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Option<Rotation>,
    ) -> Expression<Fr> {
        let (lt2, eq2) = self.bit_index_end_cmp_15.expr(meta, rotation);
        let (lt3, _eq3) = self.bit_index_end_cmp_23.expr(meta, rotation);
        not::expr(lt2 + eq2) * lt3
    }

    /// A bitstring spans 3 bytes if the bit_index at which it ends is such that:
    /// - 16 <= bit_index_end <= 23.
    #[allow(dead_code)]
    fn spans_three_bytes(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Option<Rotation>,
    ) -> Expression<Fr> {
        let (lt2, eq2) = self.bit_index_end_cmp_15.expr(meta, rotation);
        not::expr(lt2 + eq2)
    }

    /// A bitstring spans 3 bytes and is byte-aligned:
    /// - bit_index_end == 23.
    fn aligned_three_bytes(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Option<Rotation>,
    ) -> Expression<Fr> {
        let (_lt, eq) = self.bit_index_end_cmp_23.expr(meta, rotation);
        eq
    }

    /// bit_index_start' == bit_index_start.
    fn start_unchanged(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        let (bit_index_start_prev, bit_index_start_curr) = (
            meta.query_advice(self.bit_index_start, Rotation(rotation.0 - 1)),
            meta.query_advice(self.bit_index_start, rotation),
        );
        self.start_unchanged
            .expr_at(meta, rotation, bit_index_start_prev, bit_index_start_curr)
    }

    /// if is_nb0=true then 0 else bit_index_end - bit_index_start + 1.
    fn bitstring_len(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        let (bit_index_start, bit_index_end) = (
            meta.query_advice(self.bit_index_start, rotation),
            meta.query_advice(self.bit_index_end, rotation),
        );
        select::expr(
            self.is_nb0(meta, rotation),
            0.expr(),
            bit_index_end - bit_index_start + 1.expr(),
        )
    }

    /// bit_index_end - bit_index_start + 1.
    fn bitstring_len_unchecked(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Rotation,
    ) -> Expression<Fr> {
        let (bit_index_start, bit_index_end) = (
            meta.query_advice(self.bit_index_start, rotation),
            meta.query_advice(self.bit_index_end, rotation),
        );
        bit_index_end - bit_index_start + 1.expr()
    }
}

#[derive(Clone, Debug)]
pub struct FseDecoder {
    /// The FSE table that is being decoded in this tag. Possible values are:
    /// - LLT = 0, MOT = 1, MLT = 2
    table_kind: Column<Advice>,
    /// The number of states in the FSE table. table_size == 1 << AL, where AL is the accuracy log
    /// of the FSE table.
    table_size: Column<Advice>,
    /// The incremental symbol for which probability is decoded.
    symbol: Column<Advice>,
    /// An accumulator of the number of states allocated to each symbol as we decode the FSE table.
    /// This is the normalised probability for the symbol.
    probability_acc: Column<Advice>,
    /// Whether we are in the repeat bits loop.
    is_repeat_bits_loop: Column<Advice>,
}

impl FseDecoder {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            table_kind: meta.advice_column(),
            table_size: meta.advice_column(),
            symbol: meta.advice_column(),
            probability_acc: meta.advice_column(),
            is_repeat_bits_loop: meta.advice_column(),
        }
    }
}

impl FseDecoder {
    fn is_llt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        let table_kind = meta.query_advice(self.table_kind, rotation);
        let invert_of_2 = Fr::from(2).invert().expect("infallible");
        (FseTableKind::MLT.expr() - table_kind.expr())
            * (FseTableKind::MOT.expr() - table_kind.expr())
            * invert_of_2
    }

    fn is_mlt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        let table_kind = meta.query_advice(self.table_kind, rotation);
        (table_kind.expr() - FseTableKind::LLT.expr())
            * (FseTableKind::MOT.expr() - table_kind.expr())
    }

    fn is_mot(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        let table_kind = meta.query_advice(self.table_kind, rotation);
        let invert_of_2 = Fr::from(2).invert().expect("infallible");
        (table_kind.expr() - FseTableKind::LLT.expr())
            * (table_kind.expr() - FseTableKind::MLT.expr())
            * invert_of_2
    }
}

#[derive(Clone, Debug)]
pub struct SequencesDataDecoder {
    /// The incremental index of the sequence. The first sequence has an index of idx=1.
    idx: Column<Advice>,
    /// A boolean column to identify rows where we are finding the initial state of the FSE table.
    /// This is tricky since the order is not the same as the below interleaved order of decoding
    /// sequences. The is_init_state flag is set only while reading the first 3 bitstrings (after
    /// the sentinel bitstring) to compute the initial states of LLT -> MOT -> MLT in this order.
    is_init_state: Column<Advice>,
    /// A boolean column to help us determine the exact purpose of the bitstring we are currently
    /// reading. Since the sequences data is interleaved with 6 possible variants:
    /// 1. MOT Code to Value
    /// 2. MLT Code to Value
    /// 3. LLT Code to Value
    /// 4. LLT FSE update
    /// 5. MLT FSE update
    /// 6. MOT FSE update, goto #1
    ///
    /// The tuple:
    /// (
    ///     fse_decoder.table_kind,
    ///     sequences_data_decoder.is_update_state,
    /// )
    ///
    /// tells us exactly which variant we are at currently.
    is_update_state: Column<Advice>,
    /// The states (LLT, MLT, MOT) at this row.
    states: [Column<Advice>; 3],
    /// The symbols emitted at this state (LLT, MLT, MOT).
    symbols: [Column<Advice>; 3],
    /// The values computed for literal length, match length and match offset.
    values: [Column<Advice>; 3],
    /// The baseline value associated with this state.
    baseline: Column<Advice>,
}

impl SequencesDataDecoder {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            idx: meta.advice_column(),
            is_init_state: meta.advice_column(),
            is_update_state: meta.advice_column(),
            states: [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ],
            symbols: [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ],
            values: [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ],
            baseline: meta.advice_column(),
        }
    }
}

impl SequencesDataDecoder {
    fn is_init_state(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.is_init_state, rotation)
    }

    fn is_update_state(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.is_update_state, rotation)
    }

    fn is_code_to_value(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        and::expr([
            not::expr(self.is_init_state(meta, rotation)),
            not::expr(self.is_update_state(meta, rotation)),
        ])
    }

    fn state_llt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.states[0], rotation)
    }

    fn state_mlt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.states[1], rotation)
    }

    fn state_mot(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.states[2], rotation)
    }

    fn symbol_llt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.symbols[0], rotation)
    }

    fn symbol_mlt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.symbols[1], rotation)
    }

    fn symbol_mot(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.symbols[2], rotation)
    }

    fn state(
        &self,
        meta: &mut VirtualCells<Fr>,
        fse_decoder: &FseDecoder,
        rotation: Rotation,
    ) -> Expression<Fr> {
        select::expr(
            fse_decoder.is_llt(meta, rotation),
            self.state_llt(meta, rotation),
            select::expr(
                fse_decoder.is_mlt(meta, rotation),
                self.state_mlt(meta, rotation),
                self.state_mot(meta, rotation),
            ),
        )
    }

    fn state_at_prev(
        &self,
        meta: &mut VirtualCells<Fr>,
        fse_decoder: &FseDecoder,
        rotation: Rotation,
    ) -> Expression<Fr> {
        select::expr(
            fse_decoder.is_llt(meta, rotation),
            self.state_llt(meta, Rotation(rotation.0 - 1)),
            select::expr(
                fse_decoder.is_mlt(meta, rotation),
                self.state_mlt(meta, Rotation(rotation.0 - 1)),
                self.state_mot(meta, Rotation(rotation.0 - 1)),
            ),
        )
    }

    fn symbol(
        &self,
        meta: &mut VirtualCells<Fr>,
        fse_decoder: &FseDecoder,
        rotation: Rotation,
    ) -> Expression<Fr> {
        select::expr(
            fse_decoder.is_llt(meta, rotation),
            self.symbol_llt(meta, rotation),
            select::expr(
                fse_decoder.is_mlt(meta, rotation),
                self.symbol_mlt(meta, rotation),
                self.symbol_mot(meta, rotation),
            ),
        )
    }

    fn symbol_at_prev(
        &self,
        meta: &mut VirtualCells<Fr>,
        fse_decoder: &FseDecoder,
        rotation: Rotation,
    ) -> Expression<Fr> {
        select::expr(
            fse_decoder.is_llt(meta, rotation),
            self.symbol_llt(meta, Rotation(rotation.0 - 1)),
            select::expr(
                fse_decoder.is_mlt(meta, rotation),
                self.symbol_mlt(meta, Rotation(rotation.0 - 1)),
                self.symbol_mot(meta, Rotation(rotation.0 - 1)),
            ),
        )
    }
}

pub struct AssignedDecoderConfigExports {
    /// The RLC of the zstd encoded bytes, i.e. blob bytes.
    pub encoded_rlc: AssignedCell<Fr, Fr>,
    /// The RLC of the decoded bytes, i.e. batch bytes.
    pub decoded_rlc: AssignedCell<Fr, Fr>,
}

pub struct DecoderConfigArgs {
    /// Power of randomness table.
    pub pow_rand_table: PowOfRandTable,
    /// Power of 2 lookup table, up to exponent=20.
    pub pow2_table: Pow2Table<20>,
    /// Range table for lookup: [0, 256).
    pub u8_table: U8Table,
    /// Range table for lookup: [0, 8).
    pub range8: RangeTable<8>,
    /// Range table for lookup: [0, 16).
    pub range16: RangeTable<16>,
    /// Bitwise operation lookup table.
    pub bitwise_op_table: BitwiseOpTable,
}

impl DecoderConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        challenges: &Challenges<Expression<Fr>>,
        DecoderConfigArgs {
            pow_rand_table,
            pow2_table,
            u8_table,
            range8,
            range16,
            bitwise_op_table,
        }: DecoderConfigArgs,
    ) -> Self {
        // Fixed tables
        let rom_tag_table = RomTagTable::construct(meta);
        let rom_fse_order_table = RomFseOrderTable::construct(meta);
        let rom_interleaved_order_table = RomSequencesDataInterleavedOrder::construct(meta);
        let rom_sequence_codes_table = RomSequenceCodes::construct(meta);

        // Helper tables
        let literals_header_table = LiteralsHeaderTable::configure(meta, range8, range16);
        let bitstring_table = BitstringTable::configure(meta);
        let fse_table = FseTable::configure(meta, u8_table, range8, pow2_table, bitwise_op_table);
        // TODO(enable): let sequence_instruction_table = SequenceInstructionTable::configure(meta);

        // Peripheral configs
        let tag_config = TagConfig::configure(meta);
        let block_config = BlockConfig::configure(meta);
        let (byte, is_padding) = (meta.advice_column(), meta.advice_column());
        let sequences_header_decoder =
            SequencesHeaderDecoder::configure(meta, byte, is_padding, u8_table);
        let bitstream_decoder = BitstreamDecoder::configure(meta, is_padding, u8_table);
        let fse_decoder = FseDecoder::configure(meta);
        let sequences_data_decoder = SequencesDataDecoder::configure(meta);

        // Main config
        let config = Self {
            q_first: meta.fixed_column(),
            byte_idx: meta.advice_column(),
            byte,
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
            is_padding,
            tag_config,
            block_config,
            sequences_header_decoder,
            bitstream_decoder,
            fse_decoder,
            sequences_data_decoder,
            range8,
            range16,
            pow2_table,
            literals_header_table,
            bitstring_table,
            fse_table,
            // TODO(enable): sequence_instruction_table,
            rom_tag_table,
            rom_fse_order_table,
            rom_interleaved_order_table,
            rom_sequence_codes_table,
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
        is_tag!(is_zb_sequence_header, ZstdBlockSequenceHeader);
        is_tag!(is_zb_sequence_fse, ZstdBlockFseCode);
        // TODO: update to ZstdBlockSequenceData once witgen code is merged.
        is_tag!(is_zb_sequence_data, ZstdBlockHuffmanCode);

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

            // The first row is not padded row.
            cb.require_zero(
                "is_padding is False on the first row",
                meta.query_advice(config.is_padding, Rotation::cur()),
            );

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

        meta.create_gate("DecoderConfig: all rows except the first row", |meta| {
            let condition = not::expr(meta.query_fixed(config.q_first, Rotation::cur()));

            let mut cb = BaseConstraintBuilder::default();

            let is_padding_curr = meta.query_advice(config.is_padding, Rotation::cur());
            let is_padding_prev = meta.query_advice(config.is_padding, Rotation::prev());

            // is_padding is boolean.
            cb.require_boolean("is_padding is boolean", is_padding_curr.expr());

            // is_padding transitions from 0 -> 1 only once, i.e. is_padding_delta is boolean.
            let is_padding_delta = is_padding_curr - is_padding_prev;
            cb.require_boolean("is_padding_delta is boolean", is_padding_delta);

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
            degree_reduction_check!(config.tag_config.is_fse_code, is_zb_sequence_fse(meta));
            degree_reduction_check!(
                config.tag_config.is_sequence_data,
                is_zb_sequence_data(meta)
            );

            cb.gate(condition)
        });

        meta.create_gate(
            "DecoderConfig: all non-padded rows except the first row",
            |meta| {
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

                // If the previous tag was done processing, verify that the is_change boolean was
                // set.
                let tag_idx_prev = meta.query_advice(config.tag_config.tag_idx, Rotation::prev());
                let tag_len_prev = meta.query_advice(config.tag_config.tag_len, Rotation::prev());
                let tag_idx_eq_tag_len_prev = config.tag_config.tag_idx_eq_tag_len.expr_at(
                    meta,
                    Rotation::prev(),
                    tag_idx_prev,
                    tag_len_prev,
                );
                cb.condition(and::expr([byte_idx_delta, tag_idx_eq_tag_len_prev]), |cb| {
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
            },
        );

        meta.create_gate("DecoderConfig: padded rows", |meta| {
            let condition = and::expr([
                meta.query_advice(config.is_padding, Rotation::prev()),
                meta.query_advice(config.is_padding, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // Fields that do not change until the end of the layout once we have encountered
            // padded rows.
            for column in [config.encoded_rlc, config.decoded_rlc, config.decoded_len] {
                cb.require_equal(
                    "unchanged column in padded rows",
                    meta.query_advice(column, Rotation::cur()),
                    meta.query_advice(column, Rotation::prev()),
                );
            }

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

        meta.create_gate("DecoderConfig: tag FrameContentSize (block_idx)", |meta| {
            let condition =
                meta.query_advice(config.tag_config.is_frame_content_size, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "block_idx == 0 to start",
                meta.query_advice(config.block_config.block_idx, Rotation::cur()),
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
                meta.query_advice(config.block_config.is_last_block, Rotation::cur()),
                is_last_block,
            );

            // block_idx increments when we see a new block header.
            cb.require_equal(
                "block_idx::cur == block_idx::prev + 1",
                meta.query_advice(config.block_config.block_idx, Rotation::cur()),
                meta.query_advice(config.block_config.block_idx, Rotation::prev()) + 1.expr(),
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
            let block_size = meta.query_advice(config.block_config.block_len, Rotation::cur());
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

            // block_idx remains unchanged.
            cb.require_equal(
                "block_idx::cur == block_len::idx",
                meta.query_advice(config.block_config.block_idx, Rotation::cur()),
                meta.query_advice(config.block_config.block_idx, Rotation::prev()),
            );

            // the number of sequences in the block remains the same.
            cb.require_equal(
                "num_sequences::cur == num_sequences::prev",
                meta.query_advice(config.block_config.num_sequences, Rotation::cur()),
                meta.query_advice(config.block_config.num_sequences, Rotation::prev()),
            );

            // the compression modes are remembered throughout the block's context.
            for column in config.block_config.compression_modes {
                cb.require_equal(
                    "compression_modes::cur == compression_modes::prev (during block)",
                    meta.query_advice(column, Rotation::cur()),
                    meta.query_advice(column, Rotation::prev()),
                );
            }

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

                let block_idx = meta.query_advice(config.block_config.block_idx, Rotation::cur());
                [
                    block_idx,
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
        meta.create_gate("DecoderConfig: tag ZstdBlockLiteralsRawBytes", |meta| {
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

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////// ZstdTag::ZstdBlockSequenceHeader /////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: tag ZstdBlockSequenceHeader", |meta| {
            let condition = and::expr([
                is_zb_sequence_header(meta),
                meta.query_advice(config.tag_config.is_change, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // The Sequences_Section_Header consists of 2 items:
            // - Number of Sequences (1-3 bytes)
            // - Symbol Compression Mode (1 byte)
            let decoded_sequences_header =
                config
                    .sequences_header_decoder
                    .decode(meta, config.byte, &config.bits);

            cb.require_equal(
                "sequences header tag_len check",
                meta.query_advice(config.tag_config.tag_len, Rotation::cur()),
                decoded_sequences_header.tag_len,
            );

            cb.require_equal(
                "number of sequences in block decoded from the sequences section header",
                meta.query_advice(config.block_config.num_sequences, Rotation::cur()),
                decoded_sequences_header.num_sequences,
            );

            // The compression modes for literals length, match length and offsets are expected to
            // be either Predefined_Mode or Fse_Compressed_Mode, i.e. compression mode==0 or
            // compression_mode==2. i.e. bit0==0.
            cb.require_zero("ll: bit0 == 0", decoded_sequences_header.comp_mode_bit0_ll);
            cb.require_zero("om: bit0 == 0", decoded_sequences_header.comp_mode_bit0_om);
            cb.require_zero("ml: bit0 == 0", decoded_sequences_header.comp_mode_bit0_ml);

            // Depending on bit1==0 or bit1==1 we know whether the compression mode is
            // Predefined_Mode or Fse_Compressed_Mode. The compression_modes flag is set when
            // Fse_Compressed_Mode is utilised.
            cb.require_equal(
                "block_config: compression_modes llt",
                meta.query_advice(config.block_config.compression_modes[0], Rotation::cur()),
                decoded_sequences_header.comp_mode_bit1_ll,
            );
            cb.require_equal(
                "block_config: compression_modes mot",
                meta.query_advice(config.block_config.compression_modes[1], Rotation::cur()),
                decoded_sequences_header.comp_mode_bit1_om,
            );
            cb.require_equal(
                "block_config: compression_modes mlt",
                meta.query_advice(config.block_config.compression_modes[2], Rotation::cur()),
                decoded_sequences_header.comp_mode_bit1_ml,
            );

            // If all the three LLT, MOT and MLT use the Predefined_Mode, we have no FSE tables to
            // decode in the sequences section. And the tag=ZstdBlockSequenceHeader will
            // immediately be followed by tag=ZstdBlockSequenceData.
            let no_fse_tables = config
                .block_config
                .are_predefined_all(meta, Rotation::cur());
            cb.require_equal(
                "SequenceHeader: tag_next=FseCode or tag_next=SequencesData",
                meta.query_advice(config.tag_config.tag_next, Rotation::cur()),
                select::expr(
                    no_fse_tables,
                    // TODO: replace with SequencesData once witgen code is merged.
                    ZstdTag::ZstdBlockHuffmanCode.expr(),
                    ZstdTag::ZstdBlockFseCode.expr(),
                ),
            );

            cb.gate(condition)
        });

        // TODO: lookup(SeqInstTable) for seq_count_lookup
        // meta.lookup_any(
        //     "DecoderConfig: tag ZstdBlockSequenceHeader (sequence count)",
        //     |meta| {
        //         let condition = and::expr([
        //             is_zb_sequence_header(meta),
        //             meta.query_advice(config.tag_config.is_change, Rotation::cur()),
        //         ]);
        //         let (block_idx, num_sequences) = (
        //             meta.query_advice(config.block_config.block_idx, Rotation::cur()),
        //             meta.query_advice(config.block_config.num_sequences, Rotation::cur()),
        //         );
        //         [
        //             1.expr(), // q_enabled
        //             block_idx,
        //             1.expr(), // s_beginning
        //             num_sequences,
        //         ]
        //         .into_iter()
        //         .zip_eq(config.sequence_instruction_table.seq_count_exprs(meta))
        //         .map(|(arg, table)| (condition.expr() * arg, table))
        //         .collect()
        //     },
        // );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////// ZstdTag::ZstdBlockSequenceFseCode /////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (first row)",
            |meta| {
                // The first row of a ZstdBlockSequenceFseCode tag.
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_change, Rotation::cur()),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // At this tag=ZstdBlockSequenceFseCode we are not processing bits instead of
                // bytes. The first bitstring is the 4-bits bitstring that encodes the accuracy log
                // of the FSE table.
                cb.require_zero(
                    "fse(al): bit_index_start == 0",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                );

                cb.require_equal(
                    "fse(al): bit_index_end == 3",
                    meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
                    3.expr(),
                );

                cb.require_zero(
                    "fse(init): probability_acc=0",
                    meta.query_advice(config.fse_decoder.probability_acc, Rotation::cur()),
                );

                // The symbol=0 is handled immediately after the AL 4-bits.
                cb.require_zero(
                    "fse(init): symbol=0",
                    meta.query_advice(config.fse_decoder.symbol, Rotation::next()),
                );

                // The is_repeat_bits_loop inits at 0 after the AL 4-bits.
                cb.require_zero(
                    "fse(init): is_repeat_bits_loop=0",
                    meta.query_advice(config.fse_decoder.is_repeat_bits_loop, Rotation::next()),
                );

                // We will always start reading bits from the bitstream for the first symbol.
                cb.require_zero(
                    "fse(init): is_nil=0",
                    config.bitstream_decoder.is_nil(meta, Rotation::next()),
                );

                cb.gate(condition)
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (table kind)",
            |meta| {
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_change, Rotation::cur()),
                ]);

                [
                    meta.query_advice(config.block_config.compression_modes[0], Rotation::cur()),
                    meta.query_advice(config.block_config.compression_modes[1], Rotation::cur()),
                    meta.query_advice(config.block_config.compression_modes[2], Rotation::cur()),
                    meta.query_advice(config.tag_config.tag, Rotation::prev()), // tag_prev
                    meta.query_advice(config.tag_config.tag, Rotation::cur()),  // tag_cur
                    meta.query_advice(config.tag_config.tag_next, Rotation::cur()), // tag_next
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()), // table_kind
                ]
                .into_iter()
                .zip_eq(config.rom_fse_order_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (table size)",
            |meta| {
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_change, Rotation::cur()),
                ]);

                // accuracy_log == 4bits + 5
                let al = meta
                    .query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur())
                    + 5.expr();
                let table_size = meta.query_advice(config.fse_decoder.table_size, Rotation::cur());

                // table_size == 1 << al
                [al, table_size]
                    .into_iter()
                    .zip_eq(config.pow2_table.table_exprs(meta))
                    .map(|(arg, table)| (condition.expr() * arg, table))
                    .collect()
            },
        );

        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (other rows)",
            |meta| {
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    not::expr(meta.query_advice(config.tag_config.is_change, Rotation::cur())),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // FseDecoder columns that remain unchanged.
                for column in [config.fse_decoder.table_kind, config.fse_decoder.table_size] {
                    cb.require_equal(
                        "fse_decoder column unchanged",
                        meta.query_advice(column, Rotation::cur()),
                        meta.query_advice(column, Rotation::prev()),
                    );
                }

                // FSE tables are decoded for Literal Length (LLT), Match Offset (MOT) and Match
                // Length (MLT).
                //
                // The maximum permissible accuracy log for the above are:
                // - LLT: 9
                // - MOT: 8
                // - MLT: 9
                //
                // Which means, at the most we would be reading a bitstring up to length=9. Note
                // that an FSE table would exist only if there are more than one symbols and in
                // that case, we wouldn't actually reserve ALL possibly states for a single symbol,
                // indirectly meaning that we would be reading bitstrings of at the most length=9.
                //
                // The only scenario in which we would skip reading bits from a byte altogether is
                // if the bitstring is ``aligned_two_bytes``.
                cb.require_zero(
                    "fse: bitstrings cannot span 3 bytes",
                    config
                        .bitstream_decoder
                        .spans_three_bytes(meta, Some(Rotation::cur())),
                );

                // If the bitstring read at the current row is ``aligned_two_bytes`` then the one
                // on the next row is nil (not read).
                cb.condition(
                    config
                        .bitstream_decoder
                        .aligned_two_bytes(meta, Some(Rotation::cur())),
                    |cb| {
                        cb.require_equal(
                            "fse: aligned_two_bytes is followed by is_nil",
                            config.bitstream_decoder.is_nil(meta, Rotation::next()),
                            1.expr(),
                        );
                    },
                );

                // We now tackle the scenario of observing value=1 (prob=0) which is then followed
                // by 2-bits repeat bits.
                //
                // If we are not in a repeat-bits loop and encounter a value=1 (prob=0) bitstring,
                // then we enter a repeat bits loop.
                let is_repeat_bits_loop =
                    meta.query_advice(config.fse_decoder.is_repeat_bits_loop, Rotation::cur());
                cb.condition(
                    and::expr([
                        not::expr(is_repeat_bits_loop.expr()),
                        config.bitstream_decoder.is_prob0(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        cb.require_equal(
                            "fse: enter repeat-bits loop",
                            meta.query_advice(
                                config.fse_decoder.is_repeat_bits_loop,
                                Rotation::next(),
                            ),
                            1.expr(),
                        );
                    },
                );

                // If we are in a repeat-bits loop and the repeat-bits are [1, 1], then continue
                // the repeat-bits loop.
                let is_rb_flag3 = config.bitstream_decoder.is_rb_flag3(meta, Rotation::cur());
                cb.condition(
                    and::expr([is_repeat_bits_loop.expr(), is_rb_flag3.expr()]),
                    |cb| {
                        cb.require_equal(
                            "fse: continue repeat-bits loop",
                            meta.query_advice(
                                config.fse_decoder.is_repeat_bits_loop,
                                Rotation::next(),
                            ),
                            1.expr(),
                        );
                    },
                );

                // If we are in a repeat-bits loop and the repeat-bits are not [1, 1] then break
                // out of the repeat-bits loop.
                cb.condition(
                    and::expr([is_repeat_bits_loop.expr(), not::expr(is_rb_flag3)]),
                    |cb| {
                        cb.require_zero(
                            "fse: break out of repeat-bits loop",
                            meta.query_advice(
                                config.fse_decoder.is_repeat_bits_loop,
                                Rotation::next(),
                            ),
                        );
                    },
                );

                // We not tackle the normalised probability of symbols in the FSE table, their
                // updating and the FSE symbol itself.
                //
                // If no bitstring was read, even the symbol value is carried forward.
                let (prob_acc_cur, prob_acc_prev, fse_symbol_cur, fse_symbol_prev, value) = (
                    meta.query_advice(config.fse_decoder.probability_acc, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.probability_acc, Rotation::prev()),
                    meta.query_advice(config.fse_decoder.symbol, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.symbol, Rotation::prev()),
                    meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
                );
                cb.condition(
                    config.bitstream_decoder.is_nil(meta, Rotation::cur()),
                    |cb| {
                        cb.require_equal(
                            "fse: probability_acc continues",
                            prob_acc_cur.expr(),
                            prob_acc_prev.expr(),
                        );
                        cb.require_equal(
                            "fse: symbol continues",
                            fse_symbol_cur.expr(),
                            fse_symbol_prev.expr(),
                        );
                    },
                );

                // As we decode the normalised probability for each symbol in the FSE table, we
                // update the probability accumulator. It should be updated as long as we are
                // reading a bitstring and we are not in the repeat-bits loop.
                cb.condition(
                    and::expr([
                        config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                        not::expr(is_repeat_bits_loop.expr()),
                    ]),
                    |cb| {
                        // prob_acc_cur == prob_acc_prev + (value - 1)
                        cb.require_equal(
                            "fse: probability_acc is updated correctly",
                            prob_acc_cur.expr() + 1.expr(),
                            prob_acc_prev.expr() + value.expr(),
                        );
                        cb.require_equal(
                            "fse: symbol increments",
                            fse_symbol_cur.expr(),
                            fse_symbol_prev.expr() + 1.expr(),
                        );
                    },
                );

                // If we are in the repeat-bits loop, then the normalised probability accumulator
                // does not change, as the repeat-bits loop is for symbols that are not emitted
                // through the FSE table. However, the symbol value itself increments by the value
                // in the 2 repeat bits.
                cb.condition(is_repeat_bits_loop.expr(), |cb| {
                    let bit_index_start = meta
                        .query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur());
                    let bit_index_end =
                        meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur());
                    cb.require_equal(
                        "fse: repeat-bits read N_BITS_REPEAT_FLAG=2 bits",
                        bit_index_end - bit_index_start + 1.expr(),
                        N_BITS_REPEAT_FLAG.expr(),
                    );
                    cb.require_equal(
                        "fse: repeat-bits do not change probability_acc",
                        prob_acc_cur,
                        prob_acc_prev,
                    );
                    cb.require_equal(
                        "fse: repeat-bits increases by the 2-bit value",
                        fse_symbol_cur,
                        fse_symbol_prev + value,
                    );
                });

                cb.gate(condition)
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (normalised probability of symbol)",
            |meta| {
                // At every row where a non-nil bitstring is read:
                // - except the AL bits
                // - except when the value=1, i.e. prob=0
                // - except when we are in repeat-bits loop
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                    not::expr(meta.query_advice(config.tag_config.is_change, Rotation::cur())),
                    not::expr(config.bitstream_decoder.is_prob0(meta, Rotation::cur())),
                    not::expr(
                        meta.query_advice(config.fse_decoder.is_repeat_bits_loop, Rotation::cur()),
                    ),
                ]);

                let (block_idx, fse_table_kind, fse_table_size, fse_symbol, bitstring_value) = (
                    meta.query_advice(config.block_config.block_idx, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_size, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.symbol, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
                );
                let is_prob_less_than1 = config
                    .bitstream_decoder
                    .is_prob_less_than1(meta, Rotation::cur());
                let norm_prob = select::expr(
                    is_prob_less_than1.expr(),
                    1.expr(),
                    bitstring_value - 1.expr(),
                );

                [
                    0.expr(), // skip first row
                    block_idx,
                    fse_table_kind,
                    fse_table_size,
                    0.expr(), // is_predefined
                    fse_symbol,
                    norm_prob.expr(),
                    norm_prob.expr(),
                    is_prob_less_than1.expr(),
                    0.expr(), // is_padding
                ]
                .into_iter()
                .zip_eq(config.fse_table.table_exprs_by_symbol(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////// ZstdTag::ZstdBlockSequenceData ///////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceData (sentinel row)",
            |meta| {
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_change, Rotation::cur()),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // We read the tag=SequencesData from back-to-front, i.e. is_reverse=true. The first
                // bitstring we read is the sentinel bitstring, i.e. 0-7 number of 0s followed by a
                // sentinel 1-bit. This is used to eventually byte-align the entire SequencesData
                // bitstream.
                cb.require_zero(
                    "sentinel: is_nil=false",
                    config.bitstream_decoder.is_nil(meta, Rotation::cur()),
                );
                cb.require_zero(
                    "sentinel: is_nb0=false",
                    config.bitstream_decoder.is_nb0(meta, Rotation::cur()),
                );
                cb.require_equal(
                    "sentinel: bitstring_value=1",
                    meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
                    1.expr(),
                );
                cb.require_equal(
                    "sentinel: bit_index_end <= 7",
                    config
                        .bitstream_decoder
                        .spans_one_byte(meta, Some(Rotation::cur())),
                    1.expr(),
                );

                // The next row starts with initialising the states (with LLT), and this is in fact
                // the start of the decoding process for sequence_idx=1.
                cb.require_equal(
                    "seq_idx==1",
                    meta.query_advice(config.sequences_data_decoder.idx, Rotation::next()),
                    1.expr(),
                );

                cb.gate(condition)
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceData (interleaved order)",
            |meta| {
                // We want to check for the interleaved order within the SequencesData section
                // whenever we are reading a bitstring. We skip the first row of the
                // tag (is_change=true) since that is guaranteed to be the sentinel
                // bitstring. We also skip the row where we don't read a bitstring
                // (is_nil=true).
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    not::expr(meta.query_advice(config.tag_config.is_change, Rotation::cur())),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                ]);

                let (table_kind_prev, table_kind_curr, is_init_state, is_update_state) = (
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::prev()),
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()),
                    meta.query_advice(config.sequences_data_decoder.is_init_state, Rotation::cur()),
                    meta.query_advice(
                        config.sequences_data_decoder.is_update_state,
                        Rotation::cur(),
                    ),
                );

                [
                    table_kind_prev,
                    table_kind_curr,
                    is_init_state,
                    is_update_state,
                ]
                .into_iter()
                .zip_eq(config.rom_interleaved_order_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceData (sequences)",
            |meta| {
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    not::expr(meta.query_advice(config.tag_config.is_change, Rotation::cur())),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // - Init "state" at init-state (literal length)
                // - Init "state" at init-state (match offset)
                // - Init "state" at init-state (match length)
                cb.condition(
                    and::expr([
                        config.fse_decoder.is_llt(meta, Rotation::cur()),
                        config
                            .sequences_data_decoder
                            .is_init_state(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        cb.require_equal(
                            "llt: state == 0x00 + readBits(nb)",
                            config
                                .sequences_data_decoder
                                .state_llt(meta, Rotation::cur()),
                            meta.query_advice(
                                config.bitstream_decoder.bitstring_value,
                                Rotation::cur(),
                            ),
                        );
                    },
                );
                cb.condition(
                    and::expr([
                        config.fse_decoder.is_mot(meta, Rotation::cur()),
                        config
                            .sequences_data_decoder
                            .is_init_state(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        cb.require_equal(
                            "mot: state == 0x00 + readBits(nb)",
                            config
                                .sequences_data_decoder
                                .state_mot(meta, Rotation::cur()),
                            meta.query_advice(
                                config.bitstream_decoder.bitstring_value,
                                Rotation::cur(),
                            ),
                        );
                    },
                );
                cb.condition(
                    and::expr([
                        config.fse_decoder.is_mlt(meta, Rotation::cur()),
                        config
                            .sequences_data_decoder
                            .is_init_state(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        cb.require_equal(
                            "mlt: state == 0x00 + readBits(nb)",
                            config
                                .sequences_data_decoder
                                .state_mlt(meta, Rotation::cur()),
                            meta.query_advice(
                                config.bitstream_decoder.bitstring_value,
                                Rotation::cur(),
                            ),
                        );
                    },
                );

                // - Update "value" at code-to-value (match offset)
                // - Update "value" at code-to-value (match length)
                // - Update "value" at code-to-value (literal length)
                cb.condition(
                    and::expr([
                        config.fse_decoder.is_mot(meta, Rotation::cur()),
                        config
                            .sequences_data_decoder
                            .is_code_to_value(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        let (baseline, bitstring_value) = (
                            meta.query_advice(
                                config.sequences_data_decoder.baseline,
                                Rotation::cur(),
                            ),
                            meta.query_advice(
                                config.bitstream_decoder.bitstring_value,
                                Rotation::cur(),
                            ),
                        );
                        cb.require_equal(
                            "value(mot) update",
                            meta.query_advice(
                                config.sequences_data_decoder.values[2],
                                Rotation::cur(),
                            ),
                            baseline + bitstring_value,
                        );
                    },
                );
                cb.condition(
                    and::expr([
                        config.fse_decoder.is_mlt(meta, Rotation::cur()),
                        config
                            .sequences_data_decoder
                            .is_code_to_value(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        let (baseline, bitstring_value) = (
                            meta.query_advice(
                                config.sequences_data_decoder.baseline,
                                Rotation::cur(),
                            ),
                            meta.query_advice(
                                config.bitstream_decoder.bitstring_value,
                                Rotation::cur(),
                            ),
                        );
                        cb.require_equal(
                            "value(mlt) update",
                            meta.query_advice(
                                config.sequences_data_decoder.values[1],
                                Rotation::cur(),
                            ),
                            baseline + bitstring_value,
                        );
                    },
                );
                cb.condition(
                    and::expr([
                        config.fse_decoder.is_llt(meta, Rotation::cur()),
                        config
                            .sequences_data_decoder
                            .is_code_to_value(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        let (baseline, bitstring_value) = (
                            meta.query_advice(
                                config.sequences_data_decoder.baseline,
                                Rotation::cur(),
                            ),
                            meta.query_advice(
                                config.bitstream_decoder.bitstring_value,
                                Rotation::cur(),
                            ),
                        );
                        cb.require_equal(
                            "value(llt) update",
                            meta.query_advice(
                                config.sequences_data_decoder.values[0],
                                Rotation::cur(),
                            ),
                            baseline + bitstring_value,
                        );
                    },
                );

                // - Update "state" at update-state (literal length)
                //      - This also means we have started decoding another sequence.
                // - Update "state" at update-state (match length)
                // - Update "state" at update-state (match offset)
                cb.condition(
                    and::expr([
                        config.fse_decoder.is_llt(meta, Rotation::cur()),
                        config
                            .sequences_data_decoder
                            .is_update_state(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        let (baseline, bitstring_value) = (
                            meta.query_advice(
                                config.sequences_data_decoder.baseline,
                                Rotation::cur(),
                            ),
                            meta.query_advice(
                                config.bitstream_decoder.bitstring_value,
                                Rotation::cur(),
                            ),
                        );
                        cb.require_equal(
                            "llt: state == baseline + readBits(nb)",
                            config
                                .sequences_data_decoder
                                .state_llt(meta, Rotation::cur()),
                            baseline + bitstring_value,
                        );
                        cb.require_equal(
                            "seq_idx increments",
                            meta.query_advice(config.sequences_data_decoder.idx, Rotation::cur()),
                            meta.query_advice(config.sequences_data_decoder.idx, Rotation::prev())
                                + 1.expr(),
                        );
                    },
                );
                cb.condition(
                    and::expr([
                        config.fse_decoder.is_mlt(meta, Rotation::cur()),
                        config
                            .sequences_data_decoder
                            .is_update_state(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        let (baseline, bitstring_value) = (
                            meta.query_advice(
                                config.sequences_data_decoder.baseline,
                                Rotation::cur(),
                            ),
                            meta.query_advice(
                                config.bitstream_decoder.bitstring_value,
                                Rotation::cur(),
                            ),
                        );
                        cb.require_equal(
                            "mlt: state == baseline + readBits(nb)",
                            config
                                .sequences_data_decoder
                                .state_mlt(meta, Rotation::cur()),
                            baseline + bitstring_value,
                        );
                    },
                );
                cb.condition(
                    and::expr([
                        config.fse_decoder.is_mot(meta, Rotation::cur()),
                        config
                            .sequences_data_decoder
                            .is_update_state(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        let (baseline, bitstring_value) = (
                            meta.query_advice(
                                config.sequences_data_decoder.baseline,
                                Rotation::cur(),
                            ),
                            meta.query_advice(
                                config.bitstream_decoder.bitstring_value,
                                Rotation::cur(),
                            ),
                        );
                        cb.require_equal(
                            "mot: state == baseline + readBits(nb)",
                            config
                                .sequences_data_decoder
                                .state_mot(meta, Rotation::cur()),
                            baseline + bitstring_value,
                        );
                    },
                );

                // TODO: make sure columns don't change if not at the appropriate condition.

                cb.gate(condition)
            },
        );

        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceData (is_nil)",
            |meta| {
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    config.bitstream_decoder.is_nil(meta, Rotation::cur()),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // If we encounter an is_nil=true scenario in the tag=SequencesData region, we make
                // sure that certain columns remain unchanged, specifically: SequencesDataDecoder
                // and FseDecoder.
                for column in [
                    config.fse_decoder.table_kind,
                    config.fse_decoder.table_size,
                    config.sequences_data_decoder.idx,
                    config.sequences_data_decoder.is_init_state,
                    config.sequences_data_decoder.is_update_state,
                    config.sequences_data_decoder.states[0],
                    config.sequences_data_decoder.states[1],
                    config.sequences_data_decoder.states[2],
                    config.sequences_data_decoder.symbols[0],
                    config.sequences_data_decoder.symbols[1],
                    config.sequences_data_decoder.symbols[2],
                    config.sequences_data_decoder.values[0],
                    config.sequences_data_decoder.values[1],
                    config.sequences_data_decoder.values[2],
                ] {
                    cb.require_equal(
                        "sequencesData: is_nil=true columns unchanged",
                        meta.query_advice(column, Rotation::cur()),
                        meta.query_advice(column, Rotation::prev()),
                    );
                }

                cb.gate(condition)
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceData (ROM sequence codes)",
            |meta| {
                // When we read a bitstring in tag=ZstdBlockSequenceData that is:
                // - not init state
                // - not update state
                //
                // We know that we are trying to get the "value" from the "code" for literal length
                // or match offset or match length. Hence we do a lookup to the ROM table (Sequence
                // Codes).
                //
                // The "value" is calculated as:
                // - value == baseline + bitstring_value(nb)
                //
                // which is used in the next lookup to the SequenceInstructionTable.
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                    config
                        .sequences_data_decoder
                        .is_code_to_value(meta, Rotation::cur()),
                ]);

                let (table_kind, code, baseline, nb) = (
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()),
                    config.sequences_data_decoder.symbol(
                        meta,
                        &config.fse_decoder,
                        Rotation::cur(),
                    ),
                    meta.query_advice(config.sequences_data_decoder.baseline, Rotation::cur()),
                    config
                        .bitstream_decoder
                        .bitstring_len(meta, Rotation::cur()),
                );

                [table_kind, code, baseline, nb]
                    .into_iter()
                    .zip_eq(config.rom_sequence_codes_table.table_exprs(meta))
                    .map(|(arg, table)| (condition.expr() * arg, table))
                    .collect()
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceData (init state pow2 table)",
            |meta| {
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    config
                        .sequences_data_decoder
                        .is_init_state(meta, Rotation::cur()),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                ]);

                let (nb, table_size) = (
                    config
                        .bitstream_decoder
                        .bitstring_len_unchecked(meta, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_size, Rotation::cur()),
                );

                // When state is initialised, we must read AL number of bits.
                // Since table_size == 1 << AL, we do a lookup to the pow2 table.
                [nb, table_size]
                    .into_iter()
                    .zip_eq(config.pow2_table.table_exprs(meta))
                    .map(|(arg, table)| (condition.expr() * arg, table))
                    .collect()
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceData (init state fse table)",
            |meta| {
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                    config
                        .sequences_data_decoder
                        .is_init_state(meta, Rotation::cur()),
                ]);

                let (block_idx, table_kind, table_size) = (
                    meta.query_advice(config.block_config.block_idx, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_size, Rotation::cur()),
                );
                let is_predefined_mode =
                    config
                        .block_config
                        .is_predefined(meta, &config.fse_decoder, Rotation::cur());

                [
                    0.expr(), // q_first
                    1.expr(), // q_start
                    block_idx,
                    table_kind,
                    table_size,
                    is_predefined_mode, // is_predefined
                    0.expr(),           // is_padding
                ]
                .into_iter()
                .zip_eq(config.fse_table.table_exprs_metadata(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        // TODO(enable): lookup(SeqInstTable) at code-to-value for seq_values_lookup
        // meta.lookup_any(
        //     "DecoderConfig: tag ZstdBlockSequenceData (sequence instructions table)",
        //     |meta| {
        //         // At the row where we compute the code-to-value of LLT, we have the values for
        //         // all of match offset, match length and literal length.
        //         let condition = and::expr([
        //             meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
        //             config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
        //             config.fse_decoder.is_llt(meta, Rotation::cur()),
        //             config
        //                 .sequences_data_decoder
        //                 .is_code_to_value(meta, Rotation::cur()),
        //         ]);
        //         let (block_idx, sequence_idx) = (
        //             meta.query_advice(config.block_config.block_idx, Rotation::cur()),
        //             meta.query_advice(config.sequences_data_decoder.idx, Rotation::cur()),
        //         );
        //         let (literal_length_value, match_offset_value, match_length_value) = (
        //             meta.query_advice(config.sequences_data_decoder.values[0], Rotation::cur()),
        //             meta.query_advice(config.sequences_data_decoder.values[2], Rotation::cur()),
        //             meta.query_advice(config.sequences_data_decoder.values[1], Rotation::cur()),
        //         );
        //         [
        //             1.expr(), // q_enabled
        //             block_idx,
        //             0.expr(), // s_beginning
        //             sequence_idx,
        //             literal_length_value,
        //             match_offset_value,
        //             match_length_value,
        //         ]
        //         .into_iter()
        //         .zip_eq(config.sequence_instruction_table.seq_values_exprs(meta))
        //         .map(|(arg, table)| (condition.expr() * arg, table))
        //         .collect()
        //     },
        // );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceData (FseTable)",
            |meta| {
                let condition = and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    not::expr(meta.query_advice(config.tag_config.is_change, Rotation::cur())),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                    config
                        .sequences_data_decoder
                        .is_update_state(meta, Rotation::cur()),
                ]);

                let state = config.sequences_data_decoder.state_at_prev(
                    meta,
                    &config.fse_decoder,
                    Rotation::cur(),
                );
                let symbol = config.sequences_data_decoder.symbol_at_prev(
                    meta,
                    &config.fse_decoder,
                    Rotation::cur(),
                );
                let (block_idx, table_kind, table_size, baseline, nb) = (
                    meta.query_advice(config.block_config.block_idx, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_size, Rotation::cur()),
                    meta.query_advice(config.sequences_data_decoder.baseline, Rotation::cur()),
                    config
                        .bitstream_decoder
                        .bitstring_len(meta, Rotation::cur()),
                );
                let is_predefined_mode =
                    config
                        .block_config
                        .is_predefined(meta, &config.fse_decoder, Rotation::cur());

                [
                    0.expr(), // q_first
                    block_idx,
                    table_kind,
                    table_size,
                    is_predefined_mode, // is_predefined
                    state,
                    symbol,
                    baseline,
                    nb,
                    0.expr(), // is_skipped_state
                    0.expr(), // is_padding
                ]
                .into_iter()
                .zip_eq(config.fse_table.table_exprs_by_state(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        ///////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// Bitstream Decoding /////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: Bitstream Decoder (is_nil)", |meta| {
            // Bitstream decoder when we skip reading a bitstring at a row.
            let condition = config.bitstream_decoder.is_nil(meta, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "bit_index_start == 0",
                meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
            );
            cb.require_zero(
                "bit_index_end == 0",
                meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
            );
            cb.require_zero(
                "bit_index_start' == 0",
                meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::next()),
            );
            cb.require_equal(
                "if is_nil: byte_idx' == byte_idx",
                meta.query_advice(config.byte_idx, Rotation::next()),
                meta.query_advice(config.byte_idx, Rotation::cur()),
            );

            cb.require_zero(
                "if is_nil is True then is_nb0 is False",
                config.bitstream_decoder.is_nb0(meta, Rotation::cur()),
            );
            cb.require_equal(
                "bitstream(is_nil) can occur in [FseCode, SequencesData] tags",
                sum::expr([
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                ]),
                1.expr(),
            );

            cb.gate(condition)
        });

        meta.create_gate("DecoderConfig: Bitstream Decoder (is_nb0)", |meta| {
            // Bitstream decoder when we read nb=0 bits from the bitstream.
            let condition = config.bitstream_decoder.is_nb0(meta, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "bit_index_start == bit_index_end",
                meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
            );
            cb.require_equal(
                "bit_index_start' == bit_index_start",
                meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::next()),
                meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
            );
            cb.require_equal(
                "if is_nb0: byte_idx' == byte_idx",
                meta.query_advice(config.byte_idx, Rotation::next()),
                meta.query_advice(config.byte_idx, Rotation::cur()),
            );
            cb.require_zero(
                "if is_nb0: bitstring_value == 0",
                meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
            );

            cb.require_zero(
                "if is_nb0 is True then is_nil is False",
                config.bitstream_decoder.is_nil(meta, Rotation::cur()),
            );

            // This can only occur in tag=SequencesData.
            cb.require_equal(
                "bitstream(is_nb0) can occur in SequencesData",
                meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                1.expr(),
            );

            cb.gate(condition)
        });

        meta.create_gate(
            "DecoderConfig: Bitstream Decoder (read from bitstream)",
            |meta| {
                // Bitstream decoder when the bitstring to be read is not nil.
                let condition = and::expr([
                    not::expr(config.bitstream_decoder.is_nil(meta, Rotation::cur())),
                    not::expr(config.bitstream_decoder.is_nb0(meta, Rotation::cur())),
                    sum::expr([
                        meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                        meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    ]),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // We process bits instead of bytes for a few tags, namely, ZstdBlockSequenceFseCode
                // and ZstdBlockSequenceData. In these tags, over adjacent rows we may experience:
                // - byte_idx' == byte_idx
                // - byte_idx' == byte_idx + 1
                // depending on whether or not the bitstring read was byte-aligned.
                //
                // The maximum length of bitstring we expect at the moment is N=17, which means the
                // bitstring accumulation table supports bitstring accumulation up to 3 contiguous
                // bytes.
                //
                // We have the following scenarios:
                // - bitstring strictly spans over 1 byte: 0 <= bit_index_end < 7.
                // - bitstring is byte aligned: bit_index_end == 7.
                // - bitstring strictly spans over 2 bytes: 8 <= bit_index_end < 15.
                // - bitstring is byte aligned: bit_index_end == 15.
                // - bitstring strictly spans over 3 bytes: 16 <= bit_index_end < 23.
                // - bitstring is byte aligned: bit_index_end == 23.
                //
                // Every row is reserved for a bitstring read from the bitstream. That is, we have:
                // - bitstring_len == bit_index_end - bit_index_start + 1
                //
                // On some rows we may not be reading a bitstring. This can occur when:
                // - The number of bits to be read is 0, i.e. NB_fse == 0.
                // - The previous row read a bitstring that spanned over 2 bytes and was
                //   byte-aligned.
                //      - No bitstring is read on the current row.
                // - The previous row read a bitstring that spanned over 3 bytes.
                //      - No bitstring is read on the current row.
                // - The previous row read a bitstring that spanned over 3 bytes and was
                //   byte-aligned.
                //      - No bitstring is read on the current and next row.

                // 1. bitstring strictly spans over 1 byte: 0 <= bit_index_end < 7.
                cb.condition(
                    config
                        .bitstream_decoder
                        .strictly_spans_one_byte(meta, Some(Rotation::cur())),
                    |cb| {
                        cb.require_equal(
                            "(case1): byte_idx' == byte_idx",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()),
                        );
                        cb.require_equal(
                            "(case1): bit_index_start' == bit_index_end + 1",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation::next(),
                            ),
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_end,
                                Rotation::cur(),
                            ) + 1.expr(),
                        );
                    },
                );

                // 2. bitstring is byte-aligned: bit_index_end == 7.
                cb.condition(
                    config
                        .bitstream_decoder
                        .aligned_one_byte(meta, Some(Rotation::cur())),
                    |cb| {
                        cb.require_equal(
                            "(case2): byte_idx' == byte_idx + 1",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                        );
                        cb.require_zero(
                            "(case2): bit_index_start' == 0",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation::next(),
                            ),
                        );
                    },
                );

                // 3. bitstring strictly spans over 2 bytes: 8 <= bit_index_end < 15.
                cb.condition(
                    config
                        .bitstream_decoder
                        .strictly_spans_two_bytes(meta, Some(Rotation::cur())),
                    |cb| {
                        cb.require_equal(
                            "(case3): byte_idx' == byte_idx + 1",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                        );
                        cb.require_equal(
                            "(case3): bit_index_start' == bit_index_end - 7",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation::next(),
                            ) + 7.expr(),
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_end,
                                Rotation::cur(),
                            ),
                        );
                    },
                );

                // 4. bitstring is byte-aligned: bit_index_end == 15.
                cb.condition(
                    config
                        .bitstream_decoder
                        .aligned_two_bytes(meta, Some(Rotation::cur())),
                    |cb| {
                        cb.require_equal(
                            "(case4): byte_idx' == byte_idx + 1",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                        );
                        cb.require_equal(
                            "(case4): byte_idx'' == byte_idx + 2",
                            meta.query_advice(config.byte_idx, Rotation(2)),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 2.expr(),
                        );
                        cb.require_equal(
                            "(case4): bitstring decoder skipped next row",
                            config.bitstream_decoder.is_nil(meta, Rotation::next()),
                            1.expr(),
                        );
                        cb.require_zero(
                            "(case4): bit_index_start' == 0",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation::next(),
                            ),
                        );
                        cb.require_zero(
                            "(case4): bit_index_start'' == 0",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation(2),
                            ),
                        );
                    },
                );

                // 5. bitstring strictly spans over 3 bytes: 16 <= bit_index_end < 23.
                cb.condition(
                    config
                        .bitstream_decoder
                        .strictly_spans_three_bytes(meta, Some(Rotation::cur())),
                    |cb| {
                        cb.require_equal(
                            "(case5): byte_idx' == byte_idx + 1",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                        );
                        cb.require_equal(
                            "(case5): byte_idx'' == byte_idx + 2",
                            meta.query_advice(config.byte_idx, Rotation(2)),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 2.expr(),
                        );
                        cb.require_equal(
                            "(case5): bitstring decoder skipped next row",
                            config.bitstream_decoder.is_nil(meta, Rotation::next()),
                            1.expr(),
                        );
                        cb.require_equal(
                            "(case5): bit_index_start' == bit_index_start''",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation::next(),
                            ),
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation(2),
                            ),
                        );
                        cb.require_equal(
                            "(case5): bit_index_start'' == bit_index_end - 15",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation(2),
                            ) + 15.expr(),
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_end,
                                Rotation::cur(),
                            ),
                        );
                    },
                );

                // 6. bitstring is byte-aligned: bit_index_end == 23.
                cb.condition(
                    config
                        .bitstream_decoder
                        .aligned_three_bytes(meta, Some(Rotation::cur())),
                    |cb| {
                        cb.require_equal(
                            "(case6): byte_idx' == byte_idx + 1",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                        );
                        cb.require_equal(
                            "(case6): byte_idx'' == byte_idx + 2",
                            meta.query_advice(config.byte_idx, Rotation(2)),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 2.expr(),
                        );
                        cb.require_equal(
                            "(case6): byte_idx''' == byte_idx + 3",
                            meta.query_advice(config.byte_idx, Rotation(3)),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 3.expr(),
                        );
                        cb.require_equal(
                            "(case6): bitstring decoder skipped next row",
                            config.bitstream_decoder.is_nil(meta, Rotation::next()),
                            1.expr(),
                        );
                        cb.require_equal(
                            "(case6): bitstring decoder skipped next-to-next row",
                            config.bitstream_decoder.is_nil(meta, Rotation(2)),
                            1.expr(),
                        );
                        cb.require_zero(
                            "(case6): bit_index_start' == 0",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation::next(),
                            ),
                        );
                        cb.require_zero(
                            "(case6): bit_index_start'' == 0",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation(2),
                            ),
                        );
                        cb.require_zero(
                            "(case6): bit_index_start''' == 0",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation(3),
                            ),
                        );
                    },
                );

                cb.gate(condition)
            },
        );

        meta.create_gate("DecoderConfig: Bitstream Decoder", |meta| {
            let condition = sum::expr([
                meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // If the following conditions are met:
            // - we are on the same byte_idx
            // - bit_index_start' == bit_index_start
            //
            // Then it means we are either not reading from the bitstream, or reading nb=0 bits
            // from the bitstream.
            let (byte_idx_prev, byte_idx_curr) = (
                meta.query_advice(config.byte_idx, Rotation::prev()),
                meta.query_advice(config.byte_idx, Rotation::cur()),
            );
            let byte_idx_delta = byte_idx_curr - byte_idx_prev;
            cb.condition(
                and::expr([
                    not::expr(byte_idx_delta),
                    config
                        .bitstream_decoder
                        .start_unchanged(meta, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_equal(
                        "if byte_idx' == byte_idx and start' == start: is_nil=1 or is_nb0=1",
                        sum::expr([
                            config.bitstream_decoder.is_nil(meta, Rotation::prev()),
                            config.bitstream_decoder.is_nb0(meta, Rotation::prev()),
                        ]),
                        1.expr(),
                    );
                },
            );

            cb.gate(condition)
        });

        meta.lookup_any(
            "DecoderConfig: Bitstream Decoder (bitstring start)",
            |meta| {
                let condition = and::expr([
                    not::expr(config.bitstream_decoder.is_nil(meta, Rotation::cur())),
                    not::expr(config.bitstream_decoder.is_nb0(meta, Rotation::cur())),
                    sum::expr([
                        meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                        meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    ]),
                ]);

                let (byte_idx0, byte_idx1, byte_idx2) = (
                    meta.query_advice(config.byte_idx, Rotation(0)),
                    meta.query_advice(config.byte_idx, Rotation(1)),
                    meta.query_advice(config.byte_idx, Rotation(2)),
                );
                let (byte0, byte1, byte2) = (
                    meta.query_advice(config.byte, Rotation(0)),
                    meta.query_advice(config.byte, Rotation(1)),
                    meta.query_advice(config.byte, Rotation(2)),
                );
                let (bit_index_start, _bit_index_end, bitstring_value) = (
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
                );
                let is_reverse = meta.query_advice(config.tag_config.is_reverse, Rotation::cur());

                [
                    byte_idx0,
                    byte_idx1,
                    byte_idx2,
                    byte0,
                    byte1,
                    byte2,
                    bitstring_value,
                    1.expr(), // bitstring_len at start
                    bit_index_start,
                    1.expr(), // from_start
                    1.expr(), // until_end
                    is_reverse,
                    0.expr(), // is_padding
                ]
                .into_iter()
                .zip_eq(config.bitstring_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        meta.lookup_any("DecoderConfig: Bitstream Decoder (bitstring end)", |meta| {
            let condition = and::expr([
                not::expr(config.bitstream_decoder.is_nil(meta, Rotation::cur())),
                not::expr(config.bitstream_decoder.is_nb0(meta, Rotation::cur())),
                sum::expr([
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                ]),
            ]);

            let (byte_idx0, byte_idx1, byte_idx2) = (
                meta.query_advice(config.byte_idx, Rotation(0)),
                meta.query_advice(config.byte_idx, Rotation(1)),
                meta.query_advice(config.byte_idx, Rotation(2)),
            );
            let (byte0, byte1, byte2) = (
                meta.query_advice(config.byte, Rotation(0)),
                meta.query_advice(config.byte, Rotation(1)),
                meta.query_advice(config.byte, Rotation(2)),
            );
            let (bit_index_start, bit_index_end, bitstring_value) = (
                meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
                meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
            );
            let is_reverse = meta.query_advice(config.tag_config.is_reverse, Rotation::cur());

            [
                byte_idx0,
                byte_idx1,
                byte_idx2,
                byte0,
                byte1,
                byte2,
                bitstring_value,
                bit_index_end.expr() - bit_index_start + 1.expr(), // bitstring_len at end
                bit_index_end,
                1.expr(), // from_start
                1.expr(), // until_end
                is_reverse,
                0.expr(), // is_padding
            ]
            .into_iter()
            .zip_eq(config.bitstring_table.table_exprs(meta))
            .map(|(arg, table)| (condition.expr() * arg, table))
            .collect()
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
