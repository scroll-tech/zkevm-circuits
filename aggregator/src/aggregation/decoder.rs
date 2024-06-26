mod seq_exec;
mod tables;
pub mod witgen;

use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig, ComparatorInstruction},
    is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction},
    less_than::{LtChip, LtConfig, LtInstruction},
    util::{and, not, select, sum, Expr},
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Value},
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
        BitstringTable, FixedLookupTag, FixedTable, FseTable, LiteralsHeaderTable,
        SeqInstTable as SequenceInstructionTable,
    },
    witgen::{
        util::value_bits_le, AddressTableRow, BlockInfo, FseAuxiliaryTableData, FseTableKind,
        SequenceExec, SequenceInfo, ZstdTag, ZstdWitnessRow, N_BITS_PER_BYTE, N_BITS_REPEAT_FLAG,
        N_BITS_ZSTD_TAG, N_BLOCK_HEADER_BYTES, N_BLOCK_SIZE_TARGET,
    },
};
use super::util::BooleanAdvice;

use seq_exec::{LiteralTable, SeqExecConfig as SequenceExecutionConfig, SequenceConfig};

#[derive(Clone, Debug)]
pub struct DecoderConfig<const L: usize, const R: usize> {
    /// constant column required by SeqExecConfig.
    _const_col: Column<Fixed>,
    /// Fixed column to mark all the usable rows.
    q_enable: Column<Fixed>,
    /// Fixed column to mark the first row in the layout.
    q_first: Column<Fixed>,
    /// The byte index in the encoded data. At the first byte, byte_idx = 1.
    byte_idx: Column<Advice>,
    /// The byte value at this byte index in the encoded data.
    byte: Column<Advice>,
    /// The byte value decomposed in its bits. The endianness of bits depends on whether or not we
    /// are processing a chunk of bytes from back-to-front or not. The bits follow
    /// little-endianness if bytes are processed from back-to-front, otherwise big-endianness.
    bits: [BooleanAdvice; N_BITS_PER_BYTE],
    /// The RLC of the zstd encoded bytes.
    encoded_rlc: Column<Advice>,
    /// The size of the final decoded bytes.
    decoded_len: Column<Advice>,
    /// Once all the encoded bytes are decoded, we append the layout with padded rows.
    is_padding: BooleanAdvice,
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
    /// Range Table for [0, 512).
    range512: RangeTable<512>,
    /// Range table for [0, 128kb).
    range_block_len: RangeTable<{ N_BLOCK_SIZE_TARGET as usize }>,
    /// Power of 2 lookup table.
    pow2_table: Pow2Table<20>,
    /// Bitwise operation table (AND only)
    bitwise_op_table: BitwiseOpTable<1, L, R>,
    /// power of randomness table.
    pow_rand_table: PowOfRandTable,
    /// Helper table for decoding the regenerated size from LiteralsHeader.
    literals_header_table: LiteralsHeaderTable,
    /// Helper table for decoding bitstreams that span over 1 byte.
    bitstring_table_1: BitstringTable<1>,
    /// Helper table for decoding bitstreams that span over 2 bytes.
    bitstring_table_2: BitstringTable<2>,
    /// Helper table for decoding bitstreams that span over 3 bytes.
    bitstring_table_3: BitstringTable<3>,
    /// Helper table for decoding FSE tables.
    fse_table: FseTable<L, R>,
    /// Helper table for sequences as instructions.
    sequence_instruction_table: SequenceInstructionTable<Fr>,
    /// Helper table in the "output" region for accumulating the result of executing sequences.
    sequence_execution_config: SequenceExecutionConfig<Fr>,
    /// Helper booleans for degree reduction: whether to enable or not certain lookups.
    lookups_enabled: LookupsEnabled,

    /// Fixed lookups table.
    fixed_table: FixedTable,
}

#[derive(Clone, Debug)]
struct LookupsEnabled {
    enable_fse_var_bit_packing: Column<Advice>,
    enable_fse_norm_prob: Column<Advice>,
    enable_seq_data_rom: Column<Advice>,
    enable_seq_data_instruction: Column<Advice>,
    enable_seq_data_fse_table: Column<Advice>,
    enable_bs_2_bytes: Column<Advice>,
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
    /// The running accumulator of RLC values of bytes in the tag.
    tag_rlc_acc: Column<Advice>,
    /// The RLC of bytes in the tag.
    tag_rlc: Column<Advice>,
    /// Represents keccak randomness exponentiated by the tag len.
    rpow_tag_len: Column<Advice>,
    /// Whether this tag is processed from back-to-front or not.
    is_reverse: Column<Advice>,
    /// Whether this row represents the first byte in a new tag. Effectively this also means that
    /// the previous row represented the last byte of the tag processed previously.
    ///
    /// The only exception is the first row in the layout where for the FrameHeaderDescriptor we do
    /// not set this boolean value. We instead use the q_first fixed column to conditionally
    /// constrain the first row.
    is_change: BooleanAdvice,
    /// Degree reduction: FrameContentSize
    is_frame_content_size: Column<Advice>,
    /// Degree reduction: BlockHeader
    is_block_header: Column<Advice>,
    /// Degree reduction: LiteralsHeader
    is_literals_header: Column<Advice>,
    /// Degree reduction: SequencesHeader
    is_sequence_header: Column<Advice>,
    /// Degree reduction: SequenceFseCode
    is_fse_code: Column<Advice>,
    /// Degree reduction: SequencesData
    is_sequence_data: Column<Advice>,
    /// Degree reduction: Null
    is_null: Column<Advice>,
}

impl TagConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>, q_enable: Column<Fixed>) -> Self {
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
            tag_rlc_acc: meta.advice_column_in(SecondPhase),
            tag_rlc: meta.advice_column_in(SecondPhase),
            rpow_tag_len: meta.advice_column_in(SecondPhase),
            is_reverse: meta.advice_column(),
            is_change: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
            // degree reduction.
            is_frame_content_size: meta.advice_column(),
            is_block_header: meta.advice_column(),
            is_literals_header: meta.advice_column(),
            is_sequence_header: meta.advice_column(),
            is_fse_code: meta.advice_column(),
            is_sequence_data: meta.advice_column(),
            is_null: meta.advice_column(),
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
    /// The regenerated size of the block, i.e. the length of raw literals.
    regen_size: Column<Advice>,
    /// Helper boolean column to tell us whether we are in the block's contents. This field is not
    /// set for FrameHeaderDescriptor and FrameContentSize. For the tags that occur while decoding
    /// the block's contents, this field is set.
    is_block: Column<Advice>,
    /// Number of sequences decoded from the sequences section header in the block.
    num_sequences: Column<Advice>,
    /// Helper gadget to know if the number of sequences is 0.
    is_empty_sequences: IsEqualConfig<Fr>,
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
    fn configure(meta: &mut ConstraintSystem<Fr>, q_enable: Column<Fixed>) -> Self {
        let num_sequences = meta.advice_column();
        Self {
            block_len: meta.advice_column(),
            block_idx: meta.advice_column(),
            is_last_block: meta.advice_column(),
            regen_size: meta.advice_column(),
            is_block: meta.advice_column(),
            num_sequences,
            is_empty_sequences: IsEqualChip::configure(
                meta,
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
                |meta| meta.query_advice(num_sequences, Rotation::cur()),
                |_| 0.expr(),
            ),
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
        sum::expr([
            and::expr([
                fse_decoder.is_llt(meta, rotation),
                self.is_predefined_llt(meta, rotation),
            ]),
            and::expr([
                fse_decoder.is_mlt(meta, rotation),
                self.is_predefined_mlt(meta, rotation),
            ]),
            and::expr([
                fse_decoder.is_mot(meta, rotation),
                self.is_predefined_mot(meta, rotation),
            ]),
        ])
    }

    fn is_empty_sequences(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Rotation,
    ) -> Expression<Fr> {
        let num_sequences = meta.query_advice(self.num_sequences, rotation);
        self.is_empty_sequences
            .expr_at(meta, rotation, num_sequences, 0.expr())
    }
}

#[derive(Clone, Debug)]
struct SequencesHeaderDecoder {
    /// Helper gadget to evaluate byte0 < 128.
    pub byte0_lt_0x80: LtConfig<Fr, 1>,
    /// Helper gadget to evaluate byte0 < 255.
    pub byte0_lt_0xff: LtConfig<Fr, 1>,
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
        q_enable: Column<Fixed>,
        u8_table: U8Table,
    ) -> Self {
        Self {
            byte0_lt_0x80: LtChip::configure(
                meta,
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
                |meta| meta.query_advice(byte, Rotation::cur()),
                |_| 0x80.expr(),
                u8_table.into(),
            ),
            byte0_lt_0xff: LtChip::configure(
                meta,
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
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
        bits: &[BooleanAdvice; N_BITS_PER_BYTE],
    ) -> DecodedSequencesHeader {
        let byte0_lt_0x80 = self.byte0_lt_0x80.is_lt(meta, Rotation::cur());
        let byte0_lt_0xff = self.byte0_lt_0xff.is_lt(meta, Rotation::cur());

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
            bits[6].expr_at(meta, Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                bits[6].expr_at(meta, Rotation(2)),
                bits[6].expr_at(meta, Rotation(3)),
            ),
        );
        let comp_mode_bit1_ll = select::expr(
            byte0_lt_0x80.expr(),
            bits[7].expr_at(meta, Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                bits[7].expr_at(meta, Rotation(2)),
                bits[7].expr_at(meta, Rotation(3)),
            ),
        );

        let comp_mode_bit0_om = select::expr(
            byte0_lt_0x80.expr(),
            bits[4].expr_at(meta, Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                bits[4].expr_at(meta, Rotation(2)),
                bits[4].expr_at(meta, Rotation(3)),
            ),
        );
        let comp_mode_bit1_om = select::expr(
            byte0_lt_0x80.expr(),
            bits[5].expr_at(meta, Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                bits[5].expr_at(meta, Rotation(2)),
                bits[5].expr_at(meta, Rotation(3)),
            ),
        );

        let comp_mode_bit0_ml = select::expr(
            byte0_lt_0x80.expr(),
            bits[2].expr_at(meta, Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                bits[2].expr_at(meta, Rotation(2)),
                bits[2].expr_at(meta, Rotation(3)),
            ),
        );
        let comp_mode_bit1_ml = select::expr(
            byte0_lt_0x80.expr(),
            bits[3].expr_at(meta, Rotation(1)),
            select::expr(
                byte0_lt_0xff.expr(),
                bits[3].expr_at(meta, Rotation(2)),
                bits[3].expr_at(meta, Rotation(3)),
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
    /// When we have encountered a symbol with value=1, i.e. prob=0, it is followed by 2-bits
    /// repeat bits flag that tells us the number of symbols following the current one that also
    /// have a probability of prob=0. If the repeat bits flag itself is [1, 1], i.e.
    /// bitstring_value==3, then it is followed by another 2-bits repeat bits flag and so on. We
    /// utilise this equality config to identify these cases.
    bitstring_value_eq_3: IsEqualConfig<Fr>,
    /// The value of the binary bitstring.
    bitstring_value: Column<Advice>,
    /// Boolean that is set for a special case:
    /// - The bitstring that we have read in the current row is byte-aligned up to the next or the
    /// next-to-next byte. In this case, the next or the next-to-next following row(s) should have
    /// the is_nil field set.
    is_nil: BooleanAdvice,
    /// Boolean that is set for a special case:
    /// - We don't read from the bitstream, i.e. we read 0 number of bits. We can witness such a
    /// case while applying an FSE table to bitstream, where the number of bits to be read from
    /// the bitstream is 0. This can happen when we decode sequences in the SequencesData tag.
    is_nb0: BooleanAdvice,
    /// Helper gadget to check when bit_index_start has not changed.
    start_unchanged: IsEqualConfig<Fr>,
}

impl BitstreamDecoder {
    fn configure(
        meta: &mut ConstraintSystem<Fr>,
        q_enable: Column<Fixed>,
        q_first: Column<Fixed>,
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
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
                |meta| meta.query_advice(bit_index_end, Rotation::cur()),
                |_| 7.expr(),
                u8_table.into(),
            ),
            bit_index_end_cmp_15: ComparatorChip::configure(
                meta,
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
                |meta| meta.query_advice(bit_index_end, Rotation::cur()),
                |_| 15.expr(),
                u8_table.into(),
            ),
            bit_index_end_cmp_23: ComparatorChip::configure(
                meta,
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
                |meta| meta.query_advice(bit_index_end, Rotation::cur()),
                |_| 23.expr(),
                u8_table.into(),
            ),
            bitstring_value_eq_3: IsEqualChip::configure(
                meta,
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
                |meta| meta.query_advice(bitstring_value, Rotation::cur()),
                |_| 3.expr(),
            ),
            bitstring_value,
            is_nil: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
            is_nb0: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
            start_unchanged: IsEqualChip::configure(
                meta,
                |meta| {
                    and::expr([
                        meta.query_fixed(q_enable, Rotation::cur()),
                        not::expr(meta.query_fixed(q_first, Rotation::cur())),
                    ])
                },
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
        self.is_nil.expr_at(meta, rotation)
    }

    /// If we expect to read a bitstring at this row.
    fn is_not_nil(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        not::expr(self.is_nil(meta, rotation))
    }

    /// If the number of bits to be read from the bitstream is nb=0. This scenario occurs in the
    /// SequencesData tag section, when we are applying the FSE tables to decode sequences.
    fn is_nb0(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        self.is_nb0.expr_at(meta, rotation)
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
    fn strictly_spans_one_byte(&self, meta: &mut VirtualCells<Fr>, at: Rotation) -> Expression<Fr> {
        let lhs = meta.query_advice(self.bit_index_end, at);
        let (lt, _eq) = self.bit_index_end_cmp_7.expr_at(meta, at, lhs, 7.expr());
        lt
    }

    /// A bitstring spans 1 byte if the bit_index at which it ends is such that:
    /// - 0 <= bit_index_end <= 7.
    fn spans_one_byte(&self, meta: &mut VirtualCells<Fr>, at: Rotation) -> Expression<Fr> {
        let lhs = meta.query_advice(self.bit_index_end, at);
        let (lt, eq) = self.bit_index_end_cmp_7.expr_at(meta, at, lhs, 7.expr());
        lt + eq
    }

    /// A bitstring spans 1 byte and is byte-aligned:
    /// - bit_index_end == 7.
    fn aligned_one_byte(&self, meta: &mut VirtualCells<Fr>, at: Rotation) -> Expression<Fr> {
        let lhs = meta.query_advice(self.bit_index_end, at);
        let (_lt, eq) = self.bit_index_end_cmp_7.expr_at(meta, at, lhs, 7.expr());
        eq
    }

    /// A bitstring strictly spans 2 bytes if the bit_index at which it ends is such that:
    /// - 8 <= bit_index_end < 15.
    fn strictly_spans_two_bytes(
        &self,
        meta: &mut VirtualCells<Fr>,
        at: Rotation,
    ) -> Expression<Fr> {
        let spans_one_byte = self.spans_one_byte(meta, at);
        let lhs = meta.query_advice(self.bit_index_end, at);
        let (lt2, _eq2) = self.bit_index_end_cmp_15.expr_at(meta, at, lhs, 15.expr());
        not::expr(spans_one_byte) * lt2
    }

    /// A bistring spans 2 bytes if the 8 <= bit_index_end <= 15.
    fn spans_two_bytes(&self, meta: &mut VirtualCells<Fr>, at: Rotation) -> Expression<Fr> {
        let spans_one_byte = self.spans_one_byte(meta, at);
        let lhs = meta.query_advice(self.bit_index_end, at);
        let (lt2, eq2) = self.bit_index_end_cmp_15.expr_at(meta, at, lhs, 15.expr());
        not::expr(spans_one_byte) * (lt2 + eq2)
    }

    /// A bitstring spans 2 bytes and is byte-aligned:
    /// - bit_index_end == 15.
    fn aligned_two_bytes(&self, meta: &mut VirtualCells<Fr>, at: Rotation) -> Expression<Fr> {
        let lhs = meta.query_advice(self.bit_index_end, at);
        let (_lt, eq) = self.bit_index_end_cmp_15.expr_at(meta, at, lhs, 15.expr());
        eq
    }

    /// A bitstring strictly spans 3 bytes if the bit_index at which it ends is such that:
    /// - 16 <= bit_index_end < 23.
    fn strictly_spans_three_bytes(
        &self,
        meta: &mut VirtualCells<Fr>,
        at: Rotation,
    ) -> Expression<Fr> {
        let lhs = meta.query_advice(self.bit_index_end, at);
        let (lt2, eq2) = self
            .bit_index_end_cmp_15
            .expr_at(meta, at, lhs.expr(), 15.expr());
        let (lt3, _eq3) = self.bit_index_end_cmp_23.expr_at(meta, at, lhs, 23.expr());
        not::expr(lt2 + eq2) * lt3
    }

    /// A bitstring spans 3 bytes if the bit_index at which it ends is such that:
    /// - 16 <= bit_index_end <= 23.
    fn spans_three_bytes(&self, meta: &mut VirtualCells<Fr>, at: Rotation) -> Expression<Fr> {
        let lhs = meta.query_advice(self.bit_index_end, at);
        let (lt2, eq2) = self.bit_index_end_cmp_15.expr_at(meta, at, lhs, 15.expr());
        not::expr(lt2 + eq2)
    }

    /// A bitstring spans 3 bytes and is byte-aligned:
    /// - bit_index_end == 23.
    fn aligned_three_bytes(&self, meta: &mut VirtualCells<Fr>, at: Rotation) -> Expression<Fr> {
        let lhs = meta.query_advice(self.bit_index_end, at);
        let (_lt, eq) = self.bit_index_end_cmp_23.expr_at(meta, at, lhs, 23.expr());
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
    /// - LLT = 1, MOT = 2, MLT = 3
    table_kind: Column<Advice>,
    /// The number of states in the FSE table. table_size == 1 << AL, where AL is the accuracy log
    /// of the FSE table.
    table_size: Column<Advice>,
    /// If the table_kind at this row is predefined table.
    is_predefined: Column<Advice>,
    /// The incremental symbol for which probability is decoded.
    symbol: Column<Advice>,
    /// The value decoded as per variable bit-packing.
    value_decoded: Column<Advice>,
    /// An accumulator of the number of states allocated to each symbol as we decode the FSE table.
    /// This is the normalised probability for the symbol.
    probability_acc: Column<Advice>,
    /// Whether we are in the repeat bits loop.
    is_repeat_bits_loop: BooleanAdvice,
    /// Whether this row represents the 0-7 trailing bits that should be ignored.
    is_trailing_bits: BooleanAdvice,
    /// Helper gadget to know when the decoded value is 0. This contributes to an edge-case in
    /// decoding and reconstructing the FSE table from normalised distributions, where a value=0
    /// implies prob=-1 ("less than 1" probability). In this case, the symbol is allocated a state
    /// at the end of the FSE table, with baseline=0x00 and nb=AL, i.e. reset state.
    value_decoded_eq_0: IsEqualConfig<Fr>,
    /// Helper gadget to know when the decoded value is 1. This is useful in the edge-case in
    /// decoding and reconstructing the FSE table, where a value=1 implies a special case of
    /// prob=0, where the symbol is instead followed by a 2-bit repeat flag.
    value_decoded_eq_1: IsEqualConfig<Fr>,
}

impl FseDecoder {
    fn configure(
        meta: &mut ConstraintSystem<Fr>,
        block_config: &BlockConfig,
        is_fse_code: Column<Advice>,
        is_sequence_data: Column<Advice>,
        is_change: BooleanAdvice,
        q_enable: Column<Fixed>,
    ) -> Self {
        let value_decoded = meta.advice_column();

        let fse_decoder = Self {
            table_kind: meta.advice_column(),
            table_size: meta.advice_column(),
            is_predefined: meta.advice_column(),
            symbol: meta.advice_column(),
            value_decoded,
            probability_acc: meta.advice_column(),
            is_repeat_bits_loop: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
            is_trailing_bits: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
            value_decoded_eq_0: IsEqualChip::configure(
                meta,
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
                |meta| meta.query_advice(value_decoded, Rotation::cur()),
                |_| 0.expr(),
            ),
            value_decoded_eq_1: IsEqualChip::configure(
                meta,
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
                |meta| meta.query_advice(value_decoded, Rotation::cur()),
                |_| 1.expr(),
            ),
        };

        meta.create_gate("DecoderConfig::FseDecoder", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                sum::expr([
                    // for every tag=FseCode row.
                    meta.query_advice(is_fse_code, Rotation::cur()),
                    // for every tag=SequenceData row, except the sentinel row.
                    and::expr([
                        not::expr(is_change.expr_at(meta, Rotation::cur())),
                        meta.query_advice(is_sequence_data, Rotation::cur()),
                    ]),
                ]),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_predefined value",
                meta.query_advice(fse_decoder.is_predefined, Rotation::cur()),
                block_config.is_predefined(meta, &fse_decoder, Rotation::cur()),
            );

            cb.gate(condition)
        });

        fse_decoder
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

    fn is_mot(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        let table_kind = meta.query_advice(self.table_kind, rotation);
        (table_kind.expr() - FseTableKind::LLT.expr())
            * (FseTableKind::MLT.expr() - table_kind.expr())
    }

    fn is_mlt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        let table_kind = meta.query_advice(self.table_kind, rotation);
        let invert_of_2 = Fr::from(2).invert().expect("infallible");
        (table_kind.expr() - FseTableKind::LLT.expr())
            * (table_kind.expr() - FseTableKind::MOT.expr())
            * invert_of_2
    }

    /// If the decoded value is 0.
    fn is_prob_less_than1(
        &self,
        meta: &mut VirtualCells<Fr>,
        rotation: Rotation,
    ) -> Expression<Fr> {
        let value_decoded = meta.query_advice(self.value_decoded, rotation);
        self.value_decoded_eq_0
            .expr_at(meta, rotation, value_decoded, 0.expr())
    }

    /// While reconstructing the FSE table, indicates whether a value=1 was found, i.e. prob=0. In
    /// this case, the symbol is followed by 2-bits repeat flag instead.
    fn is_prob0(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        let value_decoded = meta.query_advice(self.value_decoded, rotation);
        self.value_decoded_eq_1
            .expr_at(meta, rotation, value_decoded, 1.expr())
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
    is_init_state: BooleanAdvice,
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
    is_update_state: BooleanAdvice,
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
    fn configure(meta: &mut ConstraintSystem<Fr>, q_enable: Column<Fixed>) -> Self {
        Self {
            idx: meta.advice_column(),
            is_init_state: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
            is_update_state: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
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
        self.is_init_state.expr_at(meta, rotation)
    }

    fn is_update_state(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        self.is_update_state.expr_at(meta, rotation)
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

    fn value_llt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.values[0], rotation)
    }

    fn value_mlt(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.values[1], rotation)
    }

    fn value_mot(&self, meta: &mut VirtualCells<Fr>, rotation: Rotation) -> Expression<Fr> {
        meta.query_advice(self.values[2], rotation)
    }

    fn state_at_prev(
        &self,
        meta: &mut VirtualCells<Fr>,
        fse_decoder: &FseDecoder,
        rotation: Rotation,
    ) -> Expression<Fr> {
        sum::expr([
            and::expr([
                fse_decoder.is_llt(meta, rotation),
                self.state_llt(meta, Rotation(rotation.0 - 1)),
            ]),
            and::expr([
                fse_decoder.is_mlt(meta, rotation),
                self.state_mlt(meta, Rotation(rotation.0 - 1)),
            ]),
            and::expr([
                fse_decoder.is_mot(meta, rotation),
                self.state_mot(meta, Rotation(rotation.0 - 1)),
            ]),
        ])
    }

    fn symbol(
        &self,
        meta: &mut VirtualCells<Fr>,
        fse_decoder: &FseDecoder,
        rotation: Rotation,
    ) -> Expression<Fr> {
        sum::expr([
            and::expr([
                fse_decoder.is_llt(meta, rotation),
                self.symbol_llt(meta, rotation),
            ]),
            and::expr([
                fse_decoder.is_mlt(meta, rotation),
                self.symbol_mlt(meta, rotation),
            ]),
            and::expr([
                fse_decoder.is_mot(meta, rotation),
                self.symbol_mot(meta, rotation),
            ]),
        ])
    }

    fn symbol_at_prev(
        &self,
        meta: &mut VirtualCells<Fr>,
        fse_decoder: &FseDecoder,
        rotation: Rotation,
    ) -> Expression<Fr> {
        sum::expr([
            and::expr([
                fse_decoder.is_llt(meta, rotation),
                self.symbol_llt(meta, Rotation(rotation.0 - 1)),
            ]),
            and::expr([
                fse_decoder.is_mlt(meta, rotation),
                self.symbol_mlt(meta, Rotation(rotation.0 - 1)),
            ]),
            and::expr([
                fse_decoder.is_mot(meta, rotation),
                self.symbol_mot(meta, Rotation(rotation.0 - 1)),
            ]),
        ])
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct AssignedDecoderConfigExports {
    /// The RLC of the zstd encoded bytes, i.e. blob bytes.
    pub encoded_rlc: AssignedCell<Fr, Fr>,
    /// The length of encoded data.
    pub encoded_len: AssignedCell<Fr, Fr>,
    /// The RLC of the decoded bytes, i.e. batch bytes.
    pub decoded_rlc: AssignedCell<Fr, Fr>,
    /// The length of decoded data.
    pub decoded_len: AssignedCell<Fr, Fr>,
}

pub struct DecoderConfigArgs<const L: usize, const R: usize> {
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
    /// Range table for lookup: [0, 512).
    pub range512: RangeTable<512>,
    /// Range table for [0, 128kb).
    pub range_block_len: RangeTable<{ N_BLOCK_SIZE_TARGET as usize }>,
    /// Bitwise operation lookup table.
    pub bitwise_op_table: BitwiseOpTable<1, L, R>,
}

impl<const L: usize, const R: usize> DecoderConfig<L, R> {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        challenges: &Challenges<Expression<Fr>>,
        DecoderConfigArgs {
            pow_rand_table,
            pow2_table,
            u8_table,
            range8,
            range16,
            range512,
            range_block_len,
            bitwise_op_table,
        }: DecoderConfigArgs<L, R>,
    ) -> Self {
        // Fixed table
        let fixed_table = FixedTable::construct(meta);

        let (q_enable, q_first, byte_idx, byte) = (
            meta.fixed_column(),
            meta.fixed_column(),
            meta.advice_column(),
            meta.advice_column(),
        );
        let is_padding =
            BooleanAdvice::construct(meta, |meta| meta.query_fixed(q_enable, Rotation::cur()));
        // Helper tables
        let literals_header_table = LiteralsHeaderTable::configure(meta, q_enable, range8, range16);
        let bitstring_table_1 = BitstringTable::configure(meta, q_enable, range_block_len);
        let bitstring_table_2 = BitstringTable::configure(meta, q_enable, range_block_len);
        let bitstring_table_3 = BitstringTable::configure(meta, q_enable, range_block_len);
        let fse_table = FseTable::configure(
            meta,
            q_enable,
            &fixed_table,
            u8_table,
            range8,
            range512,
            pow2_table,
            bitwise_op_table,
        );
        let sequence_instruction_table = SequenceInstructionTable::configure(meta);

        debug_assert!(meta.degree() <= 9);

        // Peripheral configs
        let tag_config = TagConfig::configure(meta, q_enable);
        let block_config = BlockConfig::configure(meta, q_enable);
        let sequences_header_decoder =
            SequencesHeaderDecoder::configure(meta, byte, q_enable, u8_table);
        let bitstream_decoder = BitstreamDecoder::configure(meta, q_enable, q_first, u8_table);
        let fse_decoder = FseDecoder::configure(
            meta,
            &block_config,
            tag_config.is_fse_code,
            tag_config.is_sequence_data,
            tag_config.is_change,
            q_enable,
        );
        let sequences_data_decoder = SequencesDataDecoder::configure(meta, q_enable);
        let sequence_execution_config = SequenceExecutionConfig::configure(
            meta,
            challenges.keccak_input(),
            &LiteralTable::construct([
                q_enable.into(),
                tag_config.tag.into(),
                block_config.block_idx.into(),
                tag_config.tag_idx.into(),
                byte.into(),
                tag_config.is_change.column.into(),
                is_padding.column.into(),
            ]),
            &sequence_instruction_table,
            &SequenceConfig::construct([
                q_enable.into(),
                block_config.is_block.into(),
                block_config.block_idx.into(),
                block_config.num_sequences.into(),
            ]),
        );

        debug_assert!(meta.degree() <= 9);
        debug_assert!(meta.clone().chunk_lookups().degree() <= 9);

        // Main config
        let _const_col = meta.fixed_column();
        meta.enable_constant(_const_col);
        let lookups_enabled = LookupsEnabled {
            enable_fse_var_bit_packing: meta.advice_column(),
            enable_fse_norm_prob: meta.advice_column(),
            enable_seq_data_rom: meta.advice_column(),
            enable_seq_data_instruction: meta.advice_column(),
            enable_seq_data_fse_table: meta.advice_column(),
            enable_bs_2_bytes: meta.advice_column(),
        };
        let config = Self {
            _const_col,
            q_enable,
            q_first,
            byte_idx,
            byte,
            bits: (0..N_BITS_PER_BYTE)
                .map(|_| {
                    BooleanAdvice::construct(meta, |meta| {
                        meta.query_fixed(q_enable, Rotation::cur())
                    })
                })
                .collect::<Vec<_>>()
                .try_into()
                .expect("N_BITS_PER_BYTE advice columns into array"),
            encoded_rlc: meta.advice_column_in(SecondPhase),
            decoded_len: meta.advice_column(),
            is_padding,
            tag_config,
            block_config,
            sequences_header_decoder,
            bitstream_decoder,
            fse_decoder,
            sequences_data_decoder,
            range8,
            range16,
            range512,
            range_block_len,
            pow2_table,
            bitwise_op_table,
            pow_rand_table,
            literals_header_table,
            bitstring_table_1,
            bitstring_table_2,
            bitstring_table_3,
            fse_table,
            lookups_enabled,

            sequence_instruction_table,
            sequence_execution_config,
            fixed_table,
        };

        meta.enable_equality(config.decoded_len);
        meta.enable_equality(config.encoded_rlc);
        meta.enable_equality(config.byte_idx);

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

        macro_rules! is_prev_tag {
            ($var:ident, $tag_variant:ident) => {
                let $var = |meta: &mut VirtualCells<Fr>| {
                    config
                        .tag_config
                        .tag_bits
                        .value_equals(ZstdTag::$tag_variant, Rotation::prev())(meta)
                };
            };
        }

        is_tag!(is_null, Null);
        is_tag!(is_frame_header_descriptor, FrameHeaderDescriptor);
        is_tag!(is_frame_content_size, FrameContentSize);
        is_tag!(is_block_header, BlockHeader);
        is_tag!(is_zb_literals_header, ZstdBlockLiteralsHeader);
        is_tag!(is_zb_raw_block, ZstdBlockLiteralsRawBytes);
        is_tag!(is_zb_sequence_header, ZstdBlockSequenceHeader);
        is_tag!(is_zb_sequence_fse, ZstdBlockSequenceFseCode);
        is_tag!(is_zb_sequence_data, ZstdBlockSequenceData);

        is_prev_tag!(is_prev_frame_content_size, FrameContentSize);
        is_prev_tag!(is_prev_sequence_header, ZstdBlockSequenceHeader);
        is_prev_tag!(is_prev_sequence_data, ZstdBlockSequenceData);

        meta.lookup("DecoderConfig: 0 <= encoded byte < 256", |meta| {
            vec![(
                meta.query_advice(config.byte, Rotation::cur()),
                u8_table.into(),
            )]
        });

        meta.create_gate("DecoderConfig: first row", |meta| {
            let condition = meta.query_fixed(config.q_first, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            // The first row is not padded row.
            cb.require_zero(
                "is_padding is False on the first row",
                config.is_padding.expr_at(meta, Rotation::cur()),
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

            cb.gate(condition)
        });

        meta.create_gate("DecoderConfig: all rows except the first row", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            let is_padding_curr = config.is_padding.expr_at(meta, Rotation::cur());
            let is_padding_prev = config.is_padding.expr_at(meta, Rotation::prev());

            // is_padding transitions from 0 -> 1 only once, i.e. is_padding_delta is boolean.
            let is_padding_delta = is_padding_curr - is_padding_prev;
            cb.require_boolean("is_padding_delta is boolean", is_padding_delta);

            cb.gate(condition)
        });

        meta.create_gate("DecoderConfig: all non-padded rows", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // byte decomposed into bits.
            let bits = config.bits.map(|bit| bit.expr_at(meta, Rotation::cur()));
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
            degree_reduction_check!(
                config.tag_config.is_literals_header,
                is_zb_literals_header(meta)
            );
            degree_reduction_check!(
                config.tag_config.is_sequence_header,
                is_zb_sequence_header(meta)
            );
            degree_reduction_check!(config.tag_config.is_fse_code, is_zb_sequence_fse(meta));
            degree_reduction_check!(
                config.tag_config.is_sequence_data,
                is_zb_sequence_data(meta)
            );
            degree_reduction_check!(config.tag_config.is_null, is_null(meta));

            // Lookups enabled check.
            macro_rules! lookups_enabled_check {
                ($column:expr, $expr:expr) => {
                    cb.require_equal(
                        "Lookups enabled check",
                        meta.query_advice($column, Rotation::cur()),
                        $expr,
                    );
                };
            }
            lookups_enabled_check!(
                config.lookups_enabled.enable_fse_var_bit_packing,
                and::expr([
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                    not::expr(config.tag_config.is_change.expr_at(meta, Rotation::cur())),
                    not::expr(
                        config
                            .fse_decoder
                            .is_repeat_bits_loop
                            .expr_at(meta, Rotation::cur()),
                    ),
                    not::expr(
                        config
                            .fse_decoder
                            .is_trailing_bits
                            .expr_at(meta, Rotation::cur()),
                    ),
                ])
            );
            lookups_enabled_check!(
                config.lookups_enabled.enable_fse_norm_prob,
                and::expr([
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                    not::expr(config.tag_config.is_change.expr_at(meta, Rotation::cur())),
                    not::expr(config.fse_decoder.is_prob0(meta, Rotation::cur())),
                    not::expr(
                        config
                            .fse_decoder
                            .is_repeat_bits_loop
                            .expr_at(meta, Rotation::cur()),
                    ),
                    not::expr(
                        config
                            .fse_decoder
                            .is_trailing_bits
                            .expr_at(meta, Rotation::cur()),
                    ),
                ])
            );
            lookups_enabled_check!(
                config.lookups_enabled.enable_seq_data_instruction,
                and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    not::expr(config.tag_config.is_change.expr_at(meta, Rotation::cur())),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                    config.fse_decoder.is_llt(meta, Rotation::cur()),
                    config
                        .sequences_data_decoder
                        .is_code_to_value(meta, Rotation::cur()),
                ])
            );
            lookups_enabled_check!(
                config.lookups_enabled.enable_seq_data_rom,
                and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    not::expr(config.tag_config.is_change.expr_at(meta, Rotation::cur())),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                    config
                        .sequences_data_decoder
                        .is_code_to_value(meta, Rotation::cur()),
                ])
            );
            lookups_enabled_check!(
                config.lookups_enabled.enable_seq_data_fse_table,
                and::expr([
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    not::expr(config.tag_config.is_change.expr_at(meta, Rotation::cur())),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                    not::expr(
                        config
                            .sequences_data_decoder
                            .is_init_state(meta, Rotation::cur()),
                    ),
                    config
                        .sequences_data_decoder
                        .is_update_state(meta, Rotation::cur()),
                ])
            );
            lookups_enabled_check!(
                config.lookups_enabled.enable_bs_2_bytes,
                and::expr([
                    not::expr(config.bitstream_decoder.is_nil(meta, Rotation::cur())),
                    not::expr(config.bitstream_decoder.is_nb0(meta, Rotation::cur())),
                    config
                        .bitstream_decoder
                        .spans_two_bytes(meta, Rotation::cur()),
                    sum::expr([
                        meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                        meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    ]),
                ])
            );

            cb.gate(condition)
        });

        meta.create_gate(
            "DecoderConfig: all non-padded rows except the first row",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(config.q_enable, Rotation::cur()),
                    not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
                    not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
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

                // byte_idx increments for all the following tags.
                cb.condition(
                    sum::expr([
                        meta.query_advice(config.tag_config.is_frame_content_size, Rotation::cur()),
                        meta.query_advice(config.tag_config.is_block_header, Rotation::cur()),
                        meta.query_advice(config.tag_config.is_literals_header, Rotation::cur()),
                        is_zb_raw_block(meta),
                        meta.query_advice(config.tag_config.is_sequence_header, Rotation::cur()),
                    ]),
                    |cb| {
                        cb.require_equal(
                            "for these tags: byte_idx increments",
                            byte_idx_delta.expr(),
                            1.expr(),
                        );
                    },
                );

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
                        config.tag_config.is_change.expr_at(meta, Rotation::cur()),
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
                meta.query_fixed(config.q_enable, Rotation::cur()),
                config.is_padding.expr_at(meta, Rotation::prev()),
                config.is_padding.expr_at(meta, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // Fields that do not change until the end of the layout once we have encountered
            // padded rows.
            for column in [config.encoded_rlc, config.decoded_len] {
                cb.require_equal(
                    "unchanged column in padded rows",
                    meta.query_advice(column, Rotation::cur()),
                    meta.query_advice(column, Rotation::prev()),
                );
            }

            cb.gate(condition)
        });

        meta.lookup_any("DecoderConfig: fixed lookup (tag transition)", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                sum::expr([
                    meta.query_fixed(config.q_first, Rotation::cur()),
                    config.tag_config.is_change.expr_at(meta, Rotation::cur()),
                ]),
            ]);

            [
                FixedLookupTag::TagTransition.expr(),
                meta.query_advice(config.tag_config.tag, Rotation::cur()),
                meta.query_advice(config.tag_config.tag_next, Rotation::cur()),
                meta.query_advice(config.tag_config.max_len, Rotation::cur()),
                meta.query_advice(config.tag_config.is_reverse, Rotation::cur()),
                meta.query_advice(config.block_config.is_block, Rotation::cur()),
                0.expr(), // unused
            ]
            .into_iter()
            .zip_eq(config.fixed_table.table_exprs(meta))
            .map(|(value, table)| (condition.expr() * value, table))
            .collect()
        });

        meta.create_gate("DecoderConfig: new tag", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                config.tag_config.is_change.expr_at(meta, Rotation::cur()),
            ]);

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
                    "tag_rlc_acc::prev == byte::prev",
                    meta.query_advice(config.tag_config.tag_rlc_acc, Rotation::prev()),
                    meta.query_advice(config.byte, Rotation::prev()),
                );
            });

            // The tag_idx is initialised correctly.
            cb.require_equal(
                "tag_idx::cur == 1 (if not padding)",
                meta.query_advice(config.tag_config.tag_idx, Rotation::cur()),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
            );

            // If the new tag is not processed from back-to-front, the RLC of the tag bytes
            // initialises at the first byte.
            let curr_tag_reverse = meta.query_advice(config.tag_config.is_reverse, Rotation::cur());
            cb.condition(not::expr(curr_tag_reverse), |cb| {
                cb.require_equal(
                    "tag_rlc_acc::cur == byte::cur",
                    meta.query_advice(config.tag_config.tag_rlc_acc, Rotation::cur()),
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
                meta.query_fixed(config.q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
                not::expr(config.tag_config.is_change.expr_at(meta, Rotation::cur())),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // Fields that are maintained while processing the same tag.
            for column in [
                config.tag_config.tag,
                config.tag_config.tag_next,
                config.tag_config.tag_len,
                config.tag_config.tag_rlc,
                config.tag_config.max_len,
                config.tag_config.rpow_tag_len,
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
            let tag_rlc_acc_prev =
                meta.query_advice(config.tag_config.tag_rlc_acc, Rotation::prev());
            let tag_rlc_acc_curr =
                meta.query_advice(config.tag_config.tag_rlc_acc, Rotation::cur());
            let curr_tag_reverse = meta.query_advice(config.tag_config.is_reverse, Rotation::cur());
            cb.condition(not::expr(byte_idx_delta.expr()), |cb| {
                cb.require_equal(
                    "tag_rlc_acc::cur == tag_rlc_acc::prev",
                    tag_rlc_acc_curr.expr(),
                    tag_rlc_acc_prev.expr(),
                );
            });
            cb.condition(
                and::expr([byte_idx_delta.expr(), curr_tag_reverse.expr()]),
                |cb| {
                    cb.require_equal(
                        "tag_rlc_acc::prev == tag_rlc_acc::cur * r + byte::prev",
                        tag_rlc_acc_prev.expr(),
                        tag_rlc_acc_curr.expr() * challenges.keccak_input() + byte_prev,
                    );
                },
            );
            cb.condition(
                and::expr([byte_idx_delta.expr(), not::expr(curr_tag_reverse.expr())]),
                |cb| {
                    cb.require_equal(
                        "tag_rlc_acc::cur == tag_rlc_acc::prev * r + byte::cur",
                        tag_rlc_acc_curr.expr(),
                        tag_rlc_acc_prev.expr() * challenges.keccak_input() + byte_curr,
                    );
                },
            );

            cb.gate(condition)
        });

        meta.lookup_any("DecoderConfig: keccak randomness power tag_len", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                config.tag_config.is_change.expr_at(meta, Rotation::cur()),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
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

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////// ZstdTag::FrameHeaderDescriptor /////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: tag FrameHeaderDescriptor", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                is_frame_header_descriptor(meta),
            ]);

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
                config.bits[5].expr_at(meta, Rotation::cur()),
                1.expr(),
            );
            cb.require_zero(
                "FHD: Unused_Bit",
                config.bits[4].expr_at(meta, Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Reserved_Bit",
                config.bits[3].expr_at(meta, Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Content_Checksum_Flag",
                config.bits[2].expr_at(meta, Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Dictionary_ID_Flag",
                config.bits[1].expr_at(meta, Rotation::cur()),
            );
            cb.require_zero(
                "FHD: Dictionary_ID_Flag",
                config.bits[0].expr_at(meta, Rotation::cur()),
            );

            // Checks for the next tag, i.e. FrameContentSize.
            let fcs_flag0 = config.bits[7].expr_at(meta, Rotation::cur());
            let fcs_flag1 = config.bits[6].expr_at(meta, Rotation::cur());
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
                meta.query_fixed(config.q_enable, Rotation::cur()),
                meta.query_advice(config.tag_config.is_frame_content_size, Rotation::cur()),
                config.tag_config.is_change.expr_at(meta, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // The previous row is FrameHeaderDescriptor.
            let fcs_flag0 = config.bits[7].expr_at(meta, Rotation::prev());
            let fcs_flag1 = config.bits[6].expr_at(meta, Rotation::prev());

            // - [1, 1]: 8 bytes
            // - [1, 0]: 4 bytes
            // - [0, 1]: 2 bytes
            // - [0, 0]: 1 bytes
            let case1 = and::expr([fcs_flag0.expr(), fcs_flag1.expr()]);
            let case2 = fcs_flag0.expr();
            let case3 = fcs_flag1.expr();

            // FrameContentSize are LE bytes.
            let case4_value = meta.query_advice(config.byte, Rotation::cur());
            let case3_value = meta.query_advice(config.byte, Rotation::next()) * 256.expr()
                + meta.query_advice(config.byte, Rotation::cur());
            let case2_value = meta.query_advice(config.byte, Rotation(3)) * 16777216.expr()
                + meta.query_advice(config.byte, Rotation(2)) * 65536.expr()
                + meta.query_advice(config.byte, Rotation(1)) * 256.expr()
                + meta.query_advice(config.byte, Rotation(0));
            let case1_value = meta.query_advice(config.byte, Rotation(7))
                * 72057594037927936u64.expr()
                + meta.query_advice(config.byte, Rotation(6)) * 281474976710656u64.expr()
                + meta.query_advice(config.byte, Rotation(5)) * 1099511627776u64.expr()
                + meta.query_advice(config.byte, Rotation(4)) * 4294967296u64.expr()
                + meta.query_advice(config.byte, Rotation(3)) * 16777216.expr()
                + meta.query_advice(config.byte, Rotation(2)) * 65536.expr()
                + meta.query_advice(config.byte, Rotation(1)) * 256.expr()
                + meta.query_advice(config.byte, Rotation(0));

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
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                meta.query_advice(config.tag_config.is_frame_content_size, Rotation::cur()),
            ]);

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
                meta.query_fixed(config.q_enable, Rotation::cur()),
                meta.query_advice(config.tag_config.is_block_header, Rotation::cur()),
                config.tag_config.is_change.expr_at(meta, Rotation::cur()),
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
            let is_last_block = config.bits[0].expr_at(meta, Rotation::cur());
            let block_type_bit1 = config.bits[1].expr_at(meta, Rotation::cur());
            let block_type_bit2 = config.bits[2].expr_at(meta, Rotation::cur());

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

            // block_len, block_idx and is_last_block fields do not change in the BlockHeader. We
            // explicitly do this check since tag=BlockHeader has is_block=false, to facilitate the
            // change of these parameters between blocks (at the tag=BlockHeader boundary). For the
            // subsequent tags, these fields remain the same and is checked via the gate for
            // is_block=true.
            for column in [
                config.block_config.block_len,
                config.block_config.block_idx,
                config.block_config.is_last_block,
            ] {
                cb.require_equal(
                    "BlockHeader: block_idx/block_len/is_last_block",
                    meta.query_advice(column, Rotation(0)),
                    meta.query_advice(column, Rotation(1)),
                );
                cb.require_equal(
                    "BlockHeader: block_idx/block_len/is_last_block",
                    meta.query_advice(column, Rotation(0)),
                    meta.query_advice(column, Rotation(2)),
                );
            }

            // We now validate the end of the previous block.
            // - tag=BlockHeader is preceded by tag in [FrameContentSize, SeqHeader, SeqData].
            // - if prev_tag=SequenceHeader: prev block had no sequences.
            // - if prev_tag=SequenceData: all sequences from prev block were decoded.
            cb.require_equal(
                "tag::prev in [FCS, SH, SD]",
                sum::expr([
                    is_prev_frame_content_size(meta),
                    is_prev_sequence_header(meta),
                    is_prev_sequence_data(meta),
                ]),
                1.expr(),
            );
            cb.condition(is_prev_sequence_header(meta), |cb| {
                cb.require_equal(
                    "tag::prev=SeqHeader",
                    config
                        .block_config
                        .is_empty_sequences(meta, Rotation::prev()),
                    1.expr(),
                );
            });
            cb.condition(is_prev_sequence_data(meta), |cb| {
                cb.require_equal(
                    "tag::prev=SeqData",
                    meta.query_advice(config.block_config.num_sequences, Rotation::prev()),
                    meta.query_advice(config.sequences_data_decoder.idx, Rotation::prev()),
                );
            });

            cb.gate(condition)
        });

        meta.lookup("DecoderConfig: tag BlockHeader (Block_Size)", |meta| {
            let condition = and::expr([
                meta.query_advice(config.tag_config.is_block_header, Rotation::cur()),
                config.tag_config.is_change.expr_at(meta, Rotation::cur()),
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
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                meta.query_advice(config.block_config.is_block, Rotation::cur()),
            ]);

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

            // the regen size column remains unchanged.
            cb.require_equal(
                "regen_size::cur == regen_size::prev",
                meta.query_advice(config.block_config.regen_size, Rotation::cur()),
                meta.query_advice(config.block_config.regen_size, Rotation::prev()),
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

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////// ZstdTag::ZstdBlockLiteralsHeader ////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: tag ZstdBlockLiteralsHeader", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                meta.query_advice(config.tag_config.is_literals_header, Rotation::cur()),
                config.tag_config.is_change.expr_at(meta, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            let literals_block_type_bit0 = config.bits[0].expr_at(meta, Rotation::cur());
            let literals_block_type_bit1 = config.bits[1].expr_at(meta, Rotation::cur());

            // We expect a Raw_Literals_Block, i.e. bit0 and bit1 are both 0.
            cb.require_zero("Raw_Literals_Block: bit0", literals_block_type_bit0);
            cb.require_zero("Raw_Literals_Block: bit1", literals_block_type_bit1);

            let size_format_bit0 = config.bits[2].expr_at(meta, Rotation::cur());
            let size_format_bit1 = config.bits[3].expr_at(meta, Rotation::cur());

            // - Size_Format is 00 or 10: Size_Format uses 1 bit, literals header is 1 byte
            // - Size_Format is 01: Size_Format uses 2 bits, literals header is 2 bytes
            // - Size_Format is 10: Size_Format uses 2 bits, literals header is 3 bytes
            let expected_tag_len = select::expr(
                not::expr(size_format_bit0.expr()),
                1.expr(),
                select::expr(size_format_bit1.expr(), 3.expr(), 2.expr()),
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
                    meta.query_advice(config.tag_config.is_literals_header, Rotation::cur()),
                    config.tag_config.is_change.expr_at(meta, Rotation::cur()),
                ]);

                let size_format_bit0 = config.bits[2].expr_at(meta, Rotation::cur());
                let size_format_bit1 = config.bits[3].expr_at(meta, Rotation::cur());

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
                    size_format_bit0.expr() * size_format_bit1.expr(),
                    meta.query_advice(config.byte, Rotation(2)),
                    0.expr(),
                );

                let (block_idx, regen_size) = (
                    meta.query_advice(config.block_config.block_idx, Rotation::cur()),
                    meta.query_advice(config.block_config.regen_size, Rotation::cur()),
                );
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
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                is_zb_raw_block(meta),
                config.tag_config.is_change.expr_at(meta, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "block's regen size is raw literals' tag length",
                meta.query_advice(config.tag_config.tag_len, Rotation::cur()),
                meta.query_advice(config.block_config.regen_size, Rotation::cur()),
            );

            cb.gate(condition)
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////// ZstdTag::ZstdBlockSequenceHeader /////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: tag ZstdBlockSequenceHeader", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                meta.query_advice(config.tag_config.is_sequence_header, Rotation::cur()),
                config.tag_config.is_change.expr_at(meta, Rotation::cur()),
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
                    ZstdTag::ZstdBlockSequenceData.expr(),
                    ZstdTag::ZstdBlockSequenceFseCode.expr(),
                ),
            );

            cb.gate(condition)
        });

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceHeader (sequence count)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(config.q_enable, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_sequence_header, Rotation::cur()),
                    config.tag_config.is_change.expr_at(meta, Rotation::cur()),
                ]);
                let (block_idx, num_sequences) = (
                    meta.query_advice(config.block_config.block_idx, Rotation::cur()),
                    meta.query_advice(config.block_config.num_sequences, Rotation::cur()),
                );
                [
                    1.expr(), // q_enabled
                    block_idx,
                    1.expr(), // s_beginning
                    num_sequences,
                ]
                .into_iter()
                .zip_eq(config.sequence_instruction_table.seq_count_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////// ZstdTag::ZstdBlockSequenceFseCode /////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (first row)",
            |meta| {
                // The first row of a ZstdBlockSequenceFseCode tag.
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    config.tag_config.is_change.expr_at(meta, Rotation::cur()),
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
                    config
                        .fse_decoder
                        .is_repeat_bits_loop
                        .expr_at(meta, Rotation::next()),
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
                    config.tag_config.is_change.expr_at(meta, Rotation::cur()),
                ]);

                let (cmode_llt, cmode_mot, cmode_mlt) = (
                    meta.query_advice(config.block_config.compression_modes[0], Rotation::cur()),
                    meta.query_advice(config.block_config.compression_modes[1], Rotation::cur()),
                    meta.query_advice(config.block_config.compression_modes[2], Rotation::cur()),
                );

                let cmodes_lc = (4.expr() * cmode_llt) + (2.expr() * cmode_mot) + cmode_mlt;
                [
                    FixedLookupTag::SeqTagOrder.expr(),
                    cmodes_lc,
                    meta.query_advice(config.tag_config.tag, Rotation::prev()), // tag_prev
                    meta.query_advice(config.tag_config.tag, Rotation::cur()),  // tag_cur
                    meta.query_advice(config.tag_config.tag_next, Rotation::cur()), // tag_next
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()), // table_kind
                    0.expr(),                                                   // unused
                ]
                .into_iter()
                .zip_eq(config.fixed_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (table size)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    config.tag_config.is_change.expr_at(meta, Rotation::cur()),
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
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    not::expr(config.tag_config.is_change.expr_at(meta, Rotation::cur())),
                    not::expr(
                        config
                            .fse_decoder
                            .is_trailing_bits
                            .expr_at(meta, Rotation::cur()),
                    ),
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
                        .spans_three_bytes(meta, Rotation::cur()),
                );

                // If the bitstring read at the current row is ``aligned_two_bytes`` then the one
                // on the next row is nil (not read).
                cb.condition(
                    config
                        .bitstream_decoder
                        .aligned_two_bytes(meta, Rotation::cur()),
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
                let is_repeat_bits_loop = config
                    .fse_decoder
                    .is_repeat_bits_loop
                    .expr_at(meta, Rotation::cur());
                cb.condition(
                    and::expr([
                        not::expr(is_repeat_bits_loop.expr()),
                        config.fse_decoder.is_prob0(meta, Rotation::cur()),
                    ]),
                    |cb| {
                        cb.require_equal(
                            "fse: enter repeat-bits loop",
                            config
                                .fse_decoder
                                .is_repeat_bits_loop
                                .expr_at(meta, Rotation::next()),
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
                            config
                                .fse_decoder
                                .is_repeat_bits_loop
                                .expr_at(meta, Rotation::next()),
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
                            config
                                .fse_decoder
                                .is_repeat_bits_loop
                                .expr_at(meta, Rotation::next()),
                        );
                    },
                );

                // We not tackle the normalised probability of symbols in the FSE table, their
                // updating and the FSE symbol itself.
                //
                // If no bitstring was read, even the symbol value is carried forward.
                let (
                    prob_acc_cur,
                    prob_acc_prev,
                    fse_symbol_cur,
                    fse_symbol_prev,
                    bitstring_value,
                    value_decoded,
                ) = (
                    meta.query_advice(config.fse_decoder.probability_acc, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.probability_acc, Rotation::prev()),
                    meta.query_advice(config.fse_decoder.symbol, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.symbol, Rotation::prev()),
                    meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.value_decoded, Rotation::cur()),
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
                //
                // We skip the check for symbol on the first bitstring after the 4-bits for AL
                // because this check has already been done on the "first row".
                cb.condition(
                    and::expr([
                        config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                        not::expr(is_repeat_bits_loop.expr()),
                    ]),
                    |cb| {
                        // if value>=1: prob_acc_cur == prob_acc_prev + (value - 1)
                        // if value==0: prob_acc_cur == prob_acc_prev + 1
                        cb.require_equal(
                            "fse: probability_acc is updated correctly",
                            prob_acc_cur.expr(),
                            select::expr(
                                config.fse_decoder.is_prob_less_than1(meta, Rotation::cur()),
                                prob_acc_prev.expr() + 1.expr(),
                                prob_acc_prev.expr() + value_decoded.expr() - 1.expr(),
                            ),
                        );
                        cb.require_equal(
                            "fse: symbol increments",
                            fse_symbol_cur.expr(),
                            select::expr(
                                config.tag_config.is_change.expr_at(meta, Rotation::prev()),
                                0.expr(),
                                fse_symbol_prev.expr() + 1.expr(),
                            ),
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
                        fse_symbol_prev + bitstring_value,
                    );
                });

                cb.gate(condition)
            },
        );

        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (last row)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    config.tag_config.is_change.expr_at(meta, Rotation::next()),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // cumulative prob of symbols == table_size
                cb.require_equal(
                    "cumulative normalised probabilities over all symbols is the table size",
                    meta.query_advice(config.fse_decoder.probability_acc, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_size, Rotation::cur()),
                );

                // bitstream can be byte-unaligned (trailing bits are ignored)
                //
                // One of the following scenarios is true for the last row of tag=FseCode:
                // - the last row is the trailing bits (ignored).
                // - the last row is a valid bitstring that is byte-aligned.
                //      - aligned_one_byte(0)
                //      - aligned_two_bytes(-1)
                //      - aligned_three_bytes(-2)
                let is_trailing_bits = config
                    .fse_decoder
                    .is_trailing_bits
                    .expr_at(meta, Rotation::cur());
                cb.require_equal(
                    "last bitstring is either byte-aligned or the 0-7 trailing bits",
                    sum::expr([
                        is_trailing_bits.expr(),
                        and::expr([
                            not::expr(is_trailing_bits),
                            sum::expr([
                                config
                                    .bitstream_decoder
                                    .aligned_one_byte(meta, Rotation::cur()),
                                config
                                    .bitstream_decoder
                                    .aligned_two_bytes(meta, Rotation::prev()),
                                config
                                    .bitstream_decoder
                                    .aligned_three_bytes(meta, Rotation(-2)),
                            ]),
                        ]),
                    ]),
                    1.expr(),
                );

                cb.gate(condition)
            },
        );

        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (trailing bits)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    config
                        .fse_decoder
                        .is_trailing_bits
                        .expr_at(meta, Rotation::cur()),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // 1. is_trailing_bits can occur iff tag=FseCode.
                cb.require_equal(
                    "tag=FseCode",
                    meta.query_advice(config.tag_config.tag, Rotation::cur()),
                    ZstdTag::ZstdBlockSequenceFseCode.expr(),
                );

                // 2. trailing bits only occur on the last row of the tag=FseCode section.
                cb.require_equal(
                    "is_change'=true",
                    config.tag_config.is_change.expr_at(meta, Rotation::next()),
                    1.expr(),
                );

                // 3. trailing bits are meant to byte-align the bitstream, i.e. bit_index_end==7.
                cb.require_equal(
                    "bit_index_end==7",
                    meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
                    7.expr(),
                );

                // 4. if trailing bits exist, it means the last valid bitstring was not
                //    byte-aligned.
                cb.require_zero(
                    "last valid bitstring byte-unaligned",
                    sum::expr([
                        config
                            .bitstream_decoder
                            .aligned_one_byte(meta, Rotation(-1)),
                        config
                            .bitstream_decoder
                            .aligned_two_bytes(meta, Rotation(-2)),
                        config
                            .bitstream_decoder
                            .aligned_three_bytes(meta, Rotation(-3)),
                    ]),
                );

                // The FSE table kind remains the same.
                cb.require_equal(
                    "table_kind remains the same for trailing bits in tag=FseCode",
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::prev()),
                );

                cb.gate(condition)
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (variable bit-packing)",
            |meta| {
                // At every row where a non-nil bitstring is read:
                // - except the AL bits (is_change=true)
                // - except when we are in repeat-bits loop
                // - except the trailing bits (if they exist)
                let condition = and::expr([
                    meta.query_fixed(config.q_enable, Rotation::cur()),
                    meta.query_advice(
                        config.lookups_enabled.enable_fse_var_bit_packing,
                        Rotation::cur(),
                    ),
                ]);

                let (table_size, probability_acc, value_read, value_decoded, num_bits) = (
                    meta.query_advice(config.fse_decoder.table_size, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.probability_acc, Rotation::prev()),
                    meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.value_decoded, Rotation::cur()),
                    config
                        .bitstream_decoder
                        .bitstring_len_unchecked(meta, Rotation::cur()),
                );

                let range = table_size - probability_acc + 1.expr();
                [
                    FixedLookupTag::VariableBitPacking.expr(),
                    range,
                    value_read,
                    value_decoded,
                    num_bits,
                    0.expr(),
                    0.expr(),
                ]
                .into_iter()
                .zip_eq(config.fixed_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceFseCode (normalised probability of symbol)",
            |meta| {
                // At every row where a non-nil bitstring is read:
                // - except the AL bits (is_change=true)
                // - except when the value=1, i.e. prob=0
                // - except when we are in repeat-bits loop
                // - except the trailing bits (if they exist)
                let condition = and::expr([
                    meta.query_fixed(config.q_enable, Rotation::cur()),
                    meta.query_advice(config.lookups_enabled.enable_fse_norm_prob, Rotation::cur()),
                ]);

                let (block_idx, fse_table_kind, fse_table_size, fse_symbol, value_decoded) = (
                    meta.query_advice(config.block_config.block_idx, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.table_size, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.symbol, Rotation::cur()),
                    meta.query_advice(config.fse_decoder.value_decoded, Rotation::cur()),
                );
                let is_prob_less_than1 =
                    config.fse_decoder.is_prob_less_than1(meta, Rotation::cur());
                let norm_prob = select::expr(
                    is_prob_less_than1.expr(),
                    1.expr(),
                    value_decoded - 1.expr(),
                );
                let is_predefined_mode =
                    meta.query_advice(config.fse_decoder.is_predefined, Rotation::cur());

                [
                    0.expr(), // q_first=0
                    block_idx,
                    fse_table_kind,
                    fse_table_size,
                    is_predefined_mode,
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
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    config.tag_config.is_change.expr_at(meta, Rotation::cur()),
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
                        .spans_one_byte(meta, Rotation::cur()),
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
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    not::expr(config.tag_config.is_change.expr_at(meta, Rotation::cur())),
                    config.bitstream_decoder.is_not_nil(meta, Rotation::cur()),
                ]);

                let (table_kind_prev, table_kind_curr, is_init_state, is_update_state) = (
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::prev()),
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()),
                    config
                        .sequences_data_decoder
                        .is_init_state
                        .expr_at(meta, Rotation::cur()),
                    config
                        .sequences_data_decoder
                        .is_update_state
                        .expr_at(meta, Rotation::cur()),
                );

                [
                    FixedLookupTag::SeqDataInterleavedOrder.expr(),
                    table_kind_prev,
                    table_kind_curr,
                    is_init_state,
                    is_update_state,
                    0.expr(), // unused
                    0.expr(), // unused
                ]
                .into_iter()
                .zip_eq(config.fixed_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceData (sequences)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    not::expr(config.tag_config.is_change.expr_at(meta, Rotation::cur())),
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
                let is_decode_value = config
                    .sequences_data_decoder
                    .is_code_to_value(meta, Rotation::cur());
                let (v_mot, v_mlt, v_llt) = (
                    and::expr([
                        config.fse_decoder.is_mot(meta, Rotation::cur()),
                        is_decode_value.expr(),
                    ]),
                    and::expr([
                        config.fse_decoder.is_mlt(meta, Rotation::cur()),
                        is_decode_value.expr(),
                    ]),
                    and::expr([
                        config.fse_decoder.is_llt(meta, Rotation::cur()),
                        is_decode_value.expr(),
                    ]),
                );
                cb.condition(v_mot.expr(), |cb| {
                    let (baseline, bitstring_value) = (
                        meta.query_advice(config.sequences_data_decoder.baseline, Rotation::cur()),
                        meta.query_advice(
                            config.bitstream_decoder.bitstring_value,
                            Rotation::cur(),
                        ),
                    );
                    cb.require_equal(
                        "value(mot) update",
                        config
                            .sequences_data_decoder
                            .value_mot(meta, Rotation::cur()),
                        baseline + bitstring_value,
                    );
                });
                cb.condition(v_mlt.expr(), |cb| {
                    let (baseline, bitstring_value) = (
                        meta.query_advice(config.sequences_data_decoder.baseline, Rotation::cur()),
                        meta.query_advice(
                            config.bitstream_decoder.bitstring_value,
                            Rotation::cur(),
                        ),
                    );
                    cb.require_equal(
                        "value(mlt) update",
                        config
                            .sequences_data_decoder
                            .value_mlt(meta, Rotation::cur()),
                        baseline + bitstring_value,
                    );
                });
                cb.condition(v_llt.expr(), |cb| {
                    let (baseline, bitstring_value) = (
                        meta.query_advice(config.sequences_data_decoder.baseline, Rotation::cur()),
                        meta.query_advice(
                            config.bitstream_decoder.bitstring_value,
                            Rotation::cur(),
                        ),
                    );
                    cb.require_equal(
                        "value(llt) update",
                        config
                            .sequences_data_decoder
                            .value_llt(meta, Rotation::cur()),
                        baseline + bitstring_value,
                    );
                });

                // - Update "state" at update-state (literal length)
                //      - This also means we have started decoding another sequence.
                // - Update "state" at update-state (match length)
                // - Update "state" at update-state (match offset)
                let is_update_state = config
                    .sequences_data_decoder
                    .is_update_state(meta, Rotation::cur());
                let (f_llt, f_mlt, f_mot) = (
                    and::expr([
                        config.fse_decoder.is_llt(meta, Rotation::cur()),
                        is_update_state.expr(),
                    ]),
                    and::expr([
                        config.fse_decoder.is_mlt(meta, Rotation::cur()),
                        is_update_state.expr(),
                    ]),
                    and::expr([
                        config.fse_decoder.is_mot(meta, Rotation::cur()),
                        is_update_state.expr(),
                    ]),
                );
                cb.condition(f_llt.expr(), |cb| {
                    let (baseline, bitstring_value) = (
                        meta.query_advice(config.sequences_data_decoder.baseline, Rotation::cur()),
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
                });
                cb.condition(f_mlt.expr(), |cb| {
                    let (baseline, bitstring_value) = (
                        meta.query_advice(config.sequences_data_decoder.baseline, Rotation::cur()),
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
                });
                cb.condition(f_mot.expr(), |cb| {
                    let (baseline, bitstring_value) = (
                        meta.query_advice(config.sequences_data_decoder.baseline, Rotation::cur()),
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
                });

                // all relevant columns in sequences data decoding.
                let all_cols = [
                    config.sequences_data_decoder.idx,
                    config.sequences_data_decoder.states[0],
                    config.sequences_data_decoder.states[1],
                    config.sequences_data_decoder.states[2],
                    config.sequences_data_decoder.symbols[0],
                    config.sequences_data_decoder.symbols[1],
                    config.sequences_data_decoder.symbols[2],
                    config.sequences_data_decoder.values[0],
                    config.sequences_data_decoder.values[1],
                    config.sequences_data_decoder.values[2],
                ];
                // tuple (condition, column) such that all columns except column should remain
                // unchanged if not this condition.
                let rules = [
                    // only value CMOT can change.
                    (v_mot, vec![config.sequences_data_decoder.values[2]]),
                    // only value MLT can change.
                    (v_mlt, vec![config.sequences_data_decoder.values[1]]),
                    // only value LLT can change.
                    (v_llt, vec![config.sequences_data_decoder.values[0]]),
                    // LLT state, symbol and sequence IDX can change.
                    (
                        f_llt,
                        vec![
                            config.sequences_data_decoder.states[0],
                            config.sequences_data_decoder.symbols[0],
                            config.sequences_data_decoder.idx,
                        ],
                    ),
                    // MLT state and symbol can change.
                    (
                        f_mlt,
                        vec![
                            config.sequences_data_decoder.states[1],
                            config.sequences_data_decoder.symbols[1],
                        ],
                    ),
                    // CMOT state and symbol can change.
                    (
                        f_mot,
                        vec![
                            config.sequences_data_decoder.states[2],
                            config.sequences_data_decoder.symbols[2],
                        ],
                    ),
                ];
                for (cond, except_col) in rules {
                    // If the rule's condition is met, all columns except that rule's columns
                    // remain unchanged.
                    cb.condition(cond, |cb| {
                        for col in all_cols {
                            if !except_col.contains(&col) {
                                cb.require_equal(
                                    "only the column of interest could be updated",
                                    meta.query_advice(col, Rotation::prev()),
                                    meta.query_advice(col, Rotation::cur()),
                                );
                            }
                        }
                    });
                }

                cb.gate(condition)
            },
        );

        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceData (last row)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(config.q_enable, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    config.tag_config.is_change.expr_at(meta, Rotation::next()),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // last operation is: code-to-value for LLT.
                cb.require_zero(
                    "last operation (sequences data): is_init",
                    config
                        .sequences_data_decoder
                        .is_init_state
                        .expr_at(meta, Rotation::cur()),
                );
                cb.require_zero(
                    "last operation (sequences data): is_update_state",
                    config
                        .sequences_data_decoder
                        .is_update_state
                        .expr_at(meta, Rotation::cur()),
                );
                cb.require_equal(
                    "last operation (sequences data): table_kind",
                    meta.query_advice(config.fse_decoder.table_kind, Rotation::cur()),
                    FseTableKind::LLT.expr(),
                );

                // idx == block.num_sequences.
                cb.require_equal(
                    "last row: idx = num_sequences",
                    meta.query_advice(config.sequences_data_decoder.idx, Rotation::cur()),
                    meta.query_advice(config.block_config.num_sequences, Rotation::cur()),
                );

                // tag::next == is_last_block ? Null : BlockHeader.
                cb.require_equal(
                    "last row: tag::next",
                    meta.query_advice(config.tag_config.tag_next, Rotation::cur()),
                    select::expr(
                        meta.query_advice(config.block_config.is_last_block, Rotation::cur()),
                        ZstdTag::Null.expr(),
                        ZstdTag::BlockHeader.expr(),
                    ),
                );

                // bitstream was consumed completely (byte-aligned):
                // - if not_nil(cur) -> bit_index_end == 7
                // - if nil(cur) and not_nil(prev) -> bit_index_end == 15
                // - if nil(cur) and nil(prev) -> not_nil(-2) and bit_index_end == 23
                let (is_nil_curr, is_nil_prev, is_nil_prev_prev) = (
                    config.bitstream_decoder.is_nil(meta, Rotation::cur()),
                    config.bitstream_decoder.is_nil(meta, Rotation::prev()),
                    config.bitstream_decoder.is_nil(meta, Rotation(-2)),
                );
                cb.condition(not::expr(is_nil_curr.expr()), |cb| {
                    cb.require_equal(
                        "is_not_nil: bit_index_end==7",
                        meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
                        7.expr(),
                    );
                });
                cb.condition(
                    and::expr([is_nil_curr.expr(), not::expr(is_nil_prev.expr())]),
                    |cb| {
                        cb.require_equal(
                            "is_nil and is_not_nil(prev): bit_index_end==15",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_end,
                                Rotation::prev(),
                            ),
                            15.expr(),
                        );
                    },
                );
                cb.condition(and::expr([is_nil_curr, is_nil_prev]), |cb| {
                    cb.require_zero("is_nil and is_nil(prev): is_not_nil(-2)", is_nil_prev_prev);
                    cb.require_equal(
                        "is_nil and is_nil(prev): bit_index_end==23",
                        meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation(-2)),
                        23.expr(),
                    );
                });

                cb.gate(condition)
            },
        );

        meta.create_gate(
            "DecoderConfig: tag ZstdBlockSequenceData (is_nil)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(config.q_enable, Rotation::cur()),
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
                    config.sequences_data_decoder.is_init_state.column,
                    config.sequences_data_decoder.is_update_state.column,
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
                // - not the first row (sentinel row)
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
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(config.lookups_enabled.enable_seq_data_rom, Rotation::cur()),
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

                [
                    FixedLookupTag::SeqCodeToValue.expr(),
                    table_kind,
                    code,
                    baseline,
                    nb,
                    0.expr(), // unused
                    0.expr(), // unused
                ]
                .into_iter()
                .zip_eq(config.fixed_table.table_exprs(meta))
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
                    meta.query_advice(config.fse_decoder.is_predefined, Rotation::cur());

                [
                    0.expr(), // q_first=0
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

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceData (sequence instructions table)",
            |meta| {
                // At the row where we compute the code-to-value of LLT, we have the values for
                // all of match offset, match length and literal length.
                let condition = and::expr([
                    meta.query_fixed(config.q_enable, Rotation::cur()),
                    meta.query_advice(
                        config.lookups_enabled.enable_seq_data_instruction,
                        Rotation::cur(),
                    ),
                ]);
                let (block_idx, sequence_idx) = (
                    meta.query_advice(config.block_config.block_idx, Rotation::cur()),
                    meta.query_advice(config.sequences_data_decoder.idx, Rotation::cur()),
                );
                let (literal_length_value, match_offset_value, match_length_value) = (
                    meta.query_advice(config.sequences_data_decoder.values[0], Rotation::cur()),
                    meta.query_advice(config.sequences_data_decoder.values[2], Rotation::cur()),
                    meta.query_advice(config.sequences_data_decoder.values[1], Rotation::cur()),
                );
                [
                    1.expr(), // q_enabled
                    block_idx,
                    0.expr(), // s_beginning
                    sequence_idx,
                    literal_length_value,
                    match_offset_value,
                    match_length_value,
                ]
                .into_iter()
                .zip_eq(config.sequence_instruction_table.seq_values_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        meta.lookup_any(
            "DecoderConfig: tag ZstdBlockSequenceData (FseTable)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(config.q_enable, Rotation::cur()),
                    meta.query_advice(
                        config.lookups_enabled.enable_seq_data_fse_table,
                        Rotation::cur(),
                    ),
                ]);

                let (state, symbol) = (
                    config.sequences_data_decoder.state_at_prev(
                        meta,
                        &config.fse_decoder,
                        Rotation::cur(),
                    ),
                    config.sequences_data_decoder.symbol_at_prev(
                        meta,
                        &config.fse_decoder,
                        Rotation::cur(),
                    ),
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
                    meta.query_advice(config.fse_decoder.is_predefined, Rotation::cur());

                [
                    0.expr(), // q_first=0
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

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////// ZstdTag::Null ////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: tag=Null", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_enable, Rotation::cur()),
                meta.query_advice(config.tag_config.is_null, Rotation::cur()),
                not::expr(meta.query_advice(config.tag_config.is_null, Rotation::prev())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // tag=Null also is the start of padding.
            cb.require_zero(
                "is_null: is_padding_prev=false",
                config.is_padding.expr_at(meta, Rotation::prev()),
            );
            cb.require_equal(
                "is_null: is_padding=true",
                config.is_padding.expr_at(meta, Rotation::cur()),
                1.expr(),
            );

            // tag::is_change=true which ensures the encoded_rlc is computed here. This also
            // implies that the previous tag in fact ended correctly.
            cb.require_equal(
                "is_null: is_tag_change=true",
                config.tag_config.is_change.expr_at(meta, Rotation::cur()),
                1.expr(),
            );

            // is_null=true implies we have reached the end of the encoded data. This can happen in
            // the following scenarios:
            // - end of block (is_last=true) with tag=SequenceData
            // - end of block (is_last=true) with tag=SequenceHeader and num_sequences=0
            // - the last tag ended OK
            cb.require_equal(
                "is_null: block::is_last=true on the previous row",
                meta.query_advice(config.block_config.is_last_block, Rotation::prev()),
                1.expr(),
            );
            cb.require_equal(
                "is_null: tag::prev check",
                meta.query_advice(config.tag_config.tag, Rotation::prev()),
                select::expr(
                    config
                        .block_config
                        .is_empty_sequences(meta, Rotation::prev()),
                    ZstdTag::ZstdBlockSequenceHeader.expr(),
                    ZstdTag::ZstdBlockSequenceData.expr(),
                ),
            );
            cb.require_equal(
                "is_null: tag_idx::prev == tag_len::prev",
                meta.query_advice(config.tag_config.tag_idx, Rotation::prev()),
                meta.query_advice(config.tag_config.tag_len, Rotation::prev()),
            );

            cb.gate(condition)
        });

        debug_assert!(meta.degree() <= 9);

        ///////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// Bitstream Decoding /////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////
        meta.create_gate("DecoderConfig: Bitstream Decoder (is_nil)", |meta| {
            // Bitstream decoder when we skip reading a bitstring at a row.
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                config.bitstream_decoder.is_nil(meta, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

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
            cb.require_equal(
                "bit_index_end == bit_index_start",
                meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
            );
            cb.require_equal(
                "bit_index_start <= 7",
                config
                    .bitstream_decoder
                    .spans_one_byte(meta, Rotation::cur()),
                1.expr(),
            );
            let (case1, case2, case3, case4) = (
                config
                    .bitstream_decoder
                    .aligned_two_bytes(meta, Rotation(-1)),
                config
                    .bitstream_decoder
                    .strictly_spans_three_bytes(meta, Rotation(-1)),
                config
                    .bitstream_decoder
                    .aligned_three_bytes(meta, Rotation(-1)),
                config
                    .bitstream_decoder
                    .aligned_three_bytes(meta, Rotation(-2)),
            );
            cb.require_equal(
                "is_nil occurs when previous bitstring was long",
                sum::expr([case1.expr(), case2.expr(), case3.expr(), case4.expr()]),
                1.expr(),
            );

            // There are 4 cases where is_nil=true can occur:
            // - previous bitstring spanned 2 bytes and was byte-aligned, bit_index_end::prev == 15.
            // - previous bitstring spanned 2 bytes, 16 <= bit_index_end::prev < 23.
            // - previous bitstring spanned 3 bytes and was byte-aligned, bit_index_end == 23.
            // - previous-previous bitstring spanned 3 bytes and was byte-aligned, bit_index_end ==
            //   23.
            let is_next_nb0 = config.bitstream_decoder.is_nb0(meta, Rotation::next());
            let is_next_nil = config.bitstream_decoder.is_nil(meta, Rotation::next());

            // 1. bit_index_end::prev == 15.
            //      - A) nb0::next == true
            //      - B) nb0::next == false
            cb.condition(case1.expr(), |cb| {
                cb.require_equal(
                    "nil(case1): bit_index_start == 7",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                    7.expr(),
                );
            });
            cb.condition(and::expr([case1.expr(), is_next_nb0.expr()]), |cb| {
                cb.require_equal(
                    "nil(case1A): preserve byte_idx",
                    meta.query_advice(config.byte_idx, Rotation::next()),
                    meta.query_advice(config.byte_idx, Rotation::cur()),
                );
                cb.require_equal(
                    "nil(case1A): preserve bit_index_start",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::next()),
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                );
            });
            cb.condition(
                and::expr([case1.expr(), not::expr(is_next_nb0.expr())]),
                |cb| {
                    cb.require_equal(
                        "nil(case1B): increment byte_idx",
                        meta.query_advice(config.byte_idx, Rotation::next()),
                        meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                    );
                    cb.require_zero(
                        "nil(case1B): reset bit_index_start",
                        meta.query_advice(
                            config.bitstream_decoder.bit_index_start,
                            Rotation::next(),
                        ),
                    );
                },
            );

            // 2. 16 <= bit_index_end::prev < 23.
            //      - A) nb0::next == true
            //      - B) nb0::next == false
            cb.condition(case2.expr(), |cb| {
                cb.require_equal(
                    "nil(case2): wrap bit_index_start by 16",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur())
                        + 16.expr(),
                    meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::prev()),
                );
                cb.require_equal(
                    "nil(case2): increment byte_idx",
                    meta.query_advice(config.byte_idx, Rotation::cur()),
                    meta.query_advice(config.byte_idx, Rotation::prev()) + 1.expr(),
                );
            });
            cb.condition(and::expr([case2.expr(), is_next_nb0.expr()]), |cb| {
                cb.require_equal(
                    "nil(case2A): preserve bit_index_start",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::next()),
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                );
            });
            cb.condition(
                and::expr([case2.expr(), not::expr(is_next_nb0.expr())]),
                |cb| {
                    cb.require_equal(
                        "nil(case2B): increment bit_index_start",
                        meta.query_advice(
                            config.bitstream_decoder.bit_index_start,
                            Rotation::next(),
                        ),
                        meta.query_advice(
                            config.bitstream_decoder.bit_index_start,
                            Rotation::cur(),
                        ) + 1.expr(),
                    );
                },
            );

            // 3. bit_index_end(-1) == 23
            // the next is_nil=true row will handle is_next_nb=0.
            cb.condition(case3.expr(), |cb| {
                cb.require_equal("nil(case3): next is_nil too", is_next_nil, 1.expr());
                cb.require_equal(
                    "nil(case3): increment byte_idx",
                    meta.query_advice(config.byte_idx, Rotation::next()),
                    meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                );
                cb.require_equal(
                    "nil(case3): bit_index_start == 7",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                    7.expr(),
                );
                cb.require_equal(
                    "nil(case3): preserve bit_index_start == 7",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::next()),
                    7.expr(),
                );
            });

            // 4. bit_index_end(-2) == 23
            cb.condition(case4.expr(), |cb| {
                cb.require_equal(
                    "nil(case4): wrap bit_index_start to 7",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                    7.expr(),
                );
            });
            cb.condition(and::expr([case4.expr(), is_next_nb0.expr()]), |cb| {
                cb.require_equal(
                    "nil(case4A): preserve byte_idx",
                    meta.query_advice(config.byte_idx, Rotation::next()),
                    meta.query_advice(config.byte_idx, Rotation::cur()),
                );
                cb.require_equal(
                    "nil(case4A): preserve bit_index_start",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::next()),
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                );
            });
            cb.condition(
                and::expr([case4.expr(), not::expr(is_next_nb0.expr())]),
                |cb| {
                    cb.require_equal(
                        "nil(case4B): increment byte_idx",
                        meta.query_advice(config.byte_idx, Rotation::next()),
                        meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                    );
                    cb.require_zero(
                        "nil(case4B): reset bit_index_start",
                        meta.query_advice(
                            config.bitstream_decoder.bit_index_start,
                            Rotation::next(),
                        ),
                    );
                },
            );

            cb.gate(condition)
        });

        meta.create_gate("DecoderConfig: Bitstream Decoder (is_nb0)", |meta| {
            // Bitstream decoder when we read nb=0 bits from the bitstream.
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                config.bitstream_decoder.is_nb0(meta, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "if is_nb0 is True then is_nil is False",
                config.bitstream_decoder.is_nil(meta, Rotation::cur()),
            );
            cb.require_equal(
                "bitstream(is_nb0) can occur in SequencesData",
                meta.query_advice(config.tag_config.tag, Rotation::cur()),
                ZstdTag::ZstdBlockSequenceData.expr(),
            );
            cb.require_zero(
                "if is_nb0: bitstring_value == 0",
                meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
            );
            cb.require_equal(
                "bit_index_end <= 7",
                config
                    .bitstream_decoder
                    .spans_one_byte(meta, Rotation::cur()),
                1.expr(),
            );
            cb.require_equal(
                "bit_index_start == bit_index_end",
                meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
            );

            // We now have a few branches, depending on whether or not we again read nb=0 bits from
            // bitstream, and whether right now we are at the end of a particular byte, i.e. if
            // bit_index_end == 7.
            let is_next_nb0 = config.bitstream_decoder.is_nb0(meta, Rotation::next());
            let is_byte_end = config
                .bitstream_decoder
                .aligned_one_byte(meta, Rotation::cur());
            let is_not_byte_end = not::expr(is_byte_end.expr());
            cb.condition(is_next_nb0.expr(), |cb| {
                cb.require_equal(
                    "preserve byte_idx",
                    meta.query_advice(config.byte_idx, Rotation::next()),
                    meta.query_advice(config.byte_idx, Rotation::cur()),
                );
                cb.require_equal(
                    "preserve bit_index_start",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::next()),
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                );
            });
            cb.condition(
                and::expr([not::expr(is_next_nb0.expr()), is_byte_end]),
                |cb| {
                    cb.require_equal(
                        "increment byte_idx",
                        meta.query_advice(config.byte_idx, Rotation::next()),
                        meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                    );
                    cb.require_zero(
                        "read from the start of the next byte",
                        meta.query_advice(
                            config.bitstream_decoder.bit_index_start,
                            Rotation::next(),
                        ),
                    );
                },
            );
            cb.condition(and::expr([not::expr(is_next_nb0), is_not_byte_end]), |cb| {
                cb.require_equal(
                    "preserve byte_idx",
                    meta.query_advice(config.byte_idx, Rotation::next()),
                    meta.query_advice(config.byte_idx, Rotation::cur()),
                );
                cb.require_equal(
                    "continue reading from bitstream",
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::next()),
                    meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur())
                        + 1.expr(),
                );
            });

            cb.gate(condition)
        });

        meta.create_gate(
            "DecoderConfig: Bitstream Decoder (read from bitstream)",
            |meta| {
                // Bitstream decoder when the bitstring to be read is not nil.
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
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
                let is_next_nb0 = config.bitstream_decoder.is_nb0(meta, Rotation::next());
                cb.condition(
                    config
                        .bitstream_decoder
                        .strictly_spans_one_byte(meta, Rotation::cur()),
                    |cb| {
                        cb.require_equal(
                            "(case1): preserve byte_idx",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()),
                        );
                        cb.require_equal(
                            "(case1): preserve/increment bit_index_start depending on is_next_nb0",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation::next(),
                            ),
                            select::expr(
                                is_next_nb0.expr(),
                                meta.query_advice(
                                    config.bitstream_decoder.bit_index_end,
                                    Rotation::cur(),
                                ),
                                meta.query_advice(
                                    config.bitstream_decoder.bit_index_end,
                                    Rotation::cur(),
                                ) + 1.expr(),
                            ),
                        );
                    },
                );

                // 2. bitstring is byte-aligned: bit_index_end == 7.
                //
                // We have two branches depending on whether or not the next row reads nb=0 bits
                // from the bitstream.
                cb.condition(
                    and::expr([
                        config
                            .bitstream_decoder
                            .aligned_one_byte(meta, Rotation::cur()),
                        is_next_nb0.expr(),
                    ]),
                    |cb| {
                        cb.require_equal(
                            "(case2a): preserve byte_idx",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()),
                        );
                        cb.require_equal(
                            "(case2a): bit_index_start' == bit_index_end == 7",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation::next(),
                            ),
                            7.expr(),
                        );
                    },
                );
                cb.condition(
                    and::expr([
                        config
                            .bitstream_decoder
                            .aligned_one_byte(meta, Rotation::cur()),
                        not::expr(is_next_nb0.expr()),
                    ]),
                    |cb| {
                        cb.require_equal(
                            "(case2b): byte_idx' == byte_idx + 1",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                        );
                        cb.require_zero(
                            "(case2b): bit_index_start' == 0",
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
                        .strictly_spans_two_bytes(meta, Rotation::cur()),
                    |cb| {
                        cb.require_equal(
                            "(case3): byte_idx' == byte_idx + 1",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                        );
                        cb.require_equal(
                            "(case3): wrap bit_index_start within <= 7, depending on whether is_next_nb0",
                            meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::next())
                            + select::expr(
                                is_next_nb0.expr(),
                                8.expr(),
                                7.expr(),
                            ),
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
                        .aligned_two_bytes(meta, Rotation::cur()),
                    |cb| {
                        cb.require_equal(
                            "(case4): bitstring decoder skipped next row",
                            config.bitstream_decoder.is_nil(meta, Rotation::next()),
                            1.expr(),
                        );
                        cb.require_equal(
                            "(case4): bit_index_start' is wrapped to 7",
                            meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::next()),
                            7.expr(),
                        );
                        cb.require_equal(
                            "(case4): byte_idx' == byte_idx + 1",
                            meta.query_advice(config.byte_idx, Rotation::next()),
                            meta.query_advice(config.byte_idx, Rotation::cur()) + 1.expr(),
                        );
                    },
                );

                // 5. bitstring strictly spans over 3 bytes: 16 <= bit_index_end < 23.
                cb.condition(
                    config
                        .bitstream_decoder
                        .strictly_spans_three_bytes(meta, Rotation::cur()),
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
                            "(case5): wrap bit_index_start' within <= 7",
                            meta.query_advice(
                                config.bitstream_decoder.bit_index_start,
                                Rotation::next(),
                            ) + 16.expr(),
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
                        .aligned_three_bytes(meta, Rotation::cur()),
                    |cb| {
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
                            "(case6): bit_index_start' == bit_index_start'' == 7",
                            meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation(1)),
                            meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation(2)),
                        );
                        cb.require_equal(
                            "(case6): bit_index_start' == bit_index_start'' == 7",
                            meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation(1)),
                            7.expr(),
                        );
                    },
                );

                cb.gate(condition)
            },
        );

        meta.create_gate("DecoderConfig: Bitstream Decoder", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                sum::expr([
                    meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                    meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                ]),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // If the following conditions are met:
            // - we are on the same byte_idx
            // - bit_index_start' == bit_index_start
            //
            // it means we are either not reading from the bitstream, or reading nb=0 bits
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
                            config.bitstream_decoder.is_nil(meta, Rotation::cur()),
                            config.bitstream_decoder.is_nb0(meta, Rotation::cur()),
                        ]),
                        1.expr(),
                    );
                },
            );

            cb.gate(condition)
        });

        meta.lookup_any(
            "DecoderConfig: Bitstream Decoder (bitstring start: bit_index_end <= 7)",
            |meta| {
                let condition = and::expr([
                    not::expr(config.bitstream_decoder.is_nil(meta, Rotation::cur())),
                    not::expr(config.bitstream_decoder.is_nb0(meta, Rotation::cur())),
                    config
                        .bitstream_decoder
                        .spans_one_byte(meta, Rotation::cur()),
                    sum::expr([
                        meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                        meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    ]),
                ]);

                let byte_idx = meta.query_advice(config.byte_idx, Rotation(0));
                let byte = meta.query_advice(config.byte, Rotation(0));

                let (bit_index_start, _bit_index_end, bitstring_value) = (
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
                );
                let is_reverse = meta.query_advice(config.tag_config.is_reverse, Rotation::cur());

                [
                    byte_idx,
                    0.expr(), // only 1 byte
                    0.expr(), // only 1 byte
                    byte,
                    0.expr(), // only 1 byte
                    0.expr(), // only 1 byte
                    bitstring_value,
                    1.expr(), // bitstring_len at start
                    bit_index_start,
                    1.expr(), // from_start
                    1.expr(), // until_end
                    is_reverse,
                    0.expr(), // is_padding
                ]
                .into_iter()
                .zip_eq(config.bitstring_table_1.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );
        meta.lookup_any(
            "DecoderConfig: Bitstream Decoder (bitstring start: bit_index_end <= 15)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(config.q_enable, Rotation::cur()),
                    meta.query_advice(config.lookups_enabled.enable_bs_2_bytes, Rotation::cur()),
                ]);

                let (byte_idx_1, byte_idx_2) = (
                    meta.query_advice(config.byte_idx, Rotation(0)),
                    meta.query_advice(config.byte_idx, Rotation(1)),
                );
                let (byte_1, byte_2) = (
                    meta.query_advice(config.byte, Rotation(0)),
                    meta.query_advice(config.byte, Rotation(1)),
                );
                let (bit_index_start, _bit_index_end, bitstring_value) = (
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
                );
                let is_reverse = meta.query_advice(config.tag_config.is_reverse, Rotation::cur());

                [
                    byte_idx_1,
                    byte_idx_2,
                    0.expr(), // only 2 bytes
                    byte_1,
                    byte_2,
                    0.expr(), // only 2 bytes
                    bitstring_value,
                    1.expr(), // bitstring_len at start
                    bit_index_start,
                    1.expr(), // from_start
                    1.expr(), // until_end
                    is_reverse,
                    0.expr(), // is_padding
                ]
                .into_iter()
                .zip_eq(config.bitstring_table_2.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );
        meta.lookup_any(
            "DecoderConfig: Bitstream Decoder (bitstring start: bit_index_end <= 23)",
            |meta| {
                let condition = and::expr([
                    not::expr(config.bitstream_decoder.is_nil(meta, Rotation::cur())),
                    not::expr(config.bitstream_decoder.is_nb0(meta, Rotation::cur())),
                    config
                        .bitstream_decoder
                        .spans_three_bytes(meta, Rotation::cur()),
                    sum::expr([
                        meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                        meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    ]),
                ]);

                let (byte_idx_1, byte_idx_2, byte_idx_3) = (
                    meta.query_advice(config.byte_idx, Rotation(0)),
                    meta.query_advice(config.byte_idx, Rotation(1)),
                    meta.query_advice(config.byte_idx, Rotation(2)),
                );
                let (byte_1, byte_2, byte_3) = (
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
                    byte_idx_1,
                    byte_idx_2,
                    byte_idx_3,
                    byte_1,
                    byte_2,
                    byte_3,
                    bitstring_value,
                    1.expr(), // bitstring_len at start
                    bit_index_start,
                    1.expr(), // from_start
                    1.expr(), // until_end
                    is_reverse,
                    0.expr(), // is_padding
                ]
                .into_iter()
                .zip_eq(config.bitstring_table_3.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        meta.lookup_any(
            "DecoderConfig: Bitstream Decoder (bitstring end: bit_index_end <= 7)",
            |meta| {
                let condition = and::expr([
                    not::expr(config.bitstream_decoder.is_nil(meta, Rotation::cur())),
                    not::expr(config.bitstream_decoder.is_nb0(meta, Rotation::cur())),
                    config
                        .bitstream_decoder
                        .spans_one_byte(meta, Rotation::cur()),
                    sum::expr([
                        meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                        meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    ]),
                ]);

                let byte_idx = meta.query_advice(config.byte_idx, Rotation(0));
                let byte = meta.query_advice(config.byte, Rotation(0));

                let (bit_index_start, bit_index_end, bitstring_value) = (
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
                );
                let is_reverse = meta.query_advice(config.tag_config.is_reverse, Rotation::cur());

                [
                    byte_idx,
                    0.expr(), // only 1 byte
                    0.expr(), // only 1 byte
                    byte,
                    0.expr(), // only 1 byte
                    0.expr(), // only 1 byte
                    bitstring_value,
                    bit_index_end.expr() - bit_index_start + 1.expr(), // bitstring_len at end
                    bit_index_end,
                    1.expr(), // from_start
                    1.expr(), // until_end
                    is_reverse,
                    0.expr(), // is_padding
                ]
                .into_iter()
                .zip_eq(config.bitstring_table_1.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );
        meta.lookup_any(
            "DecoderConfig: Bitstream Decoder (bitstring end: bit_index_end <= 15)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(config.q_enable, Rotation::cur()),
                    meta.query_advice(config.lookups_enabled.enable_bs_2_bytes, Rotation::cur()),
                ]);

                let (byte_idx_1, byte_idx_2) = (
                    meta.query_advice(config.byte_idx, Rotation(0)),
                    meta.query_advice(config.byte_idx, Rotation(1)),
                );
                let (byte_1, byte_2) = (
                    meta.query_advice(config.byte, Rotation(0)),
                    meta.query_advice(config.byte, Rotation(1)),
                );

                let (bit_index_start, bit_index_end, bitstring_value) = (
                    meta.query_advice(config.bitstream_decoder.bit_index_start, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bit_index_end, Rotation::cur()),
                    meta.query_advice(config.bitstream_decoder.bitstring_value, Rotation::cur()),
                );
                let is_reverse = meta.query_advice(config.tag_config.is_reverse, Rotation::cur());

                [
                    byte_idx_1,
                    byte_idx_2,
                    0.expr(), // only 2 bytes
                    byte_1,
                    byte_2,
                    0.expr(), // only 2 bytes
                    bitstring_value,
                    bit_index_end.expr() - bit_index_start + 1.expr(), // bitstring_len at end
                    bit_index_end,
                    1.expr(), // from_start
                    1.expr(), // until_end
                    is_reverse,
                    0.expr(), // is_padding
                ]
                .into_iter()
                .zip_eq(config.bitstring_table_2.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );
        meta.lookup_any(
            "DecoderConfig: Bitstream Decoder (bitstring end: bit_index_end <= 23)",
            |meta| {
                let condition = and::expr([
                    not::expr(config.bitstream_decoder.is_nil(meta, Rotation::cur())),
                    not::expr(config.bitstream_decoder.is_nb0(meta, Rotation::cur())),
                    config
                        .bitstream_decoder
                        .spans_three_bytes(meta, Rotation::cur()),
                    sum::expr([
                        meta.query_advice(config.tag_config.is_fse_code, Rotation::cur()),
                        meta.query_advice(config.tag_config.is_sequence_data, Rotation::cur()),
                    ]),
                ]);

                let (byte_idx_1, byte_idx_2, byte_idx_3) = (
                    meta.query_advice(config.byte_idx, Rotation(0)),
                    meta.query_advice(config.byte_idx, Rotation(1)),
                    meta.query_advice(config.byte_idx, Rotation(2)),
                );
                let (byte_1, byte_2, byte_3) = (
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
                    byte_idx_1,
                    byte_idx_2,
                    byte_idx_3,
                    byte_1,
                    byte_2,
                    byte_3,
                    bitstring_value,
                    bit_index_end.expr() - bit_index_start + 1.expr(), // bitstring_len at end
                    bit_index_end,
                    1.expr(), // from_start
                    1.expr(), // until_end
                    is_reverse,
                    0.expr(), // is_padding
                ]
                .into_iter()
                .zip_eq(config.bitstring_table_3.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        debug_assert!(meta.degree() <= 9);
        debug_assert!(meta.clone().chunk_lookups().degree() <= 9);

        config
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        raw_bytes: &[u8],
        _compressed_bytes: &[u8],
        witness_rows: Vec<ZstdWitnessRow<Fr>>,
        literal_datas: Vec<Vec<u64>>,
        fse_aux_tables: Vec<FseAuxiliaryTableData>,
        block_info_arr: Vec<BlockInfo>,
        sequence_info_arr: Vec<SequenceInfo>,
        address_table_arr: Vec<Vec<AddressTableRow>>,
        sequence_exec_info_arr: Vec<Vec<SequenceExec>>,
        challenges: &Challenges<Value<Fr>>,
        k: u32,
    ) -> Result<AssignedDecoderConfigExports, Error> {
        let n_enabled = (1 << k) - self.unusable_rows();
        let mut pow_of_rand: Vec<Value<Fr>> = vec![Value::known(Fr::ONE)];

        /////////////////////////////////////////
        //////// Load Auxiliary Tables  /////////
        /////////////////////////////////////////
        self.range8.load(layouter)?;
        self.range16.load(layouter)?;
        self.range512.load(layouter)?;
        self.range_block_len.load(layouter)?;
        self.fixed_table.load(layouter)?;
        self.pow2_table.load(layouter)?;
        self.bitwise_op_table.load(layouter)?;
        self.pow_rand_table
            .assign(layouter, challenges, n_enabled)?;

        /////////////////////////////////////////////////////////
        //////// Assign FSE and Bitstream Accumulation  /////////
        /////////////////////////////////////////////////////////
        self.fse_table.assign(layouter, fse_aux_tables, n_enabled)?;
        self.bitstring_table_1
            .assign(layouter, &block_info_arr, &witness_rows, n_enabled)?;
        self.bitstring_table_2
            .assign(layouter, &block_info_arr, &witness_rows, n_enabled)?;
        self.bitstring_table_3
            .assign(layouter, &block_info_arr, &witness_rows, n_enabled)?;

        /////////////////////////////////////////
        ///// Assign LiteralHeaderTable  ////////
        /////////////////////////////////////////
        let mut literal_headers: Vec<(u64, u64, (u64, u64, u64))> = vec![]; // (block_idx, byte_offset, (byte0, byte1, byte2))
        let literal_header_rows = witness_rows
            .iter()
            .filter(|r| r.state.tag == ZstdTag::ZstdBlockLiteralsHeader)
            .cloned()
            .collect::<Vec<ZstdWitnessRow<Fr>>>();
        let max_block_idx = witness_rows
            .iter()
            .last()
            .expect("Last row of witness exists.")
            .state
            .block_idx;
        for curr_block_idx in 1..=max_block_idx {
            let byte_idx = literal_header_rows
                .iter()
                .find(|r| r.state.block_idx == curr_block_idx)
                .unwrap()
                .encoded_data
                .byte_idx;

            let literal_bytes = literal_header_rows
                .iter()
                .filter(|&r| r.state.block_idx == curr_block_idx)
                .map(|r| r.encoded_data.value_byte as u64)
                .collect::<Vec<u64>>();

            literal_headers.push((
                curr_block_idx,
                byte_idx,
                (
                    literal_bytes[0],
                    if literal_bytes.len() > 1 {
                        literal_bytes[1]
                    } else {
                        0
                    },
                    if literal_bytes.len() > 2 {
                        literal_bytes[2]
                    } else {
                        0
                    },
                ),
            ));
        }
        self.literals_header_table
            .assign(layouter, literal_headers, n_enabled)?;

        /////////////////////////////////////////
        //// Assign Sequence-related Configs ////
        /////////////////////////////////////////
        self.sequence_instruction_table.assign(
            layouter,
            address_table_arr.iter().map(|rows| rows.iter()),
            n_enabled,
        )?;
        let (exported_len, exported_rlc) = self.sequence_execution_config.assign(
            layouter,
            challenges.keccak_input(),
            literal_datas
                .iter()
                .zip(&sequence_info_arr)
                .zip(&sequence_exec_info_arr)
                .map(|((lit, seq_info), exec)| (lit.as_slice(), seq_info, exec.as_slice())),
            raw_bytes,
            n_enabled,
        )?;

        /////////////////////////////////////////
        ///// Assign Decompression Region  //////
        /////////////////////////////////////////
        layouter.assign_region(
            || "Decompression table region",
            |mut region| {
                ////////////////////////////////////////////////////////
                //////// Capture Copy Constraint/Export Cells  /////////
                ////////////////////////////////////////////////////////
                let mut last_encoded_rlc: Value<Fr> = Value::known(Fr::zero());
                let mut last_decoded_len: Value<Fr> = Value::known(Fr::zero());

                let mut encoded_len_cell: Option<AssignedCell<Fr, Fr>> = None;
                let mut encoded_rlc_cell: Option<AssignedCell<Fr, Fr>> = None;
                let mut decoded_len_cell: Option<AssignedCell<Fr, Fr>> = None;

                /////////////////////////////////////////
                /////////// Assign First Row  ///////////
                /////////////////////////////////////////
                region.assign_fixed(|| "q_first", self.q_first, 0, || Value::known(Fr::one()))?;
                for i in 0..n_enabled {
                    region.assign_fixed(
                        || "q_enable",
                        self.q_enable,
                        i,
                        || Value::known(Fr::one()),
                    )?;
                }
                let mut last_byte_idx = 0u64;
                let mut last_bit_start_idx = 0u64;

                /////////////////////////////////////////
                ///////// Assign Witness Rows  //////////
                /////////////////////////////////////////
                for (i, row) in witness_rows.iter().enumerate() {
                    region.assign_advice(
                        || "is_padding",
                        self.is_padding.column,
                        i,
                        || Value::known(Fr::zero()),
                    )?;
                    encoded_len_cell = Some(region.assign_advice(
                        || "byte_idx",
                        self.byte_idx,
                        i,
                        || Value::known(Fr::from(row.encoded_data.byte_idx)),
                    )?);
                    last_byte_idx = row.encoded_data.byte_idx;
                    region.assign_advice(
                        || "byte",
                        self.byte,
                        i,
                        || Value::known(Fr::from(row.encoded_data.value_byte as u64)),
                    )?;
                    let bits = value_bits_le(row.encoded_data.value_byte);
                    let is_reverse = row.encoded_data.reverse;
                    for (idx, col) in self.bits.iter().rev().enumerate() {
                        region.assign_advice(
                            || "value_bits",
                            col.column,
                            i,
                            || {
                                Value::known(Fr::from(
                                    (if is_reverse {
                                        bits[idx]
                                    } else {
                                        bits[N_BITS_PER_BYTE - idx - 1]
                                    }) as u64,
                                ))
                            },
                        )?;
                    }
                    encoded_rlc_cell = Some(region.assign_advice(
                        || "encoded_rlc",
                        self.encoded_rlc,
                        i,
                        || row.encoded_data.value_rlc,
                    )?);
                    last_encoded_rlc = row.encoded_data.value_rlc;
                    decoded_len_cell = Some(region.assign_advice(
                        || "decoded_len",
                        self.decoded_len,
                        i,
                        || Value::known(Fr::from(row.decoded_data.decoded_len)),
                    )?);
                    last_decoded_len = Value::known(Fr::from(row.decoded_data.decoded_len));

                    /////////////////////////////////////////
                    ///// Assign Bitstream Decoder  /////////
                    /////////////////////////////////////////
                    region.assign_advice(
                        || "bit_index_start",
                        self.bitstream_decoder.bit_index_start,
                        i,
                        || Value::known(Fr::from(row.bitstream_read_data.bit_start_idx as u64)),
                    )?;
                    let start_unchanged =
                        IsEqualChip::construct(self.bitstream_decoder.start_unchanged.clone());
                    start_unchanged.assign(
                        &mut region,
                        i,
                        Value::known(Fr::from(last_bit_start_idx)),
                        Value::known(Fr::from(row.bitstream_read_data.bit_start_idx as u64)),
                    )?;
                    last_bit_start_idx = row.bitstream_read_data.bit_start_idx as u64;

                    region.assign_advice(
                        || "bit_index_end",
                        self.bitstream_decoder.bit_index_end,
                        i,
                        || Value::known(Fr::from(row.bitstream_read_data.bit_end_idx as u64)),
                    )?;
                    region.assign_advice(
                        || "bitstring_value",
                        self.bitstream_decoder.bitstring_value,
                        i,
                        || Value::known(Fr::from(row.bitstream_read_data.bit_value)),
                    )?;
                    region.assign_advice(
                        || "is_nb0",
                        self.bitstream_decoder.is_nb0.column,
                        i,
                        || Value::known(Fr::from(row.bitstream_read_data.is_zero_bit_read as u64)),
                    )?;
                    region.assign_advice(
                        || "is_nil",
                        self.bitstream_decoder.is_nil.column,
                        i,
                        || Value::known(Fr::from(row.bitstream_read_data.is_nil as u64)),
                    )?;

                    let bit_index_end_cmp_7 = ComparatorChip::construct(
                        self.bitstream_decoder.bit_index_end_cmp_7.clone(),
                    );
                    bit_index_end_cmp_7.assign(
                        &mut region,
                        i,
                        Fr::from(row.bitstream_read_data.bit_end_idx as u64),
                        Fr::from(7u64),
                    )?;
                    let bit_index_end_cmp_15 = ComparatorChip::construct(
                        self.bitstream_decoder.bit_index_end_cmp_15.clone(),
                    );
                    bit_index_end_cmp_15.assign(
                        &mut region,
                        i,
                        Fr::from(row.bitstream_read_data.bit_end_idx as u64),
                        Fr::from(15u64),
                    )?;
                    let bit_index_end_cmp_23 = ComparatorChip::construct(
                        self.bitstream_decoder.bit_index_end_cmp_23.clone(),
                    );
                    bit_index_end_cmp_23.assign(
                        &mut region,
                        i,
                        Fr::from(row.bitstream_read_data.bit_end_idx as u64),
                        Fr::from(23u64),
                    )?;
                    let bitstring_value_eq_3 =
                        IsEqualChip::construct(self.bitstream_decoder.bitstring_value_eq_3.clone());
                    bitstring_value_eq_3.assign(
                        &mut region,
                        i,
                        Value::known(Fr::from(row.bitstream_read_data.bit_value)),
                        Value::known(Fr::from(3u64)),
                    )?;

                    /////////////////////////////////////////
                    ////////// Assign Tag Config  ///////////
                    /////////////////////////////////////////
                    region.assign_advice(
                        || "tag_config.tag",
                        self.tag_config.tag,
                        i,
                        || Value::known(Fr::from(row.state.tag as u64)),
                    )?;
                    region.assign_advice(
                        || "tag_config.tag_next",
                        self.tag_config.tag_next,
                        i,
                        || Value::known(Fr::from(row.state.tag_next as u64)),
                    )?;
                    region.assign_advice(
                        || "tag_config.tag_len",
                        self.tag_config.tag_len,
                        i,
                        || Value::known(Fr::from(row.state.tag_len)),
                    )?;
                    region.assign_advice(
                        || "tag_config.max_len",
                        self.tag_config.max_len,
                        i,
                        || Value::known(Fr::from(row.state.max_tag_len)),
                    )?;
                    region.assign_advice(
                        || "tag_config.tag_idx",
                        self.tag_config.tag_idx,
                        i,
                        || Value::known(Fr::from(row.state.tag_idx)),
                    )?;
                    let is_sequence_data = row.state.tag == ZstdTag::ZstdBlockSequenceData;
                    region.assign_advice(
                        || "tag_config.is_sequence_data",
                        self.tag_config.is_sequence_data,
                        i,
                        || Value::known(Fr::from(is_sequence_data as u64)),
                    )?;

                    let is_frame_content_size = row.state.tag == ZstdTag::FrameContentSize;
                    region.assign_advice(
                        || "tag_config.is_frame_content_size",
                        self.tag_config.is_frame_content_size,
                        i,
                        || Value::known(Fr::from(is_frame_content_size as u64)),
                    )?;

                    let is_block_header = row.state.tag == ZstdTag::BlockHeader;
                    region.assign_advice(
                        || "tag_config.is_block_header",
                        self.tag_config.is_block_header,
                        i,
                        || Value::known(Fr::from(is_block_header as u64)),
                    )?;

                    let is_literals_header = row.state.tag == ZstdTag::ZstdBlockLiteralsHeader;
                    region.assign_advice(
                        || "tag_config.is_literals_header",
                        self.tag_config.is_literals_header,
                        i,
                        || Value::known(Fr::from(is_literals_header as u64)),
                    )?;

                    let is_sequence_header = row.state.tag == ZstdTag::ZstdBlockSequenceHeader;
                    region.assign_advice(
                        || "tag_config.is_sequence_header",
                        self.tag_config.is_sequence_header,
                        i,
                        || Value::known(Fr::from(is_sequence_header as u64)),
                    )?;

                    let is_fse_code = row.state.tag == ZstdTag::ZstdBlockSequenceFseCode;
                    region.assign_advice(
                        || "tag_config.is_fse_code",
                        self.tag_config.is_fse_code,
                        i,
                        || Value::known(Fr::from(is_fse_code as u64)),
                    )?;

                    let is_null = row.state.tag == ZstdTag::Null;
                    region.assign_advice(
                        || "tag_config.is_null",
                        self.tag_config.is_null,
                        i,
                        || Value::known(Fr::from(is_null as u64)),
                    )?;

                    region.assign_advice(
                        || "tag_config.is_change",
                        self.tag_config.is_change.column,
                        i,
                        || Value::known(Fr::from((row.state.is_tag_change && i > 0) as u64)),
                    )?;
                    region.assign_advice(
                        || "tag_config.is_reverse",
                        self.tag_config.is_reverse,
                        i,
                        || Value::known(Fr::from(row.state.tag.is_reverse() as u64)),
                    )?;
                    region.assign_advice(
                        || "tag_config.tag_rlc_acc",
                        self.tag_config.tag_rlc_acc,
                        i,
                        || row.state.tag_rlc_acc,
                    )?;
                    region.assign_advice(
                        || "tag_config.tag_rlc",
                        self.tag_config.tag_rlc,
                        i,
                        || row.state.tag_rlc,
                    )?;

                    let tag_len = row.state.tag_len as usize;
                    if tag_len >= pow_of_rand.len() {
                        let mut last = *pow_of_rand.last().expect("Last pow_of_rand exists.");
                        for _ in pow_of_rand.len()..=tag_len {
                            last = last * challenges.keccak_input();
                            pow_of_rand.push(last);
                        }
                    }
                    region.assign_advice(
                        || "tag_config.rpow_tag_len",
                        self.tag_config.rpow_tag_len,
                        i,
                        || pow_of_rand[tag_len],
                    )?;

                    let tag_idx_eq_tag_len =
                        IsEqualChip::construct(self.tag_config.tag_idx_eq_tag_len.clone());
                    tag_idx_eq_tag_len.assign(
                        &mut region,
                        i,
                        Value::known(Fr::from(row.state.tag_idx)),
                        Value::known(Fr::from(row.state.tag_len)),
                    )?;

                    let tag_chip = BinaryNumberChip::construct(self.tag_config.tag_bits);
                    tag_chip.assign(&mut region, i, &row.state.tag)?;

                    /////////////////////////////////////////
                    ///////// Assign Block Config  //////////
                    /////////////////////////////////////////
                    let block_idx = row.state.block_idx;
                    let is_block = row.state.tag.is_block();
                    let is_block_header = row.state.tag == ZstdTag::BlockHeader;

                    if is_block || is_block_header {
                        let curr_block_info = block_info_arr[block_idx as usize - 1];
                        assert_eq!(
                            block_idx as usize, curr_block_info.block_idx,
                            "block_idx mismatch"
                        );
                        let curr_sequence_info = sequence_info_arr[block_idx as usize - 1];
                        assert_eq!(
                            block_idx as usize, curr_sequence_info.block_idx,
                            "block_idx mismatch"
                        );
                        region.assign_advice(
                            || "block_config.block_len",
                            self.block_config.block_len,
                            i,
                            || Value::known(Fr::from(curr_block_info.block_len as u64)),
                        )?;
                        region.assign_advice(
                            || "block_config.block_idx",
                            self.block_config.block_idx,
                            i,
                            || Value::known(Fr::from(curr_block_info.block_idx as u64)),
                        )?;
                        region.assign_advice(
                            || "block_config.is_last_block",
                            self.block_config.is_last_block,
                            i,
                            || Value::known(Fr::from(curr_block_info.is_last_block as u64)),
                        )?;
                        region.assign_advice(
                            || "block_config.is_block",
                            self.block_config.is_block,
                            i,
                            || Value::known(Fr::from(is_block as u64)),
                        )?;
                        region.assign_advice(
                            || "block_config.num_sequences",
                            self.block_config.num_sequences,
                            i,
                            || Value::known(Fr::from(curr_sequence_info.num_sequences as u64)),
                        )?;
                        region.assign_advice(
                            || "block_config.regen_size",
                            self.block_config.regen_size,
                            i,
                            || Value::known(Fr::from(curr_block_info.regen_size)),
                        )?;
                        let is_predefined = match row.fse_data.table_kind {
                            // default: ignored case
                            0 => false,
                            // LLT
                            1 => !curr_sequence_info.compression_mode[0],
                            // MOT
                            2 => !curr_sequence_info.compression_mode[1],
                            // MLT
                            3 => !curr_sequence_info.compression_mode[2],
                            _ => unreachable!("table_kind in [1, 2, 3]"),
                        };
                        region.assign_advice(
                            || "fse_decoder.is_predefined",
                            self.fse_decoder.is_predefined,
                            i,
                            || Value::known(Fr::from(is_predefined)),
                        )?;

                        let table_names = ["LLT", "MOT", "MLT"];
                        for (idx, (&table_name, &compression_mode)) in table_names
                            .iter()
                            .zip_eq(curr_sequence_info.compression_mode.iter())
                            .enumerate()
                        {
                            region.assign_advice(
                                || table_name,
                                self.block_config.compression_modes[idx],
                                i,
                                || Value::known(Fr::from(compression_mode as u64)),
                            )?;
                        }
                        let is_empty_sequences =
                            IsEqualChip::construct(self.block_config.is_empty_sequences.clone());
                        is_empty_sequences.assign(
                            &mut region,
                            i,
                            Value::known(Fr::from(curr_sequence_info.num_sequences as u64)),
                            Value::known(Fr::zero()),
                        )?;
                    }

                    ////////////////////////////////////////////////////////////
                    ///////// Assign Extra Sequence Bitstream Fields  //////////
                    ////////////////////////////////////////////////////////////
                    region.assign_advice(
                        || "sequence_data_decoder.idx",
                        self.sequences_data_decoder.idx,
                        i,
                        || Value::known(Fr::from((row.bitstream_read_data.seq_idx) as u64)),
                    )?;
                    region.assign_advice(
                        || "sequence_data_decoder.is_init_state",
                        self.sequences_data_decoder.is_init_state.column,
                        i,
                        || Value::known(Fr::from(row.bitstream_read_data.is_seq_init as u64)),
                    )?;

                    let seq_states = row.bitstream_read_data.states;
                    let seq_symbols = row.bitstream_read_data.symbols;
                    let tables = ["LLT", "MLT", "MOT"];

                    for idx in 0..3 {
                        region.assign_advice(
                            || format!("sequence_data_decoder.states: {:?}", tables[idx]),
                            self.sequences_data_decoder.states[idx],
                            i,
                            || Value::known(Fr::from(seq_states[idx])),
                        )?;
                        region.assign_advice(
                            || format!("sequence_data_decoder.symbols: {:?}", tables[idx]),
                            self.sequences_data_decoder.symbols[idx],
                            i,
                            || Value::known(Fr::from(seq_symbols[idx])),
                        )?;
                        region.assign_advice(
                            || format!("sequence_data_decoder.values: {:?}", tables[idx]),
                            self.sequences_data_decoder.values[idx],
                            i,
                            || Value::known(Fr::from(row.bitstream_read_data.values[idx])),
                        )?;
                    }
                    region.assign_advice(
                        || "sequence_data_decoder.is_update_state",
                        self.sequences_data_decoder.is_update_state.column,
                        i,
                        || Value::known(Fr::from(row.bitstream_read_data.is_update_state)),
                    )?;
                    region.assign_advice(
                        || "sequence_data_decoder.baseline",
                        self.sequences_data_decoder.baseline,
                        i,
                        || Value::known(Fr::from(row.bitstream_read_data.baseline)),
                    )?;
                    let byte0_lt_0x80 =
                        LtChip::construct(self.sequences_header_decoder.byte0_lt_0x80);
                    byte0_lt_0x80.assign(
                        &mut region,
                        i,
                        Fr::from(row.encoded_data.value_byte as u64),
                        Fr::from(0x80),
                    )?;
                    let byte0_lt_0xff =
                        LtChip::construct(self.sequences_header_decoder.byte0_lt_0xff);
                    byte0_lt_0xff.assign(
                        &mut region,
                        i,
                        Fr::from(row.encoded_data.value_byte as u64),
                        Fr::from(0xff),
                    )?;

                    ////////////////////////////////////////////////
                    ///////// Assign FSE Decoding Fields  //////////
                    ////////////////////////////////////////////////
                    region.assign_advice(
                        || "fse_decoder.table_kind",
                        self.fse_decoder.table_kind,
                        i,
                        || Value::known(Fr::from(row.fse_data.table_kind)),
                    )?;
                    region.assign_advice(
                        || "fse_decoder.table_size",
                        self.fse_decoder.table_size,
                        i,
                        || Value::known(Fr::from(row.fse_data.table_size)),
                    )?;
                    region.assign_advice(
                        || "fse_decoder.symbol",
                        self.fse_decoder.symbol,
                        i,
                        || Value::known(Fr::from(row.fse_data.symbol)),
                    )?;
                    region.assign_advice(
                        || "fse_decoder.value_decoded",
                        self.fse_decoder.value_decoded,
                        i,
                        || Value::known(Fr::from(row.fse_data.value_decoded)),
                    )?;
                    region.assign_advice(
                        || "fse_decoder.probability_acc",
                        self.fse_decoder.probability_acc,
                        i,
                        || Value::known(Fr::from(row.fse_data.probability_acc)),
                    )?;
                    region.assign_advice(
                        || "fse_decoder.is_repeat_bits_loop",
                        self.fse_decoder.is_repeat_bits_loop.column,
                        i,
                        || Value::known(Fr::from(row.fse_data.is_repeat_bits_loop)),
                    )?;
                    region.assign_advice(
                        || "fse_decoder.is_trailing_bits",
                        self.fse_decoder.is_trailing_bits.column,
                        i,
                        || Value::known(Fr::from(row.fse_data.is_trailing_bits)),
                    )?;

                    let value_decoded_eq_0 =
                        IsEqualChip::construct(self.fse_decoder.value_decoded_eq_0.clone());
                    value_decoded_eq_0.assign(
                        &mut region,
                        i,
                        Value::known(Fr::from(row.fse_data.value_decoded)),
                        Value::known(Fr::zero()),
                    )?;
                    let value_decoded_eq_1 =
                        IsEqualChip::construct(self.fse_decoder.value_decoded_eq_1.clone());
                    value_decoded_eq_1.assign(
                        &mut region,
                        i,
                        Value::known(Fr::from(row.fse_data.value_decoded)),
                        Value::known(Fr::one()),
                    )?;

                    // Enable lookups?
                    let enable_fse_var_bit_packing = is_fse_code
                        && !row.bitstream_read_data.is_nil
                        && !row.state.is_tag_change
                        && !row.fse_data.is_repeat_bits_loop
                        && !row.fse_data.is_trailing_bits;
                    region.assign_advice(
                        || "lookups_enable.enable_fse_var_bit_packing",
                        self.lookups_enabled.enable_fse_var_bit_packing,
                        i,
                        || Value::known(Fr::from(enable_fse_var_bit_packing as u64)),
                    )?;

                    let enable_fse_norm_prob = is_fse_code
                        && !row.bitstream_read_data.is_nil
                        && !row.state.is_tag_change
                        && (row.fse_data.value_decoded != 1)
                        && !row.fse_data.is_trailing_bits
                        && !row.fse_data.is_repeat_bits_loop;
                    region.assign_advice(
                        || "lookups_enable.enable_fse_norm_prob",
                        self.lookups_enabled.enable_fse_norm_prob,
                        i,
                        || Value::known(Fr::from(enable_fse_norm_prob as u64)),
                    )?;

                    let enable_seq_data_fse_table = is_sequence_data
                        && !row.state.is_tag_change
                        && !row.bitstream_read_data.is_nil
                        && !row.bitstream_read_data.is_seq_init
                        && (row.bitstream_read_data.is_update_state == 1);
                    region.assign_advice(
                        || "lookups_enable.enable_seq_data_fse_table",
                        self.lookups_enabled.enable_seq_data_fse_table,
                        i,
                        || Value::known(Fr::from(enable_seq_data_fse_table as u64)),
                    )?;

                    let enable_seq_data_instruction = is_sequence_data
                        && !row.state.is_tag_change
                        && !row.bitstream_read_data.is_nil
                        && (row.fse_data.table_kind == 1)
                        && !row.bitstream_read_data.is_seq_init
                        && (row.bitstream_read_data.is_update_state != 1);
                    region.assign_advice(
                        || "lookups_enable.enable_seq_data_instruction",
                        self.lookups_enabled.enable_seq_data_instruction,
                        i,
                        || Value::known(Fr::from(enable_seq_data_instruction as u64)),
                    )?;

                    let enable_seq_data_rom = is_sequence_data
                        && !row.state.is_tag_change
                        && !row.bitstream_read_data.is_nil
                        && !row.bitstream_read_data.is_seq_init
                        && (row.bitstream_read_data.is_update_state != 1);
                    region.assign_advice(
                        || "lookups_enable.enable_seq_data_rom",
                        self.lookups_enabled.enable_seq_data_rom,
                        i,
                        || Value::known(Fr::from(enable_seq_data_rom as u64)),
                    )?;

                    let enable_bs_2_bytes = !row.bitstream_read_data.is_nil
                        && !row.bitstream_read_data.is_zero_bit_read
                        && row.bitstream_read_data.bit_end_idx >= 8
                        && row.bitstream_read_data.bit_end_idx <= 15
                        && (is_fse_code || is_sequence_data);
                    region.assign_advice(
                        || "lookups_enable.enable_bs_2_bytes",
                        self.lookups_enabled.enable_bs_2_bytes,
                        i,
                        || Value::known(Fr::from(enable_bs_2_bytes as u64)),
                    )?;
                }

                // The last encoded_rlc at this point indicates the encoded_rlc until the
                // penultimate tag. We need to do one more round of RLC computation, to calculate
                // the RLC taking into considering the ultimate tag as well.
                let last_row = witness_rows.last().expect("last row exists");
                let last_tag_len = last_row.state.tag_len as usize;
                let last_tag_rlc = last_row.state.tag_rlc;
                if last_tag_len >= pow_of_rand.len() {
                    let mut last = *pow_of_rand.last().expect("Last pow_of_rand exists.");
                    for _ in pow_of_rand.len()..=last_tag_len {
                        last = last * challenges.keccak_input();
                        pow_of_rand.push(last);
                    }
                }
                let last_rpow_tag_len = pow_of_rand[last_tag_len];
                let final_encoded_rlc = last_encoded_rlc * last_rpow_tag_len + last_tag_rlc;

                /////////////////////////////////////////
                ///////// Assign Padding Rows  //////////
                /////////////////////////////////////////
                for idx in witness_rows.len()..n_enabled {
                    if idx == witness_rows.len() {
                        region.assign_advice(
                            || "is_tag_change",
                            self.tag_config.is_change.column,
                            idx,
                            || Value::known(Fr::one()),
                        )?;
                    }
                    encoded_len_cell = Some(region.assign_advice(
                        || "byte_idx",
                        self.byte_idx,
                        idx,
                        || Value::known(Fr::from(last_byte_idx + 1)),
                    )?);
                    encoded_rlc_cell = Some(region.assign_advice(
                        || "encoded_rlc",
                        self.encoded_rlc,
                        idx,
                        || final_encoded_rlc,
                    )?);
                    decoded_len_cell = Some(region.assign_advice(
                        || "decoded_len",
                        self.decoded_len,
                        idx,
                        || last_decoded_len,
                    )?);

                    region.assign_advice(
                        || "tag_config.tag",
                        self.tag_config.tag,
                        idx,
                        || Value::known(Fr::from(ZstdTag::Null as u64)),
                    )?;
                    region.assign_advice(
                        || "is_padding",
                        self.is_padding.column,
                        idx,
                        || Value::known(Fr::one()),
                    )?;
                    let byte0_lt_0x80 =
                        LtChip::construct(self.sequences_header_decoder.byte0_lt_0x80);
                    byte0_lt_0x80.assign(&mut region, idx, Fr::zero(), Fr::from(0x80))?;
                    let byte0_lt_0xff =
                        LtChip::construct(self.sequences_header_decoder.byte0_lt_0xff);
                    byte0_lt_0xff.assign(&mut region, idx, Fr::zero(), Fr::from(0xff))?;

                    // Bitstream decoder gadgets
                    let bit_index_end_cmp_7 = ComparatorChip::construct(
                        self.bitstream_decoder.bit_index_end_cmp_7.clone(),
                    );
                    bit_index_end_cmp_7.assign(&mut region, idx, Fr::zero(), Fr::from(7u64))?;
                    let bit_index_end_cmp_15 = ComparatorChip::construct(
                        self.bitstream_decoder.bit_index_end_cmp_15.clone(),
                    );
                    bit_index_end_cmp_15.assign(&mut region, idx, Fr::zero(), Fr::from(15u64))?;
                    let bit_index_end_cmp_23 = ComparatorChip::construct(
                        self.bitstream_decoder.bit_index_end_cmp_23.clone(),
                    );
                    bit_index_end_cmp_23.assign(&mut region, idx, Fr::zero(), Fr::from(23u64))?;
                    let bitstring_value_eq_3 =
                        IsEqualChip::construct(self.bitstream_decoder.bitstring_value_eq_3.clone());
                    bitstring_value_eq_3.assign(
                        &mut region,
                        idx,
                        Value::known(Fr::zero()),
                        Value::known(Fr::from(3u64)),
                    )?;
                    let start_unchanged =
                        IsEqualChip::construct(self.bitstream_decoder.start_unchanged.clone());
                    start_unchanged.assign(
                        &mut region,
                        idx,
                        Value::known(Fr::from(last_bit_start_idx)),
                        Value::known(Fr::zero()),
                    )?;
                    last_bit_start_idx = 0;

                    // Fse decoder gadgets
                    let value_decoded_eq_0 =
                        IsEqualChip::construct(self.fse_decoder.value_decoded_eq_0.clone());
                    value_decoded_eq_0.assign(
                        &mut region,
                        idx,
                        Value::known(Fr::zero()),
                        Value::known(Fr::zero()),
                    )?;
                    let value_decoded_eq_1 =
                        IsEqualChip::construct(self.fse_decoder.value_decoded_eq_1.clone());
                    value_decoded_eq_1.assign(
                        &mut region,
                        idx,
                        Value::known(Fr::zero()),
                        Value::known(Fr::one()),
                    )?;
                }

                // decoded length from SeqExecConfig and decoder config must match.
                region.constrain_equal(exported_len.cell(), decoded_len_cell.unwrap().cell())?;

                Ok(AssignedDecoderConfigExports {
                    // length of encoded data (from DecoderConfig)
                    encoded_len: encoded_len_cell.unwrap().clone(),
                    // RLC of encoded data (from DecoderConfig)
                    encoded_rlc: encoded_rlc_cell.unwrap().clone(),
                    // length of decoded data (from SeqExecConfig)
                    decoded_len: exported_len.clone(),
                    // RLC of decoded data (from SeqExecConfig)
                    decoded_rlc: exported_rlc.clone(),
                })
            },
        )
    }

    pub fn unusable_rows(&self) -> usize {
        64
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        witgen::{init_zstd_encoder, process, MultiBlockProcessResult},
        DecoderConfig, DecoderConfigArgs,
    };
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use std::{fs, io::Write};
    use zkevm_circuits::{
        table::{BitwiseOpTable, Pow2Table, PowOfRandTable, RangeTable, U8Table},
        util::Challenges,
    };

    #[derive(Clone, Debug, Default)]
    struct DecoderConfigTester<const L: usize, const R: usize> {
        raw: Vec<u8>,
        compressed: Vec<u8>,
        k: u32,
    }

    impl<const L: usize, const R: usize> Circuit<Fr> for DecoderConfigTester<L, R> {
        type Config = (DecoderConfig<L, R>, U8Table, Challenges);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let challenges = Challenges::construct_p1(meta);
            let challenges_expr = challenges.exprs(meta);

            let pow_rand_table = PowOfRandTable::construct(meta, &challenges_expr);
            let pow2_table = Pow2Table::construct(meta);
            let u8_table = U8Table::construct(meta);
            let range8 = RangeTable::construct(meta);
            let range16 = RangeTable::construct(meta);
            let range512 = RangeTable::construct(meta);
            let range_block_len = RangeTable::construct(meta);
            let bitwise_op_table = BitwiseOpTable::construct(meta);

            let config = DecoderConfig::configure(
                meta,
                &challenges_expr,
                DecoderConfigArgs {
                    pow_rand_table,
                    pow2_table,
                    u8_table,
                    range8,
                    range16,
                    range512,
                    range_block_len,
                    bitwise_op_table,
                },
            );

            (config, u8_table, challenges)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let (config, u8_table, challenge) = config;
            let challenges = challenge.values(&layouter);

            let MultiBlockProcessResult {
                witness_rows,
                literal_bytes: decoded_literals,
                fse_aux_tables,
                block_info_arr,
                sequence_info_arr,
                address_table_rows: address_table_arr,
                sequence_exec_results,
            } = process(&self.compressed, challenges.keccak_input());

            let (recovered_bytes, sequence_exec_info_arr) = sequence_exec_results.into_iter().fold(
                (Vec::new(), Vec::new()),
                |(mut out_byte, mut out_exec), res| {
                    out_byte.extend(res.recovered_bytes);
                    out_exec.push(res.exec_trace);
                    (out_byte, out_exec)
                },
            );

            assert_eq!(
                recovered_bytes, self.raw,
                "witgen recovered bytes do not match original raw bytes",
            );

            u8_table.load(&mut layouter)?;
            let decoder_config_exports = config.assign(
                &mut layouter,
                &self.raw,
                &self.compressed,
                witness_rows,
                decoded_literals,
                fse_aux_tables,
                block_info_arr,
                sequence_info_arr,
                address_table_arr,
                sequence_exec_info_arr,
                &challenges,
                self.k,
            )?;

            let expected_encoded_len = Value::known(Fr::from(self.compressed.len() as u64));
            let expected_encoded_rlc = self
                .compressed
                .iter()
                .fold(Value::known(Fr::zero()), |acc, &x| {
                    acc * challenges.keccak_input() + Value::known(Fr::from(x as u64))
                });
            let expected_decoded_len = Value::known(Fr::from(self.raw.len() as u64));
            let expected_decoded_rlc = self.raw.iter().fold(Value::known(Fr::zero()), |acc, &x| {
                acc * challenges.keccak_input() + Value::known(Fr::from(x as u64))
            });

            println!("expected encoded len = {:?}", expected_encoded_len);
            println!(
                "got      encoded len = {:?}\n\n",
                decoder_config_exports.encoded_len.value()
            );
            println!("expected encoded rlc = {:?}", expected_encoded_rlc);
            println!(
                "got      encoded rlc = {:?}\n\n",
                decoder_config_exports.encoded_rlc.value()
            );
            println!("expected decoded len = {:?}", expected_decoded_len);
            println!(
                "got      decoded len = {:?}\n\n",
                decoder_config_exports.decoded_len.value()
            );
            println!("expected decoded rlc = {:?}", expected_decoded_rlc);
            println!(
                "got      decoded rlc = {:?}\n\n",
                decoder_config_exports.decoded_rlc.value()
            );

            Ok(())
        }
    }

    #[test]
    fn test_decoder_config_working_example() {
        let raw: Vec<u8> = String::from("Romeo and Juliet@Excerpt from Act 2, Scene 2@@JULIET@O Romeo, Romeo! wherefore art thou Romeo?@Deny thy father and refuse thy name;@Or, if thou wilt not, be but sworn my love,@And I'll no longer be a Capulet.@@ROMEO@[Aside] Shall I hear more, or shall I speak at this?@@JULIET@'Tis but thy name that is my enemy;@Thou art thyself, though not a Montague.@What's Montague? it is nor hand, nor foot,@Nor arm, nor face, nor any other part@Belonging to a man. O, be some other name!@What's in a name? that which we call a rose@By any other name would smell as sweet;@So Romeo would, were he not Romeo call'd,@Retain that dear perfection which he owes@Without that title. Romeo, doff thy name,@And for that name which is no part of thee@Take all myself.@@ROMEO@I take thee at thy word:@Call me but love, and I'll be new baptized;@Henceforth I never will be Romeo.@@JULIET@What man art thou that thus bescreen'd in night@So stumblest on my counsel?").as_bytes().to_vec();

        let compressed = {
            // compression level = 0 defaults to using level=3, which is zstd's default.
            let mut encoder = init_zstd_encoder(None);

            // set source length, which will be reflected in the frame header.
            encoder
                .set_pledged_src_size(Some(raw.len() as u64))
                .expect("Encoder src_size: raw.len()");

            encoder.write_all(&raw).expect("Encoder write_all");
            encoder.finish().expect("Encoder success")
        };

        let k = 18;
        let decoder_config_tester: DecoderConfigTester<256, 256> =
            DecoderConfigTester { raw, compressed, k };
        let mock_prover = MockProver::<Fr>::run(k, &decoder_config_tester, vec![]).unwrap();
        mock_prover.assert_satisfied_par();
    }

    #[test]
    fn test_decoder_config_batch_data() -> Result<(), std::io::Error> {
        let mut batch_files = fs::read_dir("./data/test_batches")?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        batch_files.sort();

        let batches = batch_files
            .iter()
            .map(fs::read_to_string)
            .filter_map(|data| data.ok())
            .map(|data| hex::decode(data.trim_end()).expect("Failed to decode hex data"))
            .collect::<Vec<Vec<u8>>>();

        let raw = batches[127].clone();
        let compressed = {
            // compression level = 0 defaults to using level=3, which is zstd's default.
            let mut encoder = init_zstd_encoder(None);

            // set source length, which will be reflected in the frame header.
            encoder
                .set_pledged_src_size(Some(raw.len() as u64))
                .expect("Encoder src_size: raw.len()");
            // include the content size to know at decode time the expected size of decoded data.

            encoder.write_all(&raw).expect("Encoder write_all");
            encoder.finish().expect("Encoder success")
        };

        println!(
            "len(encoded)={:6}\tlen(decoded)={:6}",
            compressed.len(),
            raw.len()
        );
        let k = 18;
        let decoder_config_tester: DecoderConfigTester<256, 256> =
            DecoderConfigTester { raw, compressed, k };
        let mock_prover = MockProver::<Fr>::run(k, &decoder_config_tester, vec![]).unwrap();
        mock_prover.assert_satisfied_par();

        Ok(())
    }

    #[test]
    #[ignore = "single_blob: heavy"]
    fn test_decoder_config_single_blob() -> Result<(), std::io::Error> {
        let mut blob_files = fs::read_dir("./data/test_blobs")?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        blob_files.sort();

        // This blob data is of the form, with every 32-bytes chunk having its most-significant
        // byte set to 0.
        let blob_data = hex::decode(fs::read_to_string(&blob_files[0])?.trim_end())
            .expect("failed to decode hex data");

        let mut batch_data = Vec::with_capacity(31 * 4096);
        for bytes32_chunk in blob_data.chunks(32) {
            assert!(bytes32_chunk[0] == 0);
            batch_data.extend_from_slice(&bytes32_chunk[1..])
        }

        let encoded_batch_data = {
            // compression level = 0 defaults to using level=3, which is zstd's default.
            let mut encoder = init_zstd_encoder(None);

            // set source length, which will be reflected in the frame header.
            encoder
                .set_pledged_src_size(Some(batch_data.len() as u64))
                .expect("Encoder src_size: raw.len()");

            encoder.write_all(&batch_data).expect("Encoder write_all");
            encoder.finish().expect("Encoder success")
        };

        println!("len(blob_data)          = {:6}", blob_data.len());
        println!("len(batch_data)         = {:6}", batch_data.len());
        println!("len(encoded_batch_data) = {:6}", encoded_batch_data.len());

        let k = 20;
        let decoder_config_tester: DecoderConfigTester<1024, 512> = DecoderConfigTester {
            raw: batch_data,
            compressed: encoded_batch_data,
            k,
        };
        let mock_prover = MockProver::<Fr>::run(k, &decoder_config_tester, vec![]).unwrap();
        mock_prover.assert_satisfied_par();

        Ok(())
    }

    #[test]
    fn test_decoder_config_multi_block() -> Result<(), std::io::Error> {
        let mut batch_files = fs::read_dir("./data/test_batches")?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        batch_files.sort();

        let batches = batch_files
            .iter()
            .map(fs::read_to_string)
            .filter_map(|data| data.ok())
            .map(|data| hex::decode(data.trim_end()).expect("Failed to decode hex data"))
            .collect::<Vec<Vec<u8>>>();

        let raw = batches[1].clone();
        let compressed = {
            // compression level = 0 defaults to using level=3, which is zstd's default.
            let mut encoder = init_zstd_encoder(Some(1024 * 4));

            // set source length, which will be reflected in the frame header.
            encoder
                .set_pledged_src_size(Some(raw.len() as u64))
                .expect("Encoder src_size: raw.len()");

            encoder.write_all(&raw).expect("Encoder write_all");
            encoder.finish().expect("Encoder success")
        };

        println!(
            "len(encoded)={:6}\tlen(decoded)={:6}",
            compressed.len(),
            raw.len()
        );
        let k = 18;
        let decoder_config_tester: DecoderConfigTester<256, 256> =
            DecoderConfigTester { raw, compressed, k };
        let mock_prover = MockProver::<Fr>::run(k, &decoder_config_tester, vec![]).unwrap();
        mock_prover.assert_satisfied_par();

        Ok(())
    }

    #[test]
    #[ignore = "multi_blob: heavy"]
    fn test_decoder_config_large_multi_block() -> Result<(), std::io::Error> {
        let mut batch_files = fs::read_dir("./data/test_blobs/multi")?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        batch_files.sort();

        let mut multi_batch_data = Vec::with_capacity(500_000);
        for batch_file in batch_files {
            let batch_data = fs::read(batch_file)?;
            multi_batch_data.extend_from_slice(&batch_data);
        }

        let encoded_multi_batch_data = {
            // compression level = 0 defaults to using level=3, which is zstd's default.
            let mut encoder = init_zstd_encoder(None);

            // set source length, which will be reflected in the frame header.
            encoder
                .set_pledged_src_size(Some(multi_batch_data.len() as u64))
                .expect("Encoder src_size: raw.len()");

            encoder
                .write_all(&multi_batch_data)
                .expect("Encoder write_all");
            encoder.finish().expect("Encoder success")
        };

        println!("len(multi_batch_data)={:?}", multi_batch_data.len());
        println!(
            "len(encoded_multi_batch_data)={:?}",
            encoded_multi_batch_data.len()
        );

        let k = 20;
        let decoder_config_tester: DecoderConfigTester<1024, 512> = DecoderConfigTester {
            raw: multi_batch_data,
            compressed: encoded_multi_batch_data,
            k,
        };
        let mock_prover = MockProver::<Fr>::run(k, &decoder_config_tester, vec![]).unwrap();
        mock_prover.assert_satisfied_par();

        Ok(())
    }
}
