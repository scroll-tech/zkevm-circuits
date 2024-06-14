use std::{collections::BTreeMap, io::Cursor};

use bitstream_io::{BitRead, BitReader, LittleEndian};
use gadgets::impl_expr;
use gadgets::Field;
use halo2_proofs::{circuit::Value, plonk::Expression};
use itertools::Itertools;
use std::collections::HashMap;
use strum_macros::EnumIter;

use super::{
    params::N_BITS_PER_BYTE,
    util::{read_variable_bit_packing, smaller_powers_of_two, value_bits_le},
};

#[derive(Debug, Default, Clone, Copy)]
pub enum BlockType {
    #[default]
    RawBlock = 0,
    RleBlock,
    ZstdCompressedBlock,
    Reserved,
}

impl From<u8> for BlockType {
    fn from(src: u8) -> Self {
        match src {
            0 => Self::RawBlock,
            1 => Self::RleBlock,
            2 => Self::ZstdCompressedBlock,
            3 => Self::Reserved,
            _ => unreachable!("BlockType is 2 bits"),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct BlockInfo {
    pub block_idx: usize,
    pub block_type: BlockType,
    pub block_len: usize,
    pub is_last_block: bool,
    pub regen_size: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SequenceInfo {
    pub block_idx: usize,
    pub num_sequences: usize,
    pub compression_mode: [bool; 3],
}

/// The type for indicate each range in output bytes by sequence execution
#[derive(Debug, Clone)]
pub enum SequenceExecInfo {
    LiteralCopy(std::ops::Range<usize>),
    BackRef(std::ops::Range<usize>),
}

/// The type to describe an execution: (instruction_id, exec_info)
#[derive(Debug, Clone)]
pub struct SequenceExec(pub usize, pub SequenceExecInfo);

/// The type of Lstream.
#[derive(Clone, Copy, Debug, EnumIter)]
pub enum LstreamNum {
    /// Lstream 1.
    Lstream1 = 0,
    /// Lstream 2.
    Lstream2,
    /// Lstream 3.
    Lstream3,
    /// Lstream 4.
    Lstream4,
}

impl From<LstreamNum> for usize {
    fn from(value: LstreamNum) -> Self {
        value as usize
    }
}
impl From<usize> for LstreamNum {
    fn from(value: usize) -> LstreamNum {
        match value {
            0 => LstreamNum::Lstream1,
            1 => LstreamNum::Lstream2,
            2 => LstreamNum::Lstream3,
            3 => LstreamNum::Lstream4,
            _ => unreachable!("Wrong stream_idx"),
        }
    }
}

impl_expr!(LstreamNum);

/// Various tags that we can decode from a zstd encoded data.
#[derive(Clone, Copy, Debug, EnumIter, PartialEq, Eq, Hash)]
pub enum ZstdTag {
    /// Null is reserved for padding rows.
    Null = 0,
    /// The frame header's descriptor.
    FrameHeaderDescriptor,
    /// The frame's content size.
    FrameContentSize,
    /// The block's header.
    BlockHeader,
    /// Zstd block's literals header.
    ZstdBlockLiteralsHeader,
    /// Zstd blocks might contain raw bytes.
    ZstdBlockLiteralsRawBytes,
    /// Beginning of sequence section.
    ZstdBlockSequenceHeader,
    /// Zstd block's FSE code.
    ZstdBlockSequenceFseCode,
    /// sequence bitstream for recovering instructions
    ZstdBlockSequenceData,
}

impl ZstdTag {
    /// Whether this tag is a part of block or not.
    pub fn is_block(&self) -> bool {
        match self {
            Self::Null => false,
            Self::FrameHeaderDescriptor => false,
            Self::FrameContentSize => false,
            Self::BlockHeader => false,
            Self::ZstdBlockLiteralsHeader => true,
            Self::ZstdBlockLiteralsRawBytes => true,
            Self::ZstdBlockSequenceHeader => true,
            Self::ZstdBlockSequenceFseCode => true,
            Self::ZstdBlockSequenceData => true,
        }
    }

    /// Whether this tag is processed in back-to-front order.
    pub fn is_reverse(&self) -> bool {
        match self {
            Self::Null => false,
            Self::FrameHeaderDescriptor => false,
            Self::FrameContentSize => false,
            Self::BlockHeader => false,
            Self::ZstdBlockLiteralsHeader => false,
            Self::ZstdBlockLiteralsRawBytes => false,
            Self::ZstdBlockSequenceHeader => false,
            Self::ZstdBlockSequenceFseCode => false,
            Self::ZstdBlockSequenceData => true,
        }
    }

    /// The maximum number of bytes that can be taken by this tag.
    pub fn max_len(&self) -> u64 {
        match self {
            Self::Null => 0,
            Self::FrameHeaderDescriptor => 1,
            Self::FrameContentSize => 8,
            Self::BlockHeader => 3,
            // as per spec, should be 5. But given that our encoder does not compress literals, it
            // is 3.
            Self::ZstdBlockLiteralsHeader => 3,
            Self::ZstdBlockLiteralsRawBytes => (1 << 17) - 1,
            Self::ZstdBlockSequenceHeader => 4,
            Self::ZstdBlockSequenceFseCode => 128,
            Self::ZstdBlockSequenceData => (1 << 17) - 1,
        }
    }
}

impl_expr!(ZstdTag);

impl From<ZstdTag> for usize {
    fn from(value: ZstdTag) -> Self {
        value as usize
    }
}

/// FSE table variants that we observe in the sequences section.
#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum FseTableKind {
    /// Literal length FSE table.
    LLT = 1,
    /// Match offset FSE table.
    MOT,
    /// Match length FSE table.
    MLT,
}

impl_expr!(FseTableKind);

impl ToString for ZstdTag {
    fn to_string(&self) -> String {
        String::from(match self {
            Self::Null => "null",
            Self::FrameHeaderDescriptor => "FrameHeaderDescriptor",
            Self::FrameContentSize => "FrameContentSize",
            Self::BlockHeader => "BlockHeader",
            Self::ZstdBlockLiteralsHeader => "ZstdBlockLiteralsHeader",
            Self::ZstdBlockLiteralsRawBytes => "ZstdBlockLiteralsRawBytes",
            Self::ZstdBlockSequenceHeader => "ZstdBlockSequenceHeader",
            Self::ZstdBlockSequenceFseCode => "ZstdBlockSequenceFseCode",
            Self::ZstdBlockSequenceData => "ZstdBlockSequenceData",
        })
    }
}

#[derive(Clone, Debug)]
pub struct ZstdState<F> {
    pub tag: ZstdTag,
    pub tag_next: ZstdTag,
    pub block_idx: u64,
    pub max_tag_len: u64,
    pub tag_len: u64,
    pub tag_idx: u64,
    pub is_tag_change: bool,
    pub tag_rlc: Value<F>,
    pub tag_rlc_acc: Value<F>,
}

impl<F: Field> Default for ZstdState<F> {
    fn default() -> Self {
        Self {
            tag: ZstdTag::Null,
            tag_next: ZstdTag::FrameHeaderDescriptor,
            block_idx: 0,
            max_tag_len: 0,
            tag_len: 0,
            tag_idx: 0,
            is_tag_change: false,
            tag_rlc: Value::known(F::zero()),
            tag_rlc_acc: Value::known(F::zero()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncodedData<F> {
    pub byte_idx: u64,
    pub encoded_len: u64,
    pub value_byte: u8,
    pub reverse: bool,
    pub reverse_idx: u64,
    pub reverse_len: u64,
    pub value_rlc: Value<F>,
}

impl<F: Field> EncodedData<F> {
    pub fn value_bits_le(&self) -> [u8; N_BITS_PER_BYTE] {
        value_bits_le(self.value_byte)
    }
}

impl<F: Field> Default for EncodedData<F> {
    fn default() -> Self {
        Self {
            byte_idx: 0,
            encoded_len: 0,
            value_byte: 0,
            reverse: false,
            reverse_idx: 0,
            reverse_len: 0,
            value_rlc: Value::known(F::zero()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DecodedData {
    pub decoded_len: u64,
}

/// FSE decoding data from witness generation
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FseDecodingRow {
    /// The FSE table that is being decoded. Possible values are:
    /// - LLT = 1, MOT = 2, MLT = 3
    pub table_kind: u64,
    /// The number of states in the FSE table. table_size == 1 << AL, where AL is the accuracy log
    /// of the FSE table.
    pub table_size: u64,
    /// The symbol emitted by the FSE table at this state.
    pub symbol: u64,
    /// During FSE table decoding, keep track of the number of symbol emitted
    pub num_emitted: u64,
    /// The value decoded as per variable bit-packing.
    pub value_decoded: u64,
    /// An accumulator of the number of states allocated to each symbol as we decode the FSE table.
    /// This is the normalised probability for the symbol.
    pub probability_acc: u64,
    /// Whether we are in the repeat bits loop.
    pub is_repeat_bits_loop: bool,
    /// Whether this row represents the 0-7 trailing bits that should be ignored.
    pub is_trailing_bits: bool,
}

/// A single row in the FSE table.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FseTableRow {
    /// The FSE state at this row in the FSE table.
    pub state: u64,
    /// The baseline associated with this state.
    pub baseline: u64,
    /// The number of bits to be read from the input bitstream at this state.
    pub num_bits: u64,
    /// The symbol emitted by the FSE table at this state.
    pub symbol: u64,
    /// During FSE table decoding, keep track of the number of symbol emitted
    pub num_emitted: u64,
    /// A boolean marker to indicate that as per the state transition rules of FSE codes, this
    /// state was reached for this symbol, however it was already pre-allocated to a prior symbol,
    /// this can happen in case we have symbols with prob=-1.
    pub is_state_skipped: bool,
}

// Used for tracking bit markers for non-byte-aligned bitstream decoding
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BitstreamReadRow {
    /// Start of the bit location within a byte [0, 8)
    pub bit_start_idx: usize,
    /// End of the bit location within a byte (0, 16)
    pub bit_end_idx: usize,
    /// The value of the bitstring
    pub bit_value: u64,
    /// Whether 0 bit is read
    pub is_zero_bit_read: bool,
    /// Indicator for when sequence data bitstream initial baselines are determined
    pub is_seq_init: bool,
    /// Idx of sequence instruction
    pub seq_idx: usize,
    /// The states (LLT, MLT, MOT) at this row
    pub states: [u64; 3],
    /// The symbols emitted at this state (LLT, MLT, MOT)
    pub symbols: [u64; 3],
    /// The values computed for literal length, match length and match offset.
    pub values: [u64; 3],
    /// The baseline value associated with this state.
    pub baseline: u64,
    /// Whether current byte is completely covered in a multi-byte packing scheme
    pub is_nil: bool,
    /// Indicate which exact state is the bitstring value is for
    /// 1. MOT Code to Value
    /// 2. MLT Code to Value
    /// 3. LLT Code to Value
    /// 4. LLT FSE update
    /// 5. MLT FSE update
    /// 6. MOT FSE update
    pub is_update_state: u64,
}

/// Sequence data is interleaved with 6 bitstreams. Each producing a different type of value.
#[derive(Clone, Copy, Debug)]
pub enum SequenceDataTag {
    LiteralLengthFse = 1,
    MatchLengthFse,
    CookedMatchOffsetFse,
    LiteralLengthValue,
    MatchLengthValue,
    CookedMatchOffsetValue,
}

/// A single row in the Address table.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AddressTableRow {
    /// Whether this row is padding for positional alignment with input
    pub s_padding: u64,
    /// Instruction Index
    pub instruction_idx: u64,
    /// Literal Length (directly decoded from sequence bitstream)
    pub literal_length: u64,
    /// Cooked Match Offset (directly decoded from sequence bitstream)
    pub cooked_match_offset: u64,
    /// Match Length (directly decoded from sequence bitstream)
    pub match_length: u64,
    /// Accumulation of literal length
    pub literal_length_acc: u64,
    /// Repeated offset 1
    pub repeated_offset1: u64,
    /// Repeated offset 2
    pub repeated_offset2: u64,
    /// Repeated offset 3
    pub repeated_offset3: u64,
    /// The actual match offset derived from cooked match offset
    pub actual_offset: u64,
}

impl AddressTableRow {
    /// a debug helper, input data in the form of example in
    /// zstd spec: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#repeat-offsets
    /// i.e. [offset, literal, rep_1, rep_2, rep_3]
    #[cfg(test)]
    pub fn mock_samples(samples: &[[u64; 5]]) -> Vec<Self> {
        Self::mock_samples_full(
            samples
                .iter()
                .map(|sample| [sample[0], sample[1], 0, sample[2], sample[3], sample[4]]),
        )
    }

    /// build row with args [offset, literal, match_len, rep_1, rep_2, rep_3]    
    #[cfg(test)]
    pub fn mock_samples_full(samples: impl IntoIterator<Item = [u64; 6]>) -> Vec<Self> {
        let mut ret = Vec::<Self>::new();

        for sample in samples {
            let mut new_item = Self {
                cooked_match_offset: sample[0],
                literal_length: sample[1],
                match_length: sample[2],
                repeated_offset1: sample[3],
                repeated_offset2: sample[4],
                repeated_offset3: sample[5],
                actual_offset: sample[3],
                ..Default::default()
            };

            if let Some(old_item) = ret.last() {
                new_item.instruction_idx = old_item.instruction_idx + 1;
                new_item.literal_length_acc = old_item.literal_length_acc + sample[1];
            } else {
                new_item.literal_length_acc = sample[1];
            }

            ret.push(new_item);
        }

        ret
    }
}

/// Data for BL and Number of Bits for a state in LLT, CMOT and MLT
#[derive(Clone, Debug)]
pub struct SequenceFixedStateActionTable {
    /// Represent the state, BL and NB
    pub states_to_actions: Vec<(u64, (u64, u64))>,
}

impl SequenceFixedStateActionTable {
    /// Reconstruct action state table for literal length recovery
    pub fn reconstruct_lltv() -> Self {
        let mut states_to_actions = vec![];

        for idx in 0..=15 {
            states_to_actions.push((idx as u64, (idx as u64, 0u64)))
        }

        let rows: Vec<(u64, u64, u64)> = vec![
            (16, 16, 1),
            (17, 18, 1),
            (18, 20, 1),
            (19, 22, 1),
            (20, 24, 2),
            (21, 28, 2),
            (22, 32, 3),
            (23, 40, 3),
            (24, 48, 4),
            (25, 64, 6),
            (26, 128, 7),
            (27, 256, 8),
            (28, 512, 9),
            (29, 1024, 10),
            (30, 2048, 11),
            (31, 4096, 12),
            (32, 8192, 13),
            (33, 16384, 14),
            (34, 32768, 15),
            (35, 65536, 16),
        ];

        for row in rows {
            states_to_actions.push((row.0, (row.1, row.2)));
        }

        Self { states_to_actions }
    }

    /// Reconstruct action state table for match length recovery
    pub fn reconstruct_mltv() -> Self {
        let mut states_to_actions = vec![];

        for idx in 0..=31 {
            states_to_actions.push((idx as u64, (idx as u64 + 3, 0u64)))
        }

        let rows: Vec<(u64, u64, u64)> = vec![
            (32, 35, 1),
            (33, 37, 1),
            (34, 39, 1),
            (35, 41, 1),
            (36, 43, 2),
            (37, 47, 2),
            (38, 51, 3),
            (39, 59, 3),
            (40, 67, 4),
            (41, 83, 4),
            (42, 99, 5),
            (43, 131, 7),
            (44, 259, 8),
            (45, 515, 9),
            (46, 1027, 10),
            (47, 2051, 11),
            (48, 4099, 12),
            (49, 8195, 13),
            (50, 16387, 14),
            (51, 32771, 15),
            (52, 65539, 16),
        ];

        for row in rows {
            states_to_actions.push((row.0, (row.1, row.2)));
        }

        Self { states_to_actions }
    }

    /// Reconstruct action state table for offset recovery
    pub fn reconstruct_cmotv(n: u64) -> Self {
        let mut states_to_actions = vec![];

        for idx in 0..=n {
            states_to_actions.push((idx, ((1 << idx) as u64, idx)))
        }

        Self { states_to_actions }
    }
}

/// Data for the FSE table's witness values.
#[derive(Clone, Debug)]
pub struct FseTableData {
    /// The byte offset in the frame at which the FSE table is described.
    pub byte_offset: u64,
    /// The FSE table's size, i.e. 1 << AL (accuracy log).
    pub table_size: u64,
    /// Represent the states, symbols, and so on of this FSE table.
    pub rows: Vec<FseTableRow>,
}

/// Auxiliary data accompanying the FSE table's witness values.
#[derive(Clone, Debug)]
pub struct FseAuxiliaryTableData {
    /// The block index in which this FSE table appears.
    pub block_idx: u64,
    /// Indicates whether the table is pre-defined.
    pub is_predefined: bool,
    /// The FSE table kind, variants are: LLT=1, MOT=2, MLT=3.
    pub table_kind: FseTableKind,
    /// The FSE table's size, i.e. 1 << AL (accuracy log).
    pub table_size: u64,
    /// Normalized probability,
    /// Used to indicate actual probability frequency of symbols, with 0 and -1 symbols present
    pub normalised_probs: BTreeMap<u64, i32>,
    /// A map from FseSymbol (weight) to states, also including fields for that state, for
    /// instance, the baseline and the number of bits to read from the FSE bitstream.
    ///
    /// For each symbol, the states as per the state transition rule.
    pub sym_to_states: BTreeMap<u64, Vec<FseTableRow>>,
    /// Similar map, but where the states for each symbol are in increasing order (sorted).
    pub sym_to_sorted_states: BTreeMap<u64, Vec<FseTableRow>>,
}

/// Another form of Fse table that has state as key instead of the FseSymbol.
/// In decoding, symbols are emitted from state-chaining.
/// This representation makes it easy to look up decoded symbol from current state.   
/// Map<state, (symbol, baseline, num_bits)>.
type FseStateMapping = BTreeMap<u64, (u64, u64, u64)>;
type ReconstructedFse = (usize, Vec<(u32, u64, u64)>, FseAuxiliaryTableData);

impl FseAuxiliaryTableData {
    /// While we reconstruct an FSE table from a bitstream, we do not know before reconstruction
    /// how many exact bytes we would finally be reading.
    ///
    /// The number of bytes actually read while reconstruction is called `t` and is returned along
    /// with the reconstructed FSE table. After processing the entire bitstream to reconstruct the
    /// FSE table, if the read bitstream was not byte aligned, then we discard the 1..8 bits from
    /// the last byte that we read from.
    #[allow(non_snake_case)]
    pub fn reconstruct(
        src: &[u8],
        block_idx: u64,
        table_kind: FseTableKind,
        byte_offset: usize,
        is_predefined: bool,
    ) -> std::io::Result<ReconstructedFse> {
        // construct little-endian bit-reader.
        let data = src.iter().skip(byte_offset).cloned().collect::<Vec<u8>>();
        let mut reader = BitReader::endian(Cursor::new(&data), LittleEndian);
        let mut bit_boundaries: Vec<(u32, u64, u64)> = vec![];

        ////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////// Parse Normalised Probabilities ////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        let mut normalised_probs = BTreeMap::new();
        let mut offset = 0;

        let (accuracy_log, table_size) = if is_predefined {
            let (predefined_frequencies, accuracy_log) = match table_kind {
                FseTableKind::LLT => (
                    vec![
                        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                        3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1,
                    ],
                    6,
                ),
                FseTableKind::MOT => (
                    vec![
                        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1,
                        -1, -1, -1, -1,
                    ],
                    5,
                ),
                FseTableKind::MLT => (
                    vec![
                        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1,
                        -1, -1, -1, -1,
                    ],
                    6,
                ),
            };
            for (symbol, freq) in predefined_frequencies.into_iter().enumerate() {
                normalised_probs.insert(symbol as u64, freq);
            }
            (accuracy_log, 1 << accuracy_log)
        } else {
            offset += 4;
            let accuracy_log = reader.read::<u8>(offset)? + 5;
            bit_boundaries.push((offset, accuracy_log as u64 - 5, accuracy_log as u64 - 5));
            let table_size = 1 << accuracy_log;
            let mut R = table_size;
            let mut symbol = 0;
            while R > 0 {
                // number of bits and value read from the variable bit-packed data.
                // And update the total number of bits read so far.
                let (n_bits_read, value_read, value_decoded) =
                    read_variable_bit_packing(&data, offset, R + 1)?;
                reader.skip(n_bits_read)?;
                offset += n_bits_read;
                bit_boundaries.push((offset, value_read, value_decoded));

                // Number of states allocated to this symbol.
                // - prob=-1 => 1
                // - prob=0  => 0
                // - prob>=1 => prob
                let N = match value_decoded {
                    0 => 1,
                    _ => value_decoded - 1,
                };

                // When a symbol has a value==0, it signifies a case of prob=-1 (or probability
                // "less than 1"), where such symbols are allocated states from the
                // end and retreating. In such cases, we reset the FSE state, i.e.
                // read accuracy_log number of bits from the bitstream with a
                // baseline==0x00.
                if value_decoded == 0 {
                    normalised_probs.insert(symbol, -1);
                    symbol += 1;
                }

                // When a symbol has a value==1 (prob==0), it is followed by a 2-bits repeat flag.
                // This repeat flag tells how many probabilities of zeroes follow
                // the current one. It provides a number ranging from 0 to 3. If it
                // is a 3, another 2-bits repeat flag follows, and so on.
                if value_decoded == 1 {
                    normalised_probs.insert(symbol, 0);
                    symbol += 1;
                    loop {
                        let repeat_bits = reader.read::<u8>(2)?;
                        offset += 2;
                        bit_boundaries.push((offset, repeat_bits as u64, repeat_bits as u64));

                        for k in 0..repeat_bits {
                            normalised_probs.insert(symbol + (k as u64), 0);
                        }
                        symbol += repeat_bits as u64;

                        if repeat_bits < 3 {
                            break;
                        }
                    }
                }

                // When a symbol has a value>1 (prob>=1), it is allocated that many number of states
                // in the FSE table.
                if value_decoded > 1 {
                    normalised_probs.insert(symbol, N as i32);
                    symbol += 1;
                }

                // remove N slots from a total of R.
                R -= N;
            }
            (accuracy_log, table_size)
        };

        // ignore any bits left to be read until byte-aligned.
        let t = if is_predefined {
            0
        } else {
            (((offset as usize) - 1) / N_BITS_PER_BYTE) + 1
        };

        // read the trailing section
        if t * N_BITS_PER_BYTE > (offset as usize) {
            let bits_remaining = t * N_BITS_PER_BYTE - offset as usize;
            let trailing_value = reader.read::<u8>(bits_remaining as u32)? as u64;
            bit_boundaries.push((
                offset + bits_remaining as u32,
                trailing_value,
                trailing_value,
            ));
        }

        // sanity check: sum(probabilities) == table_size.
        assert_eq!(
            normalised_probs
                .values()
                .map(|&prob| if prob == -1 { 1u64 } else { prob as u64 })
                .sum::<u64>(),
            table_size
        );

        ////////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////// Allocate States to Symbols ///////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        let (sym_to_states, sym_to_sorted_states) =
            Self::transform_normalised_probs(&normalised_probs, accuracy_log);

        Ok((
            t,
            if is_predefined {
                vec![]
            } else {
                bit_boundaries
            },
            Self {
                block_idx,
                is_predefined,
                table_kind,
                table_size,
                normalised_probs,
                sym_to_states,
                sym_to_sorted_states,
            },
        ))
    }

    #[allow(non_snake_case)]
    fn transform_normalised_probs(
        normalised_probs: &BTreeMap<u64, i32>,
        accuracy_log: u8,
    ) -> (
        BTreeMap<u64, Vec<FseTableRow>>,
        BTreeMap<u64, Vec<FseTableRow>>,
    ) {
        let table_size = 1 << accuracy_log;

        let mut sym_to_states = BTreeMap::new();
        let mut sym_to_sorted_states = BTreeMap::new();
        let mut state = 0;
        let mut retreating_state = table_size - 1;
        let mut allocated_states = HashMap::<u64, bool>::new();

        // We start with the symbols that have prob=-1.
        for (&symbol, _prob) in normalised_probs
            .iter()
            .filter(|(_symbol, &prob)| prob == -1)
        {
            allocated_states.insert(retreating_state, true);
            let fse_table_row = FseTableRow {
                state: retreating_state,
                num_bits: accuracy_log as u64,
                baseline: 0,
                symbol,
                is_state_skipped: false,
                num_emitted: 0,
            };
            sym_to_states.insert(symbol, vec![fse_table_row.clone()]);
            sym_to_sorted_states.insert(symbol, vec![fse_table_row]);
            retreating_state -= 1;
        }

        // We now move to the symbols with prob>=1.
        for (&symbol, &prob) in normalised_probs
            .iter()
            .filter(|(_symbol, &prob)| prob.is_positive())
        {
            let N = prob as usize;
            let mut count = 0;
            let mut states_with_skipped: Vec<(u64, bool)> = Vec::with_capacity(N);
            while count < N {
                if allocated_states.get(&state).is_some() {
                    // if state has been pre-allocated to some symbol with prob=-1.
                    states_with_skipped.push((state, true));
                } else {
                    // if state is not yet allocated, i.e. available for this symbol.
                    states_with_skipped.push((state, false));
                    count += 1;
                }

                // update state.
                state += (table_size >> 1) + (table_size >> 3) + 3;
                state &= table_size - 1;
            }
            let sorted_states = states_with_skipped
                .iter()
                .filter(|&(_s, is_state_skipped)| !is_state_skipped)
                .map(|&(s, _)| s)
                .sorted()
                .collect::<Vec<u64>>();
            let (smallest_spot_idx, nbs) = smaller_powers_of_two(table_size, N as u64);
            let baselines = if N == 1 {
                vec![0x00]
            } else {
                let mut rotated_nbs = nbs.clone();
                rotated_nbs.rotate_left(smallest_spot_idx);

                let mut baselines = std::iter::once(0x00)
                    .chain(rotated_nbs.iter().scan(0x00, |baseline, nb| {
                        *baseline += 1 << nb;
                        Some(*baseline)
                    }))
                    .take(N)
                    .collect::<Vec<u64>>();

                baselines.rotate_right(smallest_spot_idx);
                baselines
            };
            sym_to_states.insert(
                symbol,
                states_with_skipped
                    .iter()
                    .map(|&(s, is_state_skipped)| {
                        let (baseline, nb) = match sorted_states.iter().position(|&ss| ss == s) {
                            None => (0, 0),
                            Some(sorted_idx) => (baselines[sorted_idx], nbs[sorted_idx]),
                        };
                        FseTableRow {
                            state: s,
                            num_bits: nb,
                            baseline,
                            symbol,
                            num_emitted: 0,
                            is_state_skipped,
                        }
                    })
                    .collect(),
            );
            sym_to_sorted_states.insert(
                symbol,
                sorted_states
                    .iter()
                    .zip(nbs.iter())
                    .zip(baselines.iter())
                    .map(|((&s, &nb), &baseline)| FseTableRow {
                        state: s,
                        num_bits: nb,
                        baseline,
                        symbol,
                        num_emitted: 0,
                        is_state_skipped: false,
                    })
                    .collect(),
            );
        }

        (sym_to_states, sym_to_sorted_states)
    }

    /// Convert an FseAuxiliaryTableData into a state-mapped representation.
    /// This makes it easier to lookup state-chaining during decoding.
    pub fn parse_state_table(&self) -> FseStateMapping {
        let rows: Vec<FseTableRow> = self
            .sym_to_states
            .values()
            .flat_map(|v| v.clone())
            .collect();
        let mut state_table: FseStateMapping = BTreeMap::new();

        for row in rows {
            if !row.is_state_skipped {
                state_table.insert(row.state, (row.symbol, row.baseline, row.num_bits));
            }
        }

        state_table
    }
}

#[derive(Clone, Debug)]
/// Row witness value for decompression circuit
pub struct ZstdWitnessRow<F> {
    /// Current decoding state during Zstd decompression
    pub state: ZstdState<F>,
    /// Data on compressed data
    pub encoded_data: EncodedData<F>,
    /// Data on decompressed data
    pub decoded_data: DecodedData,
    /// Fse decoding state transition data
    pub fse_data: FseDecodingRow,
    /// Bitstream reader
    pub bitstream_read_data: BitstreamReadRow,
}

impl<F: Field> ZstdWitnessRow<F> {
    /// Construct the first row of witnesses for decompression circuit
    pub fn init(src_len: usize) -> Self {
        Self {
            state: ZstdState::default(),
            encoded_data: EncodedData {
                encoded_len: src_len as u64,
                ..Default::default()
            },
            decoded_data: DecodedData::default(),
            fse_data: FseDecodingRow::default(),
            bitstream_read_data: BitstreamReadRow::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregation::decoder::tables::{predefined_fse, PredefinedFse};

    use super::*;

    #[test]
    fn test_fse_reconstruction() -> std::io::Result<()> {
        // The first 3 bytes are garbage data and the offset == 3 passed to the function should
        // appropriately ignore those bytes. Only the next 4 bytes are meaningful and the FSE
        // reconstruction should read bitstreams only until the end of the 4th byte. The 3
        // other bytes are garbage (for the purpose of this test case), and we want to make
        // sure FSE reconstruction ignores them.
        let src = vec![0xff, 0xff, 0xff, 0x30, 0x6f, 0x9b, 0x03, 0xff, 0xff, 0xff];

        let (n_bytes, _bit_boundaries, table) =
            FseAuxiliaryTableData::reconstruct(&src, 1, FseTableKind::LLT, 3, false)?;

        // TODO: assert equality for the entire table.
        // for now only comparing state/baseline/nb for S1, i.e. weight == 1.

        assert_eq!(n_bytes, 4);
        assert_eq!(
            table.sym_to_sorted_states.get(&1).cloned().unwrap(),
            [
                (0x03, 0x10, 3),
                (0x0c, 0x18, 3),
                (0x11, 0x00, 2),
                (0x15, 0x04, 2),
                (0x1a, 0x08, 2),
                (0x1e, 0x0c, 2),
            ]
            .iter()
            .enumerate()
            .map(|(_i, &(state, baseline, num_bits))| FseTableRow {
                state,
                symbol: 1,
                baseline,
                num_bits,
                num_emitted: 0,
                is_state_skipped: false,
            })
            .collect::<Vec<FseTableRow>>(),
        );

        Ok(())
    }

    #[test]
    fn test_fse_reconstruction_predefined_tables() {
        // Here we test whether we can actually reconstruct the FSE table for distributions that
        // include prob=-1 cases, one such example is the Predefined FSE table as per
        // specifications.
        let default_distribution_llt = vec![
            4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1,
            1, 1, 1, -1, -1, -1, -1,
        ];
        let default_distribution_mlt = vec![
            1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
        ];
        let default_distribution_mot = vec![
            1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1,
            -1,
        ];

        for (table_kind, default_distribution) in [
            (FseTableKind::LLT, default_distribution_llt),
            (FseTableKind::MLT, default_distribution_mlt),
            (FseTableKind::MOT, default_distribution_mot),
        ] {
            let normalised_probs = {
                let mut normalised_probs = BTreeMap::new();
                for (i, &prob) in default_distribution.iter().enumerate() {
                    normalised_probs.insert(i as u64, prob);
                }
                normalised_probs
            };
            let (sym_to_states, _sym_to_sorted_states) =
                FseAuxiliaryTableData::transform_normalised_probs(
                    &normalised_probs,
                    table_kind.accuracy_log(),
                );
            let expected_predefined_table = predefined_fse(table_kind);

            let mut computed_predefined_table = sym_to_states
                .values()
                .flatten()
                .filter(|row| !row.is_state_skipped)
                .collect::<Vec<_>>();
            computed_predefined_table.sort_by_key(|row| row.state);

            for (i, (expected, computed)) in expected_predefined_table
                .iter()
                .zip_eq(computed_predefined_table.iter())
                .enumerate()
            {
                assert_eq!(computed.state, expected.state, "state mismatch at i={}", i);
                assert_eq!(
                    computed.symbol, expected.symbol,
                    "symbol mismatch at i={}",
                    i
                );
                assert_eq!(
                    computed.baseline, expected.baseline,
                    "baseline mismatch at i={}",
                    i
                );
                assert_eq!(computed.num_bits, expected.nb, "nb mismatch at i={}", i);
            }
        }
    }

    #[test]
    fn test_sequences_fse_reconstruction() -> std::io::Result<()> {
        let src = vec![
            0x21, 0x9d, 0x51, 0xcc, 0x18, 0x42, 0x44, 0x81, 0x8c, 0x94, 0xb4, 0x50, 0x1e,
        ];

        let (_n_bytes, _bit_boundaries, table) =
            FseAuxiliaryTableData::reconstruct(&src, 0, FseTableKind::LLT, 0, false)?;
        let parsed_state_map = table.parse_state_table();

        let mut expected_state_table = BTreeMap::new();

        let expected_state_table_states: [[u64; 4]; 64] = [
            [0, 0, 4, 2],
            [1, 0, 8, 2],
            [2, 0, 12, 2],
            [3, 0, 16, 2],
            [4, 0, 20, 2],
            [5, 0, 24, 2],
            [6, 1, 32, 4],
            [7, 1, 48, 4],
            [8, 2, 0, 5],
            [9, 3, 0, 4],
            [10, 4, 16, 4],
            [11, 4, 32, 4],
            [12, 6, 0, 5],
            [13, 8, 32, 5],
            [14, 9, 32, 5],
            [15, 10, 32, 5],
            [16, 12, 0, 6],
            [17, 14, 0, 6],
            [18, 15, 0, 4],
            [19, 17, 0, 6],
            [20, 20, 0, 6],
            [21, 24, 32, 5],
            [22, 0, 28, 2],
            [23, 0, 32, 2],
            [24, 0, 36, 2],
            [25, 0, 40, 2],
            [26, 0, 44, 2],
            [27, 1, 0, 3],
            [28, 1, 8, 3],
            [29, 2, 32, 5],
            [30, 3, 16, 4],
            [31, 4, 48, 4],
            [32, 4, 0, 3],
            [33, 5, 0, 5],
            [34, 7, 0, 6],
            [35, 8, 0, 4],
            [36, 9, 0, 4],
            [37, 10, 0, 4],
            [38, 13, 0, 5],
            [39, 15, 16, 4],
            [40, 16, 0, 6],
            [41, 18, 0, 5],
            [42, 24, 0, 4],
            [43, 0, 48, 2],
            [44, 0, 52, 2],
            [45, 0, 56, 2],
            [46, 0, 60, 2],
            [47, 0, 0, 1],
            [48, 0, 2, 1],
            [49, 1, 16, 3],
            [50, 1, 24, 3],
            [51, 3, 32, 4],
            [52, 3, 48, 4],
            [53, 4, 8, 3],
            [54, 5, 32, 5],
            [55, 6, 32, 5],
            [56, 8, 16, 4],
            [57, 9, 16, 4],
            [58, 10, 16, 4],
            [59, 13, 32, 5],
            [60, 15, 32, 4],
            [61, 15, 48, 4],
            [62, 18, 32, 5],
            [63, 24, 16, 4],
        ];

        for state in expected_state_table_states {
            expected_state_table.insert(state[0], (state[1], state[2], state[3]));
        }

        assert!(parsed_state_map == expected_state_table);

        Ok(())
    }
}
