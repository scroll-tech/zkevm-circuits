use std::{
    collections::{BTreeMap, HashMap},
    io::Cursor,
};

use bitstream_io::{write, BitRead, BitReader, LittleEndian};
use eth_types::Field;
use gadgets::impl_expr;
use halo2_proofs::{circuit::Value, plonk::Expression};
use itertools::Itertools;
use strum_macros::EnumIter;

use super::{
    params::N_BITS_PER_BYTE,
    util::{bit_length, read_variable_bit_packing, smaller_powers_of_two, value_bits_le},
};

// witgen_debug
use std::{io, io::Write};

/// A read-only memory table (fixed table) for decompression circuit to verify that the next tag
/// fields are assigned correctly.
#[derive(Clone, Debug)]
pub struct RomTagTableRow {
    /// The current tag.
    tag: ZstdTag,
    /// The tag that will be processed after the current tag is finished processing.
    tag_next: ZstdTag,
    /// The maximum number of bytes that are needed to represent the current tag.
    max_len: u64,
    /// Whether this tag outputs a decoded byte or not.
    is_output: bool,
    /// Whether this tag is processed from back-to-front or not.
    is_reverse: bool,
    /// Whether this tag belongs to a ``block`` in zstd or not.
    is_block: bool,
}

impl RomTagTableRow {
    pub(crate) fn rows() -> Vec<Self> {
        use ZstdTag::{
            BlockHeader, FrameContentSize, FrameHeaderDescriptor, ZstdBlockLiteralsHeader,
            ZstdBlockLiteralsRawBytes, ZstdBlockSequenceHeader,
        };

        [
            (FrameHeaderDescriptor, FrameContentSize, 1),
            (FrameContentSize, BlockHeader, 8),
            (BlockHeader, ZstdBlockLiteralsHeader, 3),
            (ZstdBlockLiteralsHeader, ZstdBlockLiteralsRawBytes, 5),
            (ZstdBlockLiteralsRawBytes, ZstdBlockSequenceHeader, 1048575), // (1 << 20) - 1
        ]
        .map(|(tag, tag_next, max_len)| Self {
            tag,
            tag_next,
            max_len,
            is_output: tag.is_output(),
            is_reverse: tag.is_reverse(),
            is_block: tag.is_block(),
        })
        .to_vec()
    }

    pub(crate) fn values<F: Field>(&self) -> Vec<Value<F>> {
        vec![
            Value::known(F::from(usize::from(self.tag) as u64)),
            Value::known(F::from(usize::from(self.tag_next) as u64)),
            Value::known(F::from(self.max_len)),
            Value::known(F::from(self.is_output as u64)),
            Value::known(F::from(self.is_reverse as u64)),
            Value::known(F::from(self.is_block as u64)),
        ]
    }
}

/// The symbol emitted by FSE table. This is also the weight in the canonical Huffman code.
#[derive(Clone, Copy, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord)]
pub enum FseSymbol {
    ///
    S0 = 0,
    ///
    S1,
    ///
    S2,
    ///
    S3,
    ///
    S4,
    ///
    S5,
    ///
    S6,
    ///
    S7,
}

impl_expr!(FseSymbol);

impl From<FseSymbol> for usize {
    fn from(value: FseSymbol) -> Self {
        value as usize
    }
}

impl From<FseSymbol> for u64 {
    fn from(value: FseSymbol) -> Self {
        value as u64
    }
}

impl From<usize> for FseSymbol {
    fn from(value: usize) -> Self {
        match value {
            0 => Self::S0,
            1 => Self::S1,
            2 => Self::S2,
            3 => Self::S3,
            4 => Self::S4,
            5 => Self::S5,
            6 => Self::S6,
            7 => Self::S7,
            _ => unreachable!("FseSymbol in [0, 8)"),
        }
    }
}

#[derive(Debug)]
pub enum BlockType {
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
    /// Null should not occur.
    Null = 0,
    /// The frame header's descriptor.
    FrameHeaderDescriptor,
    /// The frame's content size.
    FrameContentSize,
    /// The block's header.
    BlockHeader,
    /// Raw bytes.
    RawBlockBytes,
    /// Run-length encoded bytes.
    RleBlockBytes,
    /// Zstd block's literals header.
    ZstdBlockLiteralsHeader,
    /// Zstd blocks might contain raw bytes.
    ZstdBlockLiteralsRawBytes,
    /// Zstd blocks might contain rle bytes.
    ZstdBlockLiteralsRleBytes,
    /// Zstd block's huffman header and FSE code.
    ZstdBlockFseCode,
    /// Zstd block's huffman code.
    ZstdBlockHuffmanCode,
    /// Zstd block's jump table.
    ZstdBlockJumpTable,
    /// Literal stream.
    ZstdBlockLstream,
    /// Beginning of sequence section.
    ZstdBlockSequenceHeader,
    /// sequence bitstream for recovering instructions
    ZstdBlockSequenceData,
}

impl ZstdTag {
    /// Whether this tag produces an output or not.
    pub fn is_output(&self) -> bool {
        match self {
            Self::Null => false,
            Self::FrameHeaderDescriptor => false,
            Self::FrameContentSize => false,
            Self::BlockHeader => false,
            Self::RawBlockBytes => true,
            Self::RleBlockBytes => true,
            Self::ZstdBlockLiteralsHeader => false,
            Self::ZstdBlockLiteralsRawBytes => false,
            Self::ZstdBlockLiteralsRleBytes => false,
            Self::ZstdBlockFseCode => false,
            Self::ZstdBlockHuffmanCode => false,
            Self::ZstdBlockJumpTable => false,
            Self::ZstdBlockLstream => false,
            Self::ZstdBlockSequenceHeader => false,
            Self::ZstdBlockSequenceData => true,
        }
    }

    /// Whether this tag is a part of block or not.
    pub fn is_block(&self) -> bool {
        match self {
            Self::Null => false,
            Self::FrameHeaderDescriptor => false,
            Self::FrameContentSize => false,
            Self::BlockHeader => false,
            Self::RawBlockBytes => true,
            Self::RleBlockBytes => true,
            Self::ZstdBlockLiteralsHeader => true,
            Self::ZstdBlockLiteralsRawBytes => true,
            Self::ZstdBlockLiteralsRleBytes => true,
            Self::ZstdBlockFseCode => true,
            Self::ZstdBlockHuffmanCode => true,
            Self::ZstdBlockJumpTable => true,
            Self::ZstdBlockLstream => true,
            Self::ZstdBlockSequenceHeader => true,
            Self::ZstdBlockSequenceData => true,
        }
    }

    /// Whether this tag is processed in back-to-front order.
    pub fn is_reverse(&self) -> bool {
        match self {
            Self::Null => false,
            Self::FrameHeaderDescriptor => false,
            Self::FrameContentSize => true,
            Self::BlockHeader => true,
            Self::RawBlockBytes => false,
            Self::RleBlockBytes => false,
            Self::ZstdBlockLiteralsHeader => false,
            Self::ZstdBlockLiteralsRawBytes => false,
            Self::ZstdBlockLiteralsRleBytes => false,
            Self::ZstdBlockFseCode => false,
            Self::ZstdBlockHuffmanCode => true,
            Self::ZstdBlockJumpTable => false,
            Self::ZstdBlockLstream => true,
            Self::ZstdBlockSequenceHeader => false,
            Self::ZstdBlockSequenceData => true,
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
#[derive(Clone, Copy, Debug)]
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
            Self::RawBlockBytes => "RawBlockBytes",
            Self::RleBlockBytes => "RleBlockBytes",
            Self::ZstdBlockLiteralsHeader => "ZstdBlockLiteralsHeader",
            Self::ZstdBlockLiteralsRawBytes => "ZstdBlockLiteralsRawBytes",
            Self::ZstdBlockLiteralsRleBytes => "ZstdBlockLiteralsRleBytes",
            Self::ZstdBlockFseCode => "ZstdBlockFseCode",
            Self::ZstdBlockHuffmanCode => "ZstdBlockHuffmanCode",
            Self::ZstdBlockJumpTable => "ZstdBlockJumpTable",
            Self::ZstdBlockLstream => "ZstdBlockLstream",
            Self::ZstdBlockSequenceHeader => "ZstdBlockSequenceHeader",
            Self::ZstdBlockSequenceData => "ZstdBlockSequenceData",
        })
    }
}

#[derive(Clone, Debug)]
pub struct ZstdState<F> {
    pub tag: ZstdTag,
    pub tag_next: ZstdTag,
    pub max_tag_len: u64,
    pub tag_len: u64,
    pub tag_idx: u64,
    pub tag_value: Value<F>,
    pub tag_value_acc: Value<F>,
    pub is_tag_change: bool,
    // Unlike tag_value, tag_rlc only uses challenge as multiplier
    pub tag_rlc: Value<F>,
    pub tag_rlc_acc: Value<F>,
}

impl<F: Field> Default for ZstdState<F> {
    fn default() -> Self {
        Self {
            tag: ZstdTag::Null,
            tag_next: ZstdTag::FrameHeaderDescriptor,
            max_tag_len: 0,
            tag_len: 0,
            tag_idx: 0,
            tag_value: Value::known(F::zero()),
            tag_value_acc: Value::known(F::zero()),
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
    pub aux_1: Value<F>,
    pub aux_2: Value<F>,
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
            aux_1: Value::known(F::zero()),
            aux_2: Value::known(F::zero()),
            value_rlc: Value::known(F::zero()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DecodedData<F> {
    pub decoded_len: u64,
    pub decoded_len_acc: u64,
    pub total_decoded_len: u64,
    pub decoded_byte: u8,
    pub decoded_value_rlc: Value<F>,
}

#[derive(Clone, Debug, Default)]
pub struct HuffmanData {
    pub byte_offset: u64,
    pub bit_value: u8,
    pub stream_idx: usize,
    pub k: (u8, u8),
}

/// Witness to the HuffmanCodesTable.
#[derive(Clone, Debug)]
pub struct HuffmanCodesData {
    /// The byte offset in the frame at which the FSE table is described.
    pub byte_offset: u64,
    /// A mapping of symbol to the weight assigned to it as per canonical Huffman coding. The
    /// symbol is the raw byte that is encoded using a Huffman code and the weight assigned to it
    /// is a symbol emitted by the corresponding FSE table.
    pub weights: Vec<FseSymbol>,
}

/// Denotes the tuple (max_bitstring_len, Map<symbol, (weight, bit_value)>).
type ParsedCanonicalHuffmanCode = (u64, BTreeMap<u64, (u64, u64)>);
/// A representation indexed by bitstring (String) as key for decoding symbols specifically.
/// Huffman code decoding ensures prefix code, thus the explicit articulation of bitstring is
/// necessary.
type ParsedCanonicalHuffmanCodeBitstringMap = (u64, HashMap<String, u64>);

impl HuffmanCodesData {
    /// Reconstruct the bitstrings for each symbol based on the canonical Huffman code weights. The
    /// returned value is tuple of max bitstring length and a map from symbol to its weight and bit
    /// value.
    pub fn parse_canonical(&self) -> ParsedCanonicalHuffmanCode {
        let sum_weights: u64 = self
            .weights
            .iter()
            .map(|&weight| {
                let weight: usize = weight.into();
                if weight > 0 {
                    1 << (weight - 1)
                } else {
                    0
                }
            })
            .sum();

        // Calculate the last symbol's weight and append it.
        let max_bitstring_len = bit_length(sum_weights);
        let nearest_pow2 = 1 << max_bitstring_len;
        let last_weight = ((nearest_pow2 - sum_weights) as f64).log2() as u64;
        let weights = self
            .weights
            .iter()
            .map(|&weight| weight as u64)
            .chain(std::iter::once(last_weight))
            .collect::<Vec<u64>>();

        let mut sym_to_tuple = BTreeMap::new();
        let mut bit_value = 0;
        for l in (0..=max_bitstring_len).rev() {
            bit_value = (bit_value + 1) >> 1;
            weights
                .iter()
                .enumerate()
                .filter(|(_symbol, &weight)| max_bitstring_len - weight + 1 == l)
                .for_each(|(symbol, &weight)| {
                    sym_to_tuple.insert(symbol as u64, (weight, bit_value));
                    bit_value += 1;
                });
        }

        // populate symbols that don't occur in the Huffman code.
        weights
            .iter()
            .enumerate()
            .filter(|(_, &weight)| weight == 0)
            .for_each(|(sym, _)| {
                sym_to_tuple.insert(sym as u64, (0, 0));
            });

        (max_bitstring_len, sym_to_tuple)
    }

    /// parse bit string map
    pub fn parse_bitstring_map(&self) -> ParsedCanonicalHuffmanCodeBitstringMap {
        let mut weights: Vec<usize> = self.weights.iter().map(|w| *w as usize).collect();
        let sum_weights: usize = weights
            .iter()
            .filter_map(|&w| if w > 0 { Some(1 << (w - 1)) } else { None })
            .sum();

        let nearest_pow_2: usize = 1 << (sum_weights - 1).next_power_of_two().trailing_zeros();
        weights.push(f64::log2((nearest_pow_2 - sum_weights) as f64).ceil() as usize + 1);
        let max_number_of_bits = nearest_pow_2.trailing_zeros() as usize;
        let n = weights.len();

        let bitstring_length: Vec<usize> = weights
            .iter()
            .map(|&w| {
                if w != 0 {
                    max_number_of_bits - w + 1
                } else {
                    0
                }
            })
            .collect();

        let mut bitstring_map = HashMap::new();
        let mut cur_bit_value = 0;

        for bit_len in (1..=max_number_of_bits).rev() {
            cur_bit_value += 1;
            cur_bit_value >>= 1;

            for (sym, b_len) in bitstring_length.iter().enumerate().take(n) {
                if *b_len == bit_len {
                    bitstring_map.insert(
                        format!("{:0width$b}", cur_bit_value, width = bit_len),
                        sym as u64,
                    );
                    cur_bit_value += 1;
                }
            }
        }

        let max_bitstring_len = bitstring_map
            .keys()
            .map(|k| k.len())
            .max()
            .expect("Keys have maximum len");

        (max_bitstring_len as u64, bitstring_map)
    }
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
}

/// Sequence data is interleaved with 6 bitstreams. Each producing a different type of value.
#[derive(Clone, Copy, Debug)]
pub enum SequenceDataTag {
    NULL = 0,
    LiteralLength_FSE,
    MatchLength_FSE,
    CookedMatchOffset_FSE,
    LiteralLength_Value,
    MatchLength_Value,
    CookedMatchOffset_Value,
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
    pub fn reconstruct_cmotv(N: u64) -> Self {
        let mut states_to_actions = vec![];

        for idx in 0..=N {
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
    /// The FSE table kind, variants are: LLT=1, MOT=2, MLT=3.
    pub table_kind: FseTableKind,
    /// The FSE table's size, i.e. 1 << AL (accuracy log).
    pub table_size: u64,
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
type ReconstructedFse = (usize, Vec<(u32, u64)>, FseAuxiliaryTableData);

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
    ) -> std::io::Result<ReconstructedFse> {
        // construct little-endian bit-reader.
        let data = src.iter().skip(byte_offset).cloned().collect::<Vec<u8>>();
        let mut reader = BitReader::endian(Cursor::new(&data), LittleEndian);
        let mut bit_boundaries: Vec<(u32, u64)> = vec![];

        // number of bits read by the bit-reader from the bistream.
        let mut offset = 0;

        let accuracy_log = {
            offset += 4;
            reader.read::<u8>(offset)? + 5
        };
        bit_boundaries.push((offset, accuracy_log as u64 - 5));
        let table_size = 1 << accuracy_log;

        ////////////////////////////////////////////////////////////////////////////////////////
        //////////////////////////// Parse Normalised Probabilities ////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        let mut normalised_probs = BTreeMap::new();
        let mut R = table_size;
        let mut symbol = 0;
        while R > 0 {
            // number of bits and value read from the variable bit-packed data.
            // And update the total number of bits read so far.
            let (n_bits_read, value) = read_variable_bit_packing(&data, offset, R + 1)?;
            reader.skip(n_bits_read)?;
            offset += n_bits_read;
            bit_boundaries.push((offset, value));

            // Number of states allocated to this symbol.
            // - prob=-1 => 1
            // - prob=0  => 0
            // - prob>=1 => prob
            let N = match value {
                0 => 1,
                _ => value - 1,
            };

            // When a symbol has a value==0, it signifies a case of prob=-1 (or probability "less
            // than 1"), where such symbols are allocated states from the end and retreating. In
            // such cases, we reset the FSE state, i.e. read accuracy_log number of bits from the
            // bitstream with a baseline==0x00.
            if value == 0 {
                normalised_probs.insert(symbol, -1);
                symbol += 1;
            }

            // When a symbol has a value==1 (prob==0), it is followed by a 2-bits repeat flag. This
            // repeat flag tells how many probabilities of zeroes follow the current one. It
            // provides a number ranging from 0 to 3. If it is a 3, another 2-bits repeat flag
            // follows, and so on.
            if value == 1 {
                normalised_probs.insert(symbol, 0);
                symbol += 1;
                loop {
                    let repeat_bits = reader.read::<u8>(2)?;
                    offset += 2;
                    bit_boundaries.push((offset, repeat_bits as u64));

                    for k in 0..repeat_bits {
                        normalised_probs.insert(symbol + (k as u64), 0);
                    }
                    symbol += repeat_bits as u64;

                    if repeat_bits < 3 {
                        break;
                    }
                }
            }

            // When a symbol has a value>1 (prob>=1), it is allocated that many number of states in
            // the FSE table.
            if value > 1 {
                normalised_probs.insert(symbol, N as i32);
                symbol += 1;
            }

            // remove N slots from a total of R.
            R -= N;
        }

        // ignore any bits left to be read until byte-aligned.
        let t = (((offset as usize) - 1) / N_BITS_PER_BYTE) + 1;

        // read the trailing section
        if t * N_BITS_PER_BYTE > (offset as usize) {
            let bits_remaining = t * N_BITS_PER_BYTE - offset as usize;
            bit_boundaries.push((
                offset + bits_remaining as u32,
                reader.read::<u8>(bits_remaining as u32)? as u64,
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
            bit_boundaries,
            Self {
                block_idx,
                table_kind,
                table_size,
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
            state_table.insert(row.state, (row.symbol, row.baseline, row.num_bits));
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
    pub decoded_data: DecodedData<F>,
    /// Fse decoding state transition data
    pub fse_data: FseTableRow,
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
            fse_data: FseTableRow::default(),
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
            FseAuxiliaryTableData::reconstruct(&src, 1, FseTableKind::LLT, 3)?;

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
        //
        // short literalsLength_defaultDistribution[36] =
        // { 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
        //   2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
        //  -1,-1,-1,-1 };
        //
        // short matchLengths_defaultDistribution[53] =
        // { 1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
        //   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        //   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,-1,-1,
        //  -1,-1,-1,-1,-1 };
        //
        //  short offsetCodes_defaultDistribution[29] =
        // { 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
        //   1, 1, 1, 1, 1, 1, 1, 1,-1,-1,-1,-1,-1 };
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

        let (n_bytes, _bit_boundaries, table) =
            FseAuxiliaryTableData::reconstruct(&src, 1, FseTableKind::LLT, 0)?;
        let parsed_state_map = table.parse_state_table();

        // TODO: assertions

        Ok(())
    }

    #[test]
    fn test_huffman_bitstring_reconstruction() -> std::io::Result<()> {
        let weights = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 6, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 3, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            1, 2, 0, 0, 0, 2, 0, 1, 1, 1, 1, 1, 0, 0, 1, 2, 1, 0, 1, 1, 1, 2, 0, 0, 1, 1, 1, 1, 0,
            1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 5, 3, 3, 3, 6, 3, 2, 4, 4, 0, 1, 4, 4, 5, 5, 2, 0, 4, 4,
            5, 3, 1, 3, 1, 3,
        ]
        .into_iter()
        .map(FseSymbol::from)
        .collect::<Vec<FseSymbol>>();

        let huffman_codes_data = HuffmanCodesData {
            byte_offset: 0,
            weights,
        };

        let (max_bitstring_len, bitstring_map) = huffman_codes_data.parse_bitstring_map();

        let expected_bitstrings: [(&str, u64); 53] = [
            ("01001", 10),
            ("110", 32),
            ("00000000", 33),
            ("0001100", 39),
            ("001010", 44),
            ("0001101", 46),
            ("00000001", 50),
            ("00000010", 58),
            ("0001110", 59),
            ("0001111", 63),
            ("00000011", 65),
            ("00000100", 66),
            ("00000101", 67),
            ("00000110", 68),
            ("00000111", 69),
            ("00001000", 72),
            ("0010000", 73),
            ("00001001", 74),
            ("00001010", 76),
            ("00001011", 77),
            ("00001100", 78),
            ("0010001", 79),
            ("00001101", 82),
            ("00001110", 83),
            ("00001111", 84),
            ("00010000", 85),
            ("00010001", 87),
            ("00010010", 91),
            ("00010011", 93),
            ("1000", 97),
            ("001011", 98),
            ("001100", 99),
            ("001101", 100),
            ("111", 101),
            ("001110", 102),
            ("0010010", 103),
            ("01010", 104),
            ("01011", 105),
            ("00010100", 107),
            ("01100", 108),
            ("01101", 109),
            ("1001", 110),
            ("1010", 111),
            ("0010011", 112),
            ("01110", 114),
            ("01111", 115),
            ("1011", 116),
            ("001111", 117),
            ("00010101", 118),
            ("010000", 119),
            ("00010110", 120),
            ("010001", 121),
            ("00010111", 122),
        ];

        assert_eq!(max_bitstring_len, 8, "max bitstring len is 8");
        assert_eq!(
            expected_bitstrings.len(),
            bitstring_map.len(),
            "# of bitstring is the same"
        );
        for pair in expected_bitstrings {
            assert_eq!(
                *bitstring_map.get(pair.0).unwrap(),
                pair.1,
                "bitstring mapping is correct"
            );
        }

        Ok(())
    }
}
