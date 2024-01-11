use std::collections::BTreeMap;

use eth_types::Field;
use gadgets::impl_expr;
use halo2_proofs::{circuit::Value, plonk::Expression};
use strum_macros::EnumIter;

use super::{params::N_BITS_PER_BYTE, util::value_bits_le};

/// The symbol emitted by FSE table. This is also the weight in the canonical Huffman code.
#[derive(Clone, Copy, Debug, EnumIter)]
pub enum FseSymbol {
    /// Weight == 0.
    S0 = 0,
    /// Weight == 1.
    S1,
    /// Weight == 2.
    S2,
    /// Weight == 3.
    S3,
    /// Weight == 4.
    S4,
    /// Weight == 5.
    S5,
    /// Weight == 6.
    S6,
    /// Weight == 7.
    S7,
}

impl_expr!(FseSymbol);

impl From<FseSymbol> for usize {
    fn from(value: FseSymbol) -> Self {
        value as usize
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

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum ZstdTag {
    Null = 0,
    MagicNumber,
    FrameHeaderDescriptor,
    FrameContentSize,
    BlockHeader,
    RawBlockBytes,
    RleBlockBytes,
    ZstdBlockLiteralsHeader,
    ZstdBlockLiteralsRawBytes,
    ZstdBlockLiteralsRleBytes,
    ZstdBlockHuffmanHeader,
    ZstdBlockHuffmanCode,
    ZstdBlockJumpTable,
    Lstream1,
    Lstream2,
    Lstream3,
    Lstream4,
}

impl ToString for ZstdTag {
    fn to_string(&self) -> String {
        String::from(match self {
            Self::Null => "null",
            Self::MagicNumber => "MagicNumber",
            Self::FrameHeaderDescriptor => "FrameHeaderDescriptor",
            Self::FrameContentSize => "FrameContentSize",
            Self::BlockHeader => "BlockHeader",
            Self::RawBlockBytes => "RawBlockBytes",
            Self::RleBlockBytes => "RleBlockBytes",
            Self::ZstdBlockLiteralsHeader => "ZstdBlockLiteralsHeader",
            Self::ZstdBlockLiteralsRawBytes => "ZstdBlockLiteralsRawBytes",
            Self::ZstdBlockLiteralsRleBytes => "ZstdBlockLiteralsRleBytes",
            Self::ZstdBlockHuffmanHeader => "ZstdBlockHuffmanHeader",
            Self::ZstdBlockHuffmanCode => "ZstdBlockHuffmanCode",
            Self::ZstdBlockJumpTable => "ZstdBlockJumpTable",
            Self::Lstream1 => "Lstream1",
            Self::Lstream2 => "Lstream2",
            Self::Lstream3 => "Lstream3",
            Self::Lstream4 => "Lstream4",
        })
    }
}

#[derive(Clone, Debug)]
pub struct ZstdState<F> {
    pub tag: ZstdTag,
    pub tag_next: ZstdTag,
    pub tag_len: u64,
    pub tag_idx: u64,
    pub tag_value: Value<F>,
    pub tag_value_acc: Value<F>,
}

impl<F: Field> Default for ZstdState<F> {
    fn default() -> Self {
        Self {
            tag: ZstdTag::Null,
            tag_next: ZstdTag::MagicNumber,
            tag_len: 0,
            tag_idx: 0,
            tag_value: Value::known(F::zero()),
            tag_value_acc: Value::known(F::zero()),
        }
    }
}

#[derive(Clone, Debug, Default)]
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
    pub k: (u8, u8),
}

/// Witness to the HuffmanCodesTable.
#[derive(Clone, Debug)]
pub struct HuffmanCodesData {
    /// The instance ID assigned to the data we are encoding using zstd.
    pub instance_idx: u64,
    /// The frame ID we are currently decoding.
    pub frame_idx: u64,
    /// The byte offset in the frame at which the FSE table is described.
    pub byte_offset: u64,
    /// A mapping of symbol to the weight assigned to it as per canonical Huffman coding. The
    /// symbol is the raw byte that is encoded using a Huffman code and the weight assigned to it
    /// is a symbol emitted by the corresponding FSE table.
    pub weights: Vec<FseSymbol>,
}

/// Denotes the tuple (max_bitstring_len, Map<symbol, (weight, bit_value)>).
type ParsedCanonicalHuffmanCode = (u64, BTreeMap<u64, (u64, u64)>);

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

        // Helper function to get the number of bits needed to represent a u32 value in binary
        // form.
        let bit_length = |value: u64| -> u64 {
            if value == 0 {
                0
            } else {
                64 - value.leading_zeros() as u64
            }
        };

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
}

/// Witness to the FseTable.
#[derive(Clone, Debug, Default)]
pub struct FseData {
    /// Incremental index, starting at 1.
    pub idx: u64,
    /// The FSE state at this row in the FSE table.
    pub state: u8,
    /// The baseline associated with this state.
    pub baseline: u8,
    /// The number of bits to be read from the input bitstream at this state.
    pub num_bits: u8,
    /// The symbol emitted by the FSE table at this state.
    pub symbol: u8,
}

/// Auxiliary data accompanying the FSE table's witness values.
#[derive(Clone, Debug)]
pub struct FseAuxiliaryData {
    /// The instance ID assigned to the data we are encoding using zstd.
    pub instance_idx: u64,
    /// The frame ID we are currently decoding.
    pub frame_idx: u64,
    /// The byte offset in the frame at which the FSE table is described.
    pub byte_offset: u64,
    /// The FSE table's size, i.e. 1 << AL (accuracy log).
    pub table_size: u64,
    /// The data representing the states, symbols, and so on of this FSE table.
    pub data: Vec<FseData>,
}

#[derive(Clone, Debug)]
pub struct ZstdWitnessRow<F> {
    pub instance_idx: u64,
    pub frame_idx: u64,
    pub state: ZstdState<F>,
    pub encoded_data: EncodedData<F>,
    pub decoded_data: DecodedData<F>,
    pub huffman_data: HuffmanData,
    pub fse_data: FseData,
}

impl<F: Field> ZstdWitnessRow<F> {
    pub fn init(src_len: usize) -> Self {
        Self {
            instance_idx: 1,
            frame_idx: 0,
            state: ZstdState::default(),
            encoded_data: EncodedData {
                encoded_len: src_len as u64,
                ..Default::default()
            },
            decoded_data: DecodedData::default(),
            huffman_data: HuffmanData::default(),
            fse_data: FseData::default(),
        }
    }
}
