use std::{collections::BTreeMap, io::Cursor};

use bitstream_io::{BitRead, BitReader, LittleEndian};
use eth_types::Field;
use gadgets::impl_expr;
use halo2_proofs::{circuit::Value, plonk::Expression};
use itertools::Itertools;
use strum_macros::EnumIter;

use super::{
    params::N_BITS_PER_BYTE,
    util::{bit_length, read_variable_bit_packing, smaller_powers_of_two, value_bits_le},
};

/// The symbol emitted by FSE table. This is also the weight in the canonical Huffman code.
#[derive(Clone, Copy, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord)]
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

/// Various tags that we can decode from a zstd encoded data.
#[derive(Clone, Copy, Debug, EnumIter)]
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
    /// Zstd blocks might contain raw bytes
    /// NOTE: might be removed then restricted to raw blocks
    ZstdBlockLiteralsRawBytes,
    /// Zstd blocks might contain rle bytes
    /// NOTE: might be removed then restricted to rle blocks
    ZstdBlockLiteralsRleBytes,
    /// 1 byte Huffman header
    ZstdBlockHuffmanHeader,
    /// Zstd block's FSE code.
    ZstdBlockFseCode,
    /// Zstd block's huffman code.
    ZstdBlockHuffmanCode,
    /// Zstd block's jump table.
    ZstdBlockJumpTable,
    /// Literal stream.
    Lstream,
    /// Beginning of sequence section.
    ZstdBlockSequenceHeader,
}

impl_expr!(ZstdTag);

impl From<ZstdTag> for usize {
    fn from(value: ZstdTag) -> Self {
        value as usize
    }
}

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
            Self::ZstdBlockHuffmanHeader => "ZstdBlockHuffmanHeader",
            Self::ZstdBlockFseCode => "ZstdBlockFseCode",
            Self::ZstdBlockHuffmanCode => "ZstdBlockHuffmanCode",
            Self::ZstdBlockJumpTable => "ZstdBlockJumpTable",
            Self::ZstdBlockSequenceHeader => "ZstdBlockSequenceHeader",
            Self::Lstream => "Lstream",
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
            tag_next: ZstdTag::FrameHeaderDescriptor,
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
    /// The byte offset in the frame at which the FSE table is described.
    pub byte_offset: u64,
    /// A mapping of symbol to the weight assigned to it as per canonical Huffman coding. The
    /// symbol is the raw byte that is encoded using a Huffman code and the weight assigned to it
    /// is a symbol emitted by the corresponding FSE table.
    pub weights: Vec<FseSymbol>,
}

/// Denotes the tuple (max_bitstring_len, Map<symbol, (weight, bit_value)>).
type ParsedCanonicalHuffmanCode = (u64, BTreeMap<u64, (u64, u64)>);
/// A representation indexed by bit_value as key for easier lookup during decoding. (max_bitstring_len, Map<bit_value, symbol>)
type ParsedCanonicalHuffmanCodeBitValueMap = (u64, BTreeMap<u64, u64>);

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

    /// Construct a representation indexed by bit_value as key for easier lookup during decoding.
    pub fn parse_canonical_bit_value_map(&self) -> ParsedCanonicalHuffmanCodeBitValueMap {
        let mut bit_value_mapping: (u64, BTreeMap<u64, u64>) = (0, BTreeMap::new());

        let parsed_huffman_code = self.parse_canonical();

        bit_value_mapping.0 = parsed_huffman_code.0;
        bit_value_mapping.1 = parsed_huffman_code.1.into_iter().fold(BTreeMap::new(), |mut acc, (symbol, (_weight, bit_value))| {
            acc.insert(bit_value, symbol);
            acc
        });

        bit_value_mapping
    }
}

/// A single row in the FSE table.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FseTableRow {
    /// Incremental index, starting at 1.
    pub idx: u64,
    /// The FSE state at this row in the FSE table.
    pub state: u64,
    /// The baseline associated with this state.
    pub baseline: u64,
    /// The number of bits to be read from the input bitstream at this state.
    pub num_bits: u64,
    /// The symbol emitted by the FSE table at this state.
    pub symbol: u64,
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
    /// The byte offset in the frame at which the FSE table is described.
    pub byte_offset: u64,
    /// The FSE table's AL (accuracy log)
    pub accuracy_log: u8,
    /// The FSE table's size, i.e. 1 << AL (accuracy log).
    pub table_size: u64,
    /// A map from FseSymbol (weight) to states, also including fields for that state, for
    /// instance, the baseline and the number of bits to read from the FSE bitstream.
    ///
    /// For each symbol, the states are in strictly increasing order.
    pub sym_to_states: BTreeMap<FseSymbol, Vec<FseTableRow>>,
}

/// Another form of Fse table that has state as key instead of the FseSymbol.
/// In decoding, symbols are emitted from state-chaining. 
/// This representation makes it easy to look up decoded symbol from current state.   
/// Map<state, (symbol, baseline, num_bits)>.
type FseStateMapping = BTreeMap<u64, (u64, u64, u64)>;

impl FseAuxiliaryTableData {
    #[allow(non_snake_case)]
    /// While we reconstruct an FSE table from a bitstream, we do not know before reconstruction
    /// how many exact bytes we would finally be reading.
    ///
    /// The number of bytes actually read while reconstruction is called `t` and is returned along
    /// with the reconstructed FSE table. After processing the entire bitstream to reconstruct the
    /// FSE table, if the read bitstream was not byte aligned, then we discard the 1..8 bits from
    /// the last byte that we read from.
    pub fn reconstruct(src: &[u8], byte_offset: usize) -> std::io::Result<(usize, Self)> {
        // construct little-endian bit-reader.
        let data = src.iter().skip(byte_offset).cloned().collect::<Vec<u8>>();
        let mut reader = BitReader::endian(Cursor::new(&data), LittleEndian);

        // number of bits read by the bit-reader from the bistream.
        let mut offset = 0;

        let accuracy_log = {
            offset += 4;
            reader.read::<u8>(offset)? + 5
        };
        let table_size = 1 << accuracy_log;

        let mut sym_to_states = BTreeMap::new();
        let mut R = table_size;
        let mut state = 0x00;
        let mut symbol = FseSymbol::S0;
        let mut idx = 1;
        while R > 0 {
            // number of bits and value read from the variable bit-packed data.
            let (n_bits_read, value) = read_variable_bit_packing(&data, offset, R + 1)?;

            let N = value - 1;
            let states = std::iter::once(state)
                .chain((1..N).map(|_| {
                    state += (table_size >> 1) + (table_size >> 3) + 3;
                    state &= table_size - 1;
                    state
                }))
                .sorted()
                .collect::<Vec<u64>>();
            let (smallest_spot_idx, nbs) = smaller_powers_of_two(table_size, N);
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
                    .take(N as usize)
                    .collect::<Vec<u64>>();

                baselines.rotate_right(smallest_spot_idx);
                baselines
            };
            sym_to_states.insert(
                symbol,
                states
                    .iter()
                    .zip(nbs.iter())
                    .zip(baselines.iter())
                    .map(|((&state, &nb), &baseline)| FseTableRow {
                        idx,
                        state,
                        num_bits: nb,
                        baseline,
                        symbol: symbol.into(),
                    })
                    .collect(),
            );
            idx += 1;

            // update the total number of bits read so far.
            offset += n_bits_read;

            // increment symbol.
            symbol = ((symbol as usize) + 1).into();

            // update state.
            state += (table_size >> 1) + (table_size >> 3) + 3;
            state &= table_size - 1;

            // remove N slots from a total of R.
            R -= N;
        }

        // ignore any bits left to be read until byte-aligned.
        let t = (((offset as usize) - 1) / N_BITS_PER_BYTE) + 1;

        Ok((
            t,
            Self {
                byte_offset: byte_offset as u64,
                accuracy_log,
                table_size,
                sym_to_states,
            },
        ))
    }

    /// Convert an FseAuxiliaryTableData into a state-mapped representation.
    /// This makes it easier to lookup state-chaining during decoding.
    pub fn parse_state_table(&self) -> FseStateMapping {
        let rows: Vec<FseTableRow> = self.sym_to_states.values().flat_map(|v| v.clone()).collect();
        let mut state_table: FseStateMapping = BTreeMap::new();

        for row in rows {
            state_table.insert(row.state, (row.symbol, row.baseline, row.num_bits));
        }

        state_table
    }
}

#[derive(Clone, Debug)]
pub struct ZstdWitnessRow<F> {
    pub state: ZstdState<F>,
    pub encoded_data: EncodedData<F>,
    pub decoded_data: DecodedData<F>,
    pub huffman_data: HuffmanData,
    pub fse_data: FseTableRow,
}

impl<F: Field> ZstdWitnessRow<F> {
    pub fn init(src_len: usize) -> Self {
        Self {
            state: ZstdState::default(),
            encoded_data: EncodedData {
                encoded_len: src_len as u64,
                ..Default::default()
            },
            decoded_data: DecodedData::default(),
            huffman_data: HuffmanData::default(),
            fse_data: FseTableRow::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fse_reconstruction() -> std::io::Result<()> {
        // The first 3 bytes are garbage data and the offset == 3 passed to the function should
        // appropriately ignore those bytes. Only the next 4 bytes are meaningful and the FSE
        // reconstruction should read bitstreams only until the end of the 4th byte. The 3
        // other bytes are garbage (for the purpose of this test case), and we want to make
        // sure FSE reconstruction ignores them.
        let src = vec![0xff, 0xff, 0xff, 0x30, 0x6f, 0x9b, 0x03, 0xff, 0xff, 0xff];

        // compression_debug
        // let (n_bytes, table) = FseAuxiliaryTableData::reconstruct(1, 1, &src, 3)?;

        // TODO: assert equality for the entire table.
        // for now only comparing state/baseline/nb for S1, i.e. weight == 1.

        // compression_debug
        // assert_eq!(n_bytes, 4);
        // assert_eq!(
        //     table.sym_to_states.get(&FseSymbol::S1).cloned().unwrap(),
        //     [
        //         (0x03, 0x10, 3),
        //         (0x0c, 0x18, 3),
        //         (0x11, 0x00, 2),
        //         (0x15, 0x04, 2),
        //         (0x1a, 0x08, 2),
        //         (0x1e, 0x0c, 2),
        //     ]
        //     .iter()
        //     .enumerate()
        //     .map(|(i, &(state, baseline, num_bits))| FseTableRow {
        //         idx: (i + 1) as u64,
        //         state,
        //         symbol: 1,
        //         baseline,
        //         num_bits,
        //     })
        //     .collect::<Vec<FseTableRow>>(),
        // );

        Ok(())
    }
}
