
use std::collections::BTreeMap;

use eth_types::Field;
use halo2_proofs::circuit::Value;

use std::io::{Result, Read};
use bitstream_io::{
    read::{BitRead, BitReader},
    LittleEndian, BigEndian,
};

use super::util::{be_bits_to_value, increment_idx, le_bits_to_value, value_bits_le};
use super::fse;
use super::params::*;


/// the trait to define fse constants in seq decoding
pub trait SeqCode : {
    const SYMCOUNT: usize;
    fn base_line(sym: u8) -> u32;
    fn num_of_bits(sym: u8) -> u8;
}

/// fse symbol for literal length
pub struct CodeLiteralLen;
/// fse symbol for matching length
pub struct CodeMatchLen;
/// fse symbol for offset
pub struct CodeOffset<const N: usize>;

impl SeqCode for CodeLiteralLen {
    const SYMCOUNT: usize = 36;
    fn base_line(sym: u8) -> u32{
        const BASELINE_TBL : [u32; 36]= [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
            8192, 16384, 32768, 65536,
        ];
        BASELINE_TBL[sym as usize]
    }
    fn num_of_bits(sym: u8) -> u8{
        const BITS_TBL : [u8; 36] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
            13,14, 15, 16,
        ];
        BITS_TBL[sym as usize]
    }    
}

impl SeqCode for CodeMatchLen {
    const SYMCOUNT: usize = 53;
    fn base_line(sym: u8) -> u32{
        const BASELINE_TBL : [u32; 53]= [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
            35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
            4099, 8195, 16387, 32771, 65539,
        ];
        BASELINE_TBL[sym as usize]
    }
    fn num_of_bits(sym: u8) -> u8{
        const BITS_TBL : [u8; 53] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
            12, 13,14, 15, 16,
        ];
        BITS_TBL[sym as usize]
    }    
}

impl<const N: usize> SeqCode for CodeOffset<N> {
    const SYMCOUNT: usize = N+1;
    fn base_line(sym: u8) -> u32{
        1<< sym
    }
    fn num_of_bits(sym: u8) -> u8{
        sym
    }
}

/// the fse symbol template
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeSymbol<T> (u8, std::marker::PhantomData<T>);

fn collect_bits_to_code(bt: &mut impl Iterator<Item=bool>, bits: usize) -> u64 {
    let mut cache = [0u8;32];
    assert!(bits < 23, "never read more than 22 bits in OUR seq fse");
    for i in 0..bits {
        cache[i] = if bt.next().expect("never end while reading") {1} else {0};
    }
    be_bits_to_value(&cache[..bits])
}

impl<T> From<u8> for CodeSymbol<T> {
    fn from(value: u8) -> Self {
        Self(value, Default::default())
    }
}

impl<T> AsRef<u8> for CodeSymbol<T> {
    fn as_ref(&self) -> &u8 {
        &self.0
    }
}

impl<T: SeqCode> CodeSymbol<T> {
    pub fn num_of_bits(&self) -> u8{
        T::num_of_bits(self.0)
    }
    pub fn base_line(&self) -> u32{
        T::base_line(self.0)
    }
}

type CodeSymLiteralLen = CodeSymbol<CodeLiteralLen>;
type CodeSymMatchLen = CodeSymbol<CodeMatchLen>;
type CodeSymOffset<const N: usize> = CodeSymbol<CodeOffset<N>>;


/// the data help for building a row in parse circuit, re-use the
/// form of FSE to express the data for code parsing
/// notice the "state" field in FSETableRow express the value we get
pub type WitnessRow = fse::WitnessRow;

/// the processing detail for seq bitstream, include the offset and value being read
#[derive(Clone, Debug)]
pub struct CodeProcessing<T> {
    fse_processing: fse::FSESymbolProcessing,
    read_code: Option<T>,
    work_offset: usize,
    _mark: std::marker::PhantomData<T>,
}

type LiteralLenFSE = CodeProcessing<CodeSymLiteralLen>;
type MatchLenFSE = CodeProcessing<CodeSymMatchLen>;
type OffsetFSE = CodeProcessing<CodeSymOffset<CL_WINDOW_LIMIT>>;

impl LiteralLenFSE {

    /// the first state updating
    pub fn start<R: Read>(
        reader: &mut BitReader<R, BigEndian>,
        fse_table: &fse::FseAuxiliaryTableData,
        initial_offset: Option<usize>
    ) -> Result<(Self, fse::WitnessRow)>{
        let begin_offset = initial_offset.unwrap_or_default();
        Self::start_inner(reader, fse_table, begin_offset)
    }

    /// read the code value RIGHT AFTER match length is read
    pub fn read_value<R: Read>(
        &mut self, 
        reader: &mut BitReader<R, BigEndian>,
        ref_offset: &MatchLenFSE,
    ) -> Result<WitnessRow>{
        let updated_offset = ref_offset.work_offset;
        self.read_value_inner(reader, updated_offset)
    }

    /// update to next fse state RIGHT AFTER code has been read
    pub fn process_update<R: Read>(
        &mut self, 
        reader: &mut BitReader<R, BigEndian>,
    ) -> Result<fse::WitnessRow>{
        let updated_offset = self.work_offset;
        self.process_update_inner(reader, updated_offset)
    }
}

impl OffsetFSE {

    /// state updating followed by literal len
    pub fn start<R: Read>(
        reader: &mut BitReader<R, BigEndian>,
        fse_table: &fse::FseAuxiliaryTableData,
        ref_offset: &LiteralLenFSE,
    ) -> Result<(Self, fse::WitnessRow)>{
        let begin_offset = ref_offset.work_offset;
        Self::start_inner(reader, fse_table, begin_offset)
    }

    /// read the code value RIGHT AFTER staet is updated
    pub fn read_value<R: Read>(
        &mut self, 
        reader: &mut BitReader<R, BigEndian>,
    ) -> Result<WitnessRow>{
        let updated_offset = self.work_offset;
        self.read_value_inner(reader, updated_offset)
    }

    /// first time to reading the code RIGHT AFTER match length is started
    pub fn read_value_first<R: Read>(
        &mut self, 
        reader: &mut BitReader<R, BigEndian>,
        ref_offset: &MatchLenFSE,
    ) -> Result<WitnessRow>{
        let updated_offset = ref_offset.work_offset;
        self.read_value_inner(reader, updated_offset)
    }

    /// update to next fse state RIGHT AFTER code has been read
    pub fn process_update<R: Read>(
        &mut self, 
        reader: &mut BitReader<R, BigEndian>,
        ref_offset: &MatchLenFSE,
    ) -> Result<fse::WitnessRow>{
        let updated_offset = ref_offset.work_offset;
        self.process_update_inner(reader, updated_offset)
    }
}


impl MatchLenFSE {

    /// state updating followed by offset
    pub fn start<R: Read>(
        reader: &mut BitReader<R, BigEndian>,
        fse_table: &fse::FseAuxiliaryTableData,
        ref_offset: &OffsetFSE,
    ) -> Result<(Self, fse::WitnessRow)>{
        let begin_offset = ref_offset.work_offset;
        Self::start_inner(reader, fse_table, begin_offset)
    }

    /// read the code value RIGHT AFTER match length is read
    pub fn read_value<R: Read>(
        &mut self, 
        reader: &mut BitReader<R, BigEndian>,
        ref_offset: &OffsetFSE,
    ) -> Result<WitnessRow>{
        let updated_offset = ref_offset.work_offset;
        self.read_value_inner(reader, updated_offset)
    }

    /// update to next fse state RIGHT AFTER code has been read
    pub fn process_update<R: Read>(
        &mut self, 
        reader: &mut BitReader<R, BigEndian>,
        ref_offset: &LiteralLenFSE,
    ) -> Result<fse::WitnessRow>{
        let updated_offset = ref_offset.work_offset;
        self.process_update_inner(reader, updated_offset)
    }
}

impl<T: SeqCode> CodeProcessing<CodeSymbol<T>> {

    fn start_inner<R: Read>(
        reader: &mut BitReader<R, BigEndian>,        
        fse_table: &fse::FseAuxiliaryTableData,
        initial_offset: usize,
    ) -> Result<(Self, fse::WitnessRow)> {

        let mut out = Self {
            fse_processing: fse::FSESymbolProcessing::start(
                fse_table, Some(initial_offset)),
            read_code: None,
            work_offset: 0,
            _mark: Default::default(),
        };
        let wit = out.process_update_inner(reader, initial_offset)?;
        Ok((out, wit))
    }

    // parse for next fse state, also output the witness
    // of FSE part
    fn process_update_inner<R: Read>(
        &mut self, 
        reader: &mut BitReader<R, BigEndian>,
        updated_offset: usize,
    ) -> Result<fse::WitnessRow>{

        assert!(self.read_code.is_none(), "called twice before we have read the code value");

        let ret = self.fse_processing.process(reader, Some(updated_offset))?;
        self.read_code.replace({ret.0.symbol as u8}.into());
        self.work_offset = ret.2;

        Ok(ret)
    }

    // read the code value, and output the witness
    // panic if the fse is not updated before calling
    fn read_value_inner<R: Read>(
        &mut self, 
        reader: &mut BitReader<R, BigEndian>,
        updated_offset: usize,
    ) -> Result<WitnessRow>{
        let code = self.read_code.take().expect("never called twice before we have updated fse");
        let num_bits = code.num_of_bits();
        let baseline = code.base_line() as u64;
        let read_bit_val = reader.read::<u64>(num_bits as u32)?;

        self.work_offset = updated_offset + num_bits as usize;
        Ok((
            fse::FseTableRow{
                state: baseline + read_bit_val,
                baseline,
                num_bits: num_bits as u64,
                symbol: code.0 as u32,
            },
            updated_offset,
            self.work_offset,
        ))
    }

}


const LITERAL_LEN_TAG: u64 = 1;
const MATCH_LEN_TAG: u64 = 2;
const OFFSET_TAG: u64 = 3;

/// unified witness type
pub enum WitndessRowData {
    UpdatePhase(fse::WitnessRow),
    ReadingPhase(WitnessRow),
}

use WitndessRowData::*;

/// witness data for a parsed row
pub enum SeqWitnessRowData {
    LiteralLenRow(WitndessRowData),
    MatchLenRow(WitndessRowData),
    OffsetRow(WitndessRowData),
}

use SeqWitnessRowData::*;

impl SeqWitnessRowData {
    // TODO: build the better form for witness row
}

fn process_fse_context_decoding(
    // the end of slice must the beginning of (reversed) reading
    // for fse decoding
    src: &[u8],
    n_seqs: usize,
    (literal_len_fse_table, offset_fse_table, match_len_fse_table):
    &(fse::FseAuxiliaryTableData, fse::FseAuxiliaryTableData, fse::FseAuxiliaryTableData),
) -> Result<Vec<SeqWitnessRowData>> {

    assert_ne!(n_seqs, 0, "should not handle 0 seqs");

    // all the tuplies organized with literal_len, offset, match_len
    let mut states = (0u8, 0u8, 0u8);
    let mut bit_offsets = (0usize, 0usize, 0usize);

    // reverse the fse bytes
    let src : Vec<_> = src.iter().copied().rev().collect();

    // construct a bit-reader.
    let mut reader = BitReader::endian(src.as_slice(), BigEndian);
    let mut witness = vec![];

    // Exclude the leading zero section in the BEGINNING BYTE
    while !reader.read_bit().expect("can not end here") {
        bit_offsets.0+=1;
        assert!(bit_offsets.0 < 8, "leading 1 bit can not exceed first byte");
    }
    // TODO: add first witness row

    let (mut lit_processing, wit) = LiteralLenFSE::start(
        &mut reader,
        literal_len_fse_table,
        Some(bit_offsets.0),
    )?;
    witness.push(LiteralLenRow(UpdatePhase(wit)));    

    let (mut offset_processing, wit) = OffsetFSE::start(
        &mut reader,
        offset_fse_table,
        &lit_processing,
    )?;
    witness.push(OffsetRow(UpdatePhase(wit)));

    let (mut match_processing, wit) = MatchLenFSE::start(
        &mut reader,
        match_len_fse_table,
        &offset_processing,
    )?;
    witness.push(MatchLenRow(UpdatePhase(wit)));

    // TODO
    Ok(witness)

}

// use super::types::{ZstdTag::*, *};

// type HuffmanCodeProcessingResult<F> = (
//     usize,
//     Vec<ZstdWitnessRow<F>>,
//     HuffmanCodesData,
//     usize,
//     usize,
//     Value<F>,
//     usize,
//     u64,
//     u64,
//     u64,
//     FseAuxiliaryTableData,
// );


// const TAG_MAX_LEN: [(ZstdTag, u64); 13] = [
//     (FrameHeaderDescriptor, 1),
//     (FrameContentSize, 8),
//     (BlockHeader, 3),
//     (RawBlockBytes, 8388607), // (1 << 23) - 1
//     (RleBlockBytes, 8388607),
//     (ZstdBlockLiteralsHeader, 5),
//     (ZstdBlockLiteralsRawBytes, 1048575), // (1 << 20) - 1
//     (ZstdBlockLiteralsRleBytes, 1048575),
//     (ZstdBlockLiteralsHeader, 5),
//     (ZstdBlockFseCode, 128),
//     (ZstdBlockHuffmanCode, 128), // header_byte < 128
//     (ZstdBlockJumpTable, 6),
//     (ZstdBlockLstream, 1000), // 1kB hard-limit
// ];

// fn lookup_max_tag_len(tag: ZstdTag) -> u64 {
//     TAG_MAX_LEN.iter().find(|record| record.0 == tag).unwrap().1
// }

// fn process_block_zstd_huffman_code<F: Field>(
//     src: &[u8],
//     byte_offset: usize,
//     last_row: &ZstdWitnessRow<F>,
//     randomness: Value<F>,
//     n_streams: usize,
// ) -> HuffmanCodeProcessingResult<F> {
//     // Preserve this value for later construction of HuffmanCodesDataTable
//     let huffman_code_byte_offset = byte_offset;

//     // Other consistent values
//     let encoded_len = last_row.encoded_data.encoded_len;
//     let decoded_data = last_row.decoded_data.clone();

//     // Get the next tag
//     let tag_next = ZstdTag::ZstdBlockHuffmanCode;

//     // Parse the header byte
//     let mut witness_rows: Vec<ZstdWitnessRow<F>> = vec![];
//     let header_byte = src[byte_offset];
//     assert!(header_byte < 128, "FSE encoded huffman weights assumed");
//     let n_bytes = header_byte as usize;

//     let multiplier =
//         (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
//     let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

//     // Add a witness row for Huffman header
//     let mut huffman_header_row: ZstdWitnessRow<F> = ZstdWitnessRow {
//         state: ZstdState {
//             tag: ZstdTag::ZstdBlockFseCode,
//             tag_next,
//             max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockFseCode),
//             tag_len: 0_u64, /* There's no information at this point about the length of FSE
//                              * table bytes. So this value has to be modified later. */
//             tag_idx: 1_u64,
//             tag_value: Value::default(), // Must be changed after FSE table length is known
//             tag_value_acc: Value::default(), // Must be changed after FSE table length is known
//             is_tag_change: true,
//             tag_rlc: Value::known(F::zero()), // Must be changed after FSE table length is known
//             tag_rlc_acc: Value::known(F::zero()), // Must be changed after FSE table length is known
//         },
//         encoded_data: EncodedData {
//             byte_idx: (byte_offset + 1) as u64,
//             encoded_len,
//             value_byte: header_byte,
//             value_rlc,
//             reverse: false,
//             ..Default::default()
//         },
//         bitstream_read_data: BitstreamReadRow {
//             bit_start_idx: 0usize,
//             bit_end_idx: 7usize,
//             bit_value: header_byte as u64,
//             is_zero_bit_read: false,
//         },
//         decoded_data: decoded_data.clone(),
//         huffman_data: HuffmanData::default(),
//         fse_data: FseTableRow::default(),
//     };

//     // Recover the FSE table for generating Huffman weights
//     let (n_fse_bytes, bit_boundaries, table) =
//         FseAuxiliaryTableData::reconstruct(src, byte_offset + 1)
//             .expect("Reconstructing FSE table should not fail.");

//     // Witness generation
//     let accuracy_log = (src[byte_offset + 1] & 0b1111) + 5;

//     let mut tag_value_iter = src.iter().skip(byte_offset).take(n_fse_bytes + 1).scan(
//         Value::known(F::zero()),
//         |acc, &byte| {
//             *acc = *acc * randomness + Value::known(F::from(byte as u64));
//             Some(*acc)
//         },
//     );
//     let tag_value = tag_value_iter.clone().last().expect("Tag value must exist");

//     let mut tag_rlc_iter = src.iter().skip(byte_offset).take(n_fse_bytes + 1).scan(
//         Value::known(F::zero()),
//         |acc, &byte| {
//             *acc = *acc * randomness + Value::known(F::from(byte as u64));
//             Some(*acc)
//         },
//     );
//     let tag_rlc = tag_rlc_iter.clone().last().expect("Tag RLC must exist");

//     // Backfill missing data on the huffman header row
//     huffman_header_row.state.tag_len = (n_fse_bytes + 1usize) as u64;
//     huffman_header_row.state.tag_value = tag_value;
//     huffman_header_row.state.tag_value_acc =
//         tag_value_iter.next().expect("Next value should exist");
//     huffman_header_row.state.tag_rlc = tag_rlc;
//     huffman_header_row.state.tag_rlc_acc = tag_rlc_iter.next().expect("Next value expected");
//     witness_rows.push(huffman_header_row);

//     // Process bit boundaries into bitstream reader info
//     let mut decoded: u8 = 0;
//     let mut n_acc: usize = 0;
//     let mut current_tag_value_acc = Value::known(F::zero());
//     let mut current_tag_rlc_acc = Value::known(F::zero());
//     let mut last_byte_idx: i64 = 0;
//     let mut from_pos: (i64, i64) = (1, 0);
//     let mut to_pos: (i64, i64) = (0, 0);

//     let bitstream_rows = bit_boundaries
//         .iter()
//         .enumerate()
//         .map(|(sym, (bit_idx, value))| {
//             from_pos = if sym == 0 { (1, -1) } else { to_pos };

//             from_pos.1 += 1;
//             if from_pos.1 == 8 {
//                 from_pos = (from_pos.0 + 1, 0);
//             }
//             from_pos.1 = (from_pos.1 as u64).rem_euclid(8) as i64;

//             if from_pos.0 > last_byte_idx {
//                 current_tag_value_acc = tag_value_iter.next().unwrap();
//                 current_tag_rlc_acc = tag_rlc_iter.next().unwrap();
//                 last_byte_idx = from_pos.0;
//             }

//             let to_byte_idx = (bit_idx - 1) / 8;
//             let mut to_bit_idx = bit_idx - to_byte_idx * (N_BITS_PER_BYTE as u32) - 1;

//             if from_pos.0 < (to_byte_idx + 1) as i64 {
//                 to_bit_idx += 8;
//             }

//             to_pos = ((to_byte_idx + 1) as i64, to_bit_idx as i64);

//             if sym > 0 && n_acc < (1 << accuracy_log) {
//                 decoded = (sym - 1) as u8;
//                 n_acc += (*value - 1) as usize;
//             }

//             (
//                 decoded,
//                 from_pos.0 as usize,
//                 from_pos.1 as usize,
//                 to_pos.0 as usize,
//                 to_pos.1 as usize,
//                 *value,
//                 current_tag_value_acc,
//                 current_tag_rlc_acc,
//                 0,
//                 n_acc,
//             )
//         })
//         .collect::<Vec<(
//             u8,
//             usize,
//             usize,
//             usize,
//             usize,
//             u64,
//             Value<F>,
//             Value<F>,
//             usize,
//             usize,
//         )>>();

//     // Add witness rows for FSE representation bytes
//     for row in bitstream_rows {
//         witness_rows.push(ZstdWitnessRow {
//             state: ZstdState {
//                 tag: ZstdTag::ZstdBlockFseCode,
//                 tag_next,
//                 max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockFseCode),
//                 tag_len: (n_fse_bytes + 1) as u64,
//                 tag_idx: (row.1 + 1) as u64, // count the huffman header byte
//                 tag_value,
//                 tag_value_acc: row.6,
//                 is_tag_change: false,
//                 tag_rlc,
//                 tag_rlc_acc: row.7,
//             },
//             encoded_data: EncodedData {
//                 byte_idx: (byte_offset + row.1 + 1) as u64, // count the huffman header byte
//                 encoded_len,
//                 value_byte: src[byte_offset + row.1],
//                 value_rlc,
//                 reverse: false,
//                 ..Default::default()
//             },
//             bitstream_read_data: BitstreamReadRow {
//                 bit_start_idx: row.2,
//                 bit_end_idx: row.4,
//                 bit_value: row.5,
//                 is_zero_bit_read: false,
//             },
//             decoded_data: DecodedData {
//                 decoded_len: last_row.decoded_data.decoded_len,
//                 decoded_len_acc: last_row.decoded_data.decoded_len_acc,
//                 total_decoded_len: last_row.decoded_data.total_decoded_len,
//                 decoded_byte: row.0,
//                 decoded_value_rlc: last_row.decoded_data.decoded_value_rlc,
//             },
//             huffman_data: HuffmanData::default(),
//             fse_data: FseTableRow {
//                 idx: 0,
//                 state: 0,
//                 symbol: 0,
//                 baseline: 0,
//                 num_bits: 0,
//                 num_emitted: 0,
//                 n_acc: row.9 as u64,
//             },
//         });
//     }

//     // Now start decoding the huffman weights using the actual Huffman code section
//     let tag_next = if n_streams > 1 {
//         ZstdTag::ZstdBlockJumpTable
//     } else {
//         ZstdTag::ZstdBlockLstream
//     };

//     // Update the last row
//     let last_row = witness_rows.last().expect("Last row exists");
//     let multiplier =
//         (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
//     let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

//     // Bitstream processing state values
//     let mut num_emitted: usize = 0;
//     let n_huffman_code_bytes = n_bytes - n_fse_bytes;
//     let mut last_byte_idx: usize = 1;
//     let mut current_byte_idx: usize = 1; // byte_idx is 1-indexed
//     let mut current_bit_idx: usize = 0;

//     // Construct the Huffman bitstream
//     let huffman_bitstream = src
//         .iter()
//         .skip(byte_offset + n_fse_bytes + 1)
//         .take(n_huffman_code_bytes)
//         .rev()
//         .clone()
//         .flat_map(|v| {
//             let mut bits = value_bits_le(*v);
//             bits.reverse();
//             bits
//         })
//         .collect::<Vec<u8>>();

//     // Accumulators for Huffman code section
//     let mut value_rlc_iter = src
//         .iter()
//         .skip(byte_offset + n_fse_bytes + 1)
//         .take(n_huffman_code_bytes)
//         .scan(Value::known(F::zero()), |acc, &byte| {
//             *acc = *acc * randomness + Value::known(F::from(byte as u64));
//             Some(*acc)
//         })
//         .collect::<Vec<Value<F>>>()
//         .into_iter()
//         .rev();
//     let mut tag_value_iter = src
//         .iter()
//         .skip(byte_offset + n_fse_bytes + 1)
//         .take(n_huffman_code_bytes)
//         .rev()
//         .scan(Value::known(F::zero()), |acc, &byte| {
//             *acc = *acc * randomness + Value::known(F::from(byte as u64));
//             Some(*acc)
//         });
//     let tag_value = tag_value_iter.clone().last().expect("Tag value must exist");
//     let tag_rlc_iter = src
//         .iter()
//         .skip(byte_offset + n_fse_bytes + 1)
//         .take(n_huffman_code_bytes)
//         .scan(Value::known(F::zero()), |acc, &byte| {
//             *acc = *acc * randomness + Value::known(F::from(byte as u64));
//             Some(*acc)
//         });
//     let tag_rlc = tag_rlc_iter.clone().last().expect("Tag RLC must exist");
//     let mut tag_rlc_iter = tag_rlc_iter.collect::<Vec<Value<F>>>().into_iter().rev();

//     let mut next_tag_value_acc = tag_value_iter.next().unwrap();
//     let next_value_rlc_acc = value_rlc_iter.next().unwrap();
//     let mut next_tag_rlc_acc = tag_rlc_iter.next().unwrap();

//     let aux_1 = next_value_rlc_acc;
//     let aux_2 = witness_rows[witness_rows.len() - 1].encoded_data.value_rlc;

//     let mut padding_end_idx: usize = 0;
//     while huffman_bitstream[padding_end_idx] == 0 {
//         padding_end_idx += 1;
//     }

//     // Add a witness row for leading 0s and the sentinel 1-bit
//     witness_rows.push(ZstdWitnessRow {
//         state: ZstdState {
//             tag: ZstdTag::ZstdBlockHuffmanCode,
//             tag_next,
//             max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockHuffmanCode),
//             tag_len: n_huffman_code_bytes as u64,
//             tag_idx: 1_u64,
//             tag_value,
//             tag_value_acc: next_tag_value_acc,
//             is_tag_change: true,
//             tag_rlc,
//             tag_rlc_acc: next_tag_rlc_acc,
//         },
//         encoded_data: EncodedData {
//             byte_idx: (byte_offset + n_fse_bytes + 1 + current_byte_idx) as u64,
//             encoded_len,
//             value_byte: src
//                 [byte_offset + n_fse_bytes + 1 + n_huffman_code_bytes - current_byte_idx],
//             value_rlc,
//             reverse: true,
//             reverse_len: n_huffman_code_bytes as u64,
//             reverse_idx: (n_huffman_code_bytes - (current_byte_idx - 1)) as u64,
//             aux_1,
//             aux_2,
//         },
//         bitstream_read_data: BitstreamReadRow {
//             bit_value: 1u64,
//             bit_start_idx: 0usize,
//             bit_end_idx: padding_end_idx,
//             is_zero_bit_read: false,
//         },
//         huffman_data: HuffmanData::default(),
//         decoded_data: last_row.decoded_data.clone(),
//         fse_data: FseTableRow::default(),
//     });

//     // Exclude the leading zero section
//     while huffman_bitstream[current_bit_idx] == 0 {
//         (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
//     }
//     // Exclude the sentinel 1-bit
//     (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);

//     // Update accumulator
//     if current_byte_idx > last_byte_idx {
//         next_tag_value_acc = tag_value_iter.next().unwrap();
//         next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
//         last_byte_idx = current_byte_idx;
//     }

//     // Now the actual weight-bearing bitstream starts
//     // The Huffman bitstream is decoded by two interleaved states reading the stream in alternating
//     // order. The FSE table for the two independent decoding strands are the same.
//     let mut color: usize = 0; // use 0, 1 (colors) to denote two alternating decoding strands.
//     let mut prev_baseline: [u64; 2] = [0, 0];
//     let mut next_nb_to_read: [usize; 2] = [accuracy_log as usize, accuracy_log as usize];
//     let mut decoded_weights: Vec<u8> = vec![];
//     let mut fse_table_idx: u64 = 1;

//     // Convert FSE auxiliary data into a state-indexed representation
//     let fse_state_table = table.clone().parse_state_table();

//     while current_bit_idx + next_nb_to_read[color] <= (n_huffman_code_bytes) * N_BITS_PER_BYTE {
//         let nb = next_nb_to_read[color];
//         let bitstring_value =
//             be_bits_to_value(&huffman_bitstream[current_bit_idx..(current_bit_idx + nb)]);
//         let next_state = prev_baseline[color] + bitstring_value;

//         let from_bit_idx = current_bit_idx.rem_euclid(8);
//         let to_bit_idx = if nb > 0 {
//             from_bit_idx + (nb - 1)
//         } else {
//             from_bit_idx
//         };

//         // Lookup the FSE table row for the state
//         let fse_row = fse_state_table
//             .get(&{ next_state })
//             .expect("next state should be in fse table");

//         // Decode the symbol
//         decoded_weights.push(fse_row.0 as u8);
//         num_emitted += 1;

//         // Add a witness row
//         witness_rows.push(ZstdWitnessRow {
//             state: ZstdState {
//                 tag: ZstdTag::ZstdBlockHuffmanCode,
//                 tag_next,
//                 max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockHuffmanCode),
//                 tag_len: (n_huffman_code_bytes) as u64,
//                 tag_idx: current_byte_idx as u64,
//                 tag_value,
//                 tag_value_acc: next_tag_value_acc,
//                 is_tag_change: false,
//                 tag_rlc,
//                 tag_rlc_acc: next_tag_rlc_acc,
//             },
//             encoded_data: EncodedData {
//                 byte_idx: (byte_offset + n_fse_bytes + 1 + current_byte_idx) as u64,
//                 encoded_len,
//                 value_byte: src
//                     [byte_offset + n_fse_bytes + 1 + n_huffman_code_bytes - current_byte_idx],
//                 value_rlc,
//                 reverse: true,
//                 reverse_len: n_huffman_code_bytes as u64,
//                 reverse_idx: (n_huffman_code_bytes - (current_byte_idx - 1)) as u64,
//                 aux_1,
//                 aux_2,
//             },
//             bitstream_read_data: BitstreamReadRow {
//                 bit_value: bitstring_value,
//                 bit_start_idx: from_bit_idx,
//                 bit_end_idx: to_bit_idx,
//                 is_zero_bit_read: (nb == 0),
//             },
//             fse_data: FseTableRow {
//                 idx: fse_table_idx,
//                 state: next_state,
//                 symbol: fse_row.0,
//                 baseline: fse_row.1,
//                 num_bits: fse_row.2,
//                 num_emitted: num_emitted as u64,
//                 n_acc: 0,
//             },
//             huffman_data: HuffmanData::default(),
//             decoded_data: decoded_data.clone(),
//         });

//         // increment fse idx
//         fse_table_idx += 1;

//         // Advance byte and bit marks. Get next acc value if byte changes
//         for _ in 0..nb {
//             (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
//         }
//         if current_byte_idx > last_byte_idx && current_byte_idx <= n_huffman_code_bytes {
//             next_tag_value_acc = tag_value_iter.next().unwrap();
//             next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
//             last_byte_idx = current_byte_idx;
//         }

//         // Preparing for next state
//         prev_baseline[color] = fse_row.1;
//         next_nb_to_read[color] = fse_row.2 as usize;

//         color = if color > 0 { 0 } else { 1 };
//     }

//     // Construct HuffmanCodesTable
//     let huffman_codes = HuffmanCodesData {
//         byte_offset: (huffman_code_byte_offset + 1) as u64,
//         weights: decoded_weights
//             .into_iter()
//             .map(|w| super::types::FseSymbol::from(w as usize))
//             .collect(),
//     };

//     // rlc after a reverse section
//     let mul =
//         (0..(n_huffman_code_bytes - 1)).fold(Value::known(F::one()), |acc, _| acc * randomness);
//     let new_value_rlc_init_value = aux_2 * mul + aux_1;

//     (
//         byte_offset + 1 + n_fse_bytes + n_huffman_code_bytes,
//         witness_rows,
//         huffman_codes,
//         n_bytes,
//         huffman_code_byte_offset + 1,
//         new_value_rlc_init_value,
//         byte_offset + 1,
//         (1 << accuracy_log) as u64,
//         accuracy_log as u64,
//         n_huffman_code_bytes as u64,
//         table, // FSE table
//     )
// }

// fn process_block_zstd_huffman_jump_table<F: Field>(
//     src: &[u8],
//     byte_offset: usize,
//     last_row: &ZstdWitnessRow<F>,
//     literal_stream_size: usize,
//     n_streams: usize,
//     randomness: Value<F>,
//     last_rlc: Value<F>,
// ) -> (usize, Vec<ZstdWitnessRow<F>>, Vec<u64>) {
//     if n_streams <= 1 {
//         (byte_offset, vec![], vec![literal_stream_size as u64])
//     } else {
//         // Note: The decompressed size of each stream is equal to (regen_size + 3) / 4
//         // but the compressed bitstream length will be different.
//         // Jump table provides information on the length of first 3 bitstreams.

//         let jt_bytes = src
//             .iter()
//             .skip(byte_offset)
//             .take(N_JUMP_TABLE_BYTES)
//             .cloned()
//             .map(|x| x as u64)
//             .collect::<Vec<u64>>();

//         let l1: u64 = jt_bytes[0] + jt_bytes[1] * 256;
//         let l2: u64 = jt_bytes[2] + jt_bytes[3] * 256;
//         let l3: u64 = jt_bytes[4] + jt_bytes[5] * 256;
//         let l4: u64 = (literal_stream_size as u64) - l1 - l2 - l3;

//         let value_rlc_iter =
//             src.iter()
//                 .skip(byte_offset)
//                 .take(N_JUMP_TABLE_BYTES)
//                 .scan(last_rlc, |acc, &byte| {
//                     *acc = *acc * randomness + Value::known(F::from(byte as u64));
//                     Some(*acc)
//                 });
//         let multiplier =
//             (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
//         let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

//         let tag_value_iter = src.iter().skip(byte_offset).take(N_JUMP_TABLE_BYTES).scan(
//             Value::known(F::zero()),
//             |acc, &byte| {
//                 *acc = *acc * Value::known(F::from(256u64)) + Value::known(F::from(byte as u64));
//                 Some(*acc)
//             },
//         );
//         let tag_value = tag_value_iter
//             .clone()
//             .last()
//             .expect("Tag value must exist.");
//         let tag_rlc_iter = src.iter().skip(byte_offset).take(N_JUMP_TABLE_BYTES).scan(
//             Value::known(F::zero()),
//             |acc, &byte| {
//                 *acc = *acc * randomness + Value::known(F::from(byte as u64));
//                 Some(*acc)
//             },
//         );
//         let tag_rlc = tag_rlc_iter.clone().last().expect("Tag value must exist.");

//         (
//             byte_offset + N_JUMP_TABLE_BYTES,
//             src.iter()
//                 .skip(byte_offset)
//                 .take(N_JUMP_TABLE_BYTES)
//                 .zip(tag_value_iter)
//                 .zip(value_rlc_iter)
//                 .zip(tag_rlc_iter)
//                 .enumerate()
//                 .map(
//                     |(i, (((&value_byte, tag_value_acc), _v_rlc), tag_rlc_acc))| ZstdWitnessRow {
//                         state: ZstdState {
//                             tag: ZstdTag::ZstdBlockJumpTable,
//                             tag_next: ZstdTag::ZstdBlockLstream,
//                             max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockJumpTable),
//                             tag_len: N_JUMP_TABLE_BYTES as u64,
//                             tag_idx: (i + 1) as u64,
//                             tag_value,
//                             tag_value_acc,
//                             is_tag_change: i == 0,
//                             tag_rlc,
//                             tag_rlc_acc,
//                         },
//                         encoded_data: EncodedData {
//                             byte_idx: (byte_offset + i + 1) as u64,
//                             encoded_len: last_row.encoded_data.encoded_len,
//                             value_byte,
//                             value_rlc,
//                             reverse: false,
//                             ..Default::default()
//                         },
//                         bitstream_read_data: BitstreamReadRow {
//                             bit_start_idx: 0,
//                             bit_end_idx: 7,
//                             bit_value: value_byte as u64,
//                             is_zero_bit_read: false,
//                         },
//                         decoded_data: last_row.decoded_data.clone(),
//                         huffman_data: HuffmanData::default(),
//                         fse_data: FseTableRow::default(),
//                     },
//                 )
//                 .collect::<Vec<_>>(),
//             vec![l1, l2, l3, l4],
//         )
//     }
// }
