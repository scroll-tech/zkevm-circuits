use gadgets::Field;
use halo2_proofs::circuit::Value;
use revm_precompile::HashMap;

mod params;
pub use params::*;

mod types;
pub use types::*;

pub mod util;
use util::{be_bits_to_value, increment_idx, le_bits_to_value, value_bits_le};

const CMOT_N: u64 = 31;

/// FrameHeaderDescriptor and FrameContentSize
fn process_frame_header<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
) -> (usize, Vec<ZstdWitnessRow<F>>) {
    let fhd_byte = src
        .get(byte_offset)
        .expect("FrameHeaderDescriptor byte should exist");
    let value_bits = value_bits_le(*fhd_byte);

    assert_eq!(value_bits[0], 0, "dictionary ID should not exist");
    assert_eq!(value_bits[1], 0, "dictionary ID should not exist");
    assert_eq!(value_bits[2], 0, "content checksum should not exist");
    assert_eq!(value_bits[3], 0, "reserved bit should not be set");
    assert_eq!(value_bits[4], 0, "unused bit should not be set");
    assert_eq!(value_bits[5], 1, "single segment expected");

    let fhd_value_rlc =
        last_row.encoded_data.value_rlc * randomness + Value::known(F::from(*fhd_byte as u64));

    // the number of bytes taken to represent FrameContentSize.
    let fcs_tag_len: usize = match value_bits[7] * 2 + value_bits[6] {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!("2-bit value"),
    };

    let fcs_bytes = src
        .iter()
        .skip(byte_offset + 1)
        .take(fcs_tag_len)
        .cloned()
        .collect::<Vec<u8>>();
    let fcs = {
        let fcs = fcs_bytes
            .iter()
            .rev()
            .fold(0u64, |acc, &byte| acc * 256u64 + (byte as u64));
        match fcs_tag_len {
            2 => fcs + 256,
            _ => fcs,
        }
    };

    let tag_rlc_iter = fcs_bytes
        .iter()
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        })
        .collect::<Vec<Value<F>>>();
    let tag_rlc = *(tag_rlc_iter.clone().last().expect("Tag RLC expected"));

    (
        byte_offset + 1 + fcs_tag_len,
        std::iter::once(ZstdWitnessRow {
            state: ZstdState {
                tag: ZstdTag::FrameHeaderDescriptor,
                tag_next: ZstdTag::FrameContentSize,
                max_tag_len: ZstdTag::FrameHeaderDescriptor.max_len(),
                block_idx: 0,
                tag_len: 1,
                tag_idx: 1,
                is_tag_change: true,
                tag_rlc: Value::known(F::from(*fhd_byte as u64)),
                tag_rlc_acc: Value::known(F::from(*fhd_byte as u64)),
            },
            encoded_data: EncodedData {
                byte_idx: (byte_offset + 1) as u64,
                encoded_len: last_row.encoded_data.encoded_len,
                value_byte: *fhd_byte,
                value_rlc: Value::known(F::zero()),
                ..Default::default()
            },
            decoded_data: DecodedData { decoded_len: fcs },
            bitstream_read_data: BitstreamReadRow::default(),
            fse_data: FseDecodingRow::default(),
        })
        .chain(fcs_bytes.iter().zip(tag_rlc_iter.iter()).enumerate().map(
            |(i, (&value_byte, &tag_rlc_acc))| ZstdWitnessRow {
                state: ZstdState {
                    tag: ZstdTag::FrameContentSize,
                    tag_next: ZstdTag::BlockHeader,
                    block_idx: 0,
                    max_tag_len: ZstdTag::FrameContentSize.max_len(),
                    tag_len: fcs_tag_len as u64,
                    tag_idx: (i + 1) as u64,
                    is_tag_change: i == 0,
                    tag_rlc,
                    tag_rlc_acc,
                },
                encoded_data: EncodedData {
                    byte_idx: (byte_offset + 2 + i) as u64,
                    encoded_len: last_row.encoded_data.encoded_len,
                    value_byte,
                    reverse: false,
                    reverse_idx: (fcs_tag_len - i) as u64,
                    reverse_len: fcs_tag_len as u64,
                    value_rlc: fhd_value_rlc,
                },
                decoded_data: DecodedData { decoded_len: fcs },
                bitstream_read_data: BitstreamReadRow::default(),
                fse_data: FseDecodingRow::default(),
            },
        ))
        .collect::<Vec<_>>(),
    )
}

#[derive(Debug, Clone)]
pub struct AggregateBlockResult<F> {
    pub offset: usize,
    pub witness_rows: Vec<ZstdWitnessRow<F>>,
    pub block_info: BlockInfo,
    pub sequence_info: SequenceInfo,
    pub literal_bytes: Vec<u64>,
    pub fse_aux_tables: [FseAuxiliaryTableData; 3], // 3 sequence section FSE tables
    pub address_table_rows: Vec<AddressTableRow>,
    pub sequence_exec_result: SequenceExecResult,
    pub repeated_offset: [usize; 3], // repeated offsets are carried forward between blocks.
}

fn process_block<F: Field>(
    src: &[u8],
    decoded_bytes: &mut Vec<u8>,
    block_idx: u64,
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    repeated_offset: [usize; 3],
) -> AggregateBlockResult<F> {
    let mut witness_rows = vec![];

    let (byte_offset, rows, mut block_info) =
        process_block_header(src, block_idx, byte_offset, last_row, randomness);
    witness_rows.extend_from_slice(&rows);

    let last_row = rows.last().expect("last row expected to exist");

    let BlockProcessingResult {
        offset: end_offset,
        witness_rows: rows,
        literals,
        sequence_info,
        fse_aux_tables,
        address_table_rows,
        sequence_exec_result,
        repeated_offset,
        regen_size,
    } = match block_info.block_type {
        BlockType::ZstdCompressedBlock => process_block_zstd(
            src,
            decoded_bytes,
            block_idx,
            byte_offset,
            last_row,
            randomness,
            block_info.block_len,
            block_info.is_last_block,
            repeated_offset,
        ),
        _ => unreachable!("BlockType::ZstdCompressedBlock expected"),
    };
    block_info.regen_size = regen_size;
    witness_rows.extend_from_slice(&rows);

    AggregateBlockResult {
        offset: end_offset,
        witness_rows,
        block_info,
        sequence_info,
        literal_bytes: literals,
        fse_aux_tables,
        address_table_rows,
        sequence_exec_result,
        repeated_offset,
    }
}

fn process_block_header<F: Field>(
    src: &[u8],
    block_idx: u64,
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
) -> (usize, Vec<ZstdWitnessRow<F>>, BlockInfo) {
    let mut block_info = BlockInfo {
        block_idx: block_idx as usize,
        ..Default::default()
    };
    let bh_bytes = src
        .iter()
        .skip(byte_offset)
        .take(N_BLOCK_HEADER_BYTES)
        .cloned()
        .collect::<Vec<u8>>();
    block_info.is_last_block = (bh_bytes[0] & 1) == 1;
    block_info.block_type = BlockType::from((bh_bytes[0] >> 1) & 3);
    block_info.block_len =
        (bh_bytes[2] as usize * 256 * 256 + bh_bytes[1] as usize * 256 + bh_bytes[0] as usize) >> 3;

    let tag_next = match block_info.block_type {
        BlockType::ZstdCompressedBlock => ZstdTag::ZstdBlockLiteralsHeader,
        _ => unreachable!("BlockType::ZstdCompressedBlock expected"),
    };

    let tag_rlc_iter = bh_bytes
        .iter()
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        })
        .collect::<Vec<Value<F>>>();
    let tag_rlc = *(tag_rlc_iter.clone().last().expect("Tag RLC expected"));

    let multiplier =
        (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
    let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

    (
        byte_offset + N_BLOCK_HEADER_BYTES,
        bh_bytes
            .iter()
            .zip(tag_rlc_iter.iter())
            .enumerate()
            .map(|(i, (&value_byte, tag_rlc_acc))| ZstdWitnessRow {
                state: ZstdState {
                    tag: ZstdTag::BlockHeader,
                    tag_next,
                    block_idx,
                    max_tag_len: ZstdTag::BlockHeader.max_len(),
                    tag_len: N_BLOCK_HEADER_BYTES as u64,
                    tag_idx: (i + 1) as u64,
                    is_tag_change: i == 0,
                    tag_rlc,
                    tag_rlc_acc: *tag_rlc_acc,
                },
                encoded_data: EncodedData {
                    byte_idx: (byte_offset + i + 1) as u64,
                    encoded_len: last_row.encoded_data.encoded_len,
                    value_byte,
                    reverse: false,
                    value_rlc,
                    ..Default::default()
                },
                bitstream_read_data: BitstreamReadRow::default(),
                decoded_data: last_row.decoded_data.clone(),
                fse_data: FseDecodingRow::default(),
            })
            .collect::<Vec<_>>(),
        block_info,
    )
}

#[derive(Debug, Default, Clone)]
pub struct SequenceExecResult {
    pub exec_trace: Vec<SequenceExec>,
    pub recovered_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BlockProcessingResult<F> {
    pub offset: usize,
    pub witness_rows: Vec<ZstdWitnessRow<F>>,
    pub literals: Vec<u64>,
    pub sequence_info: SequenceInfo,
    pub fse_aux_tables: [FseAuxiliaryTableData; 3], // 3 sequence section FSE tables
    pub address_table_rows: Vec<AddressTableRow>,
    pub sequence_exec_result: SequenceExecResult,
    pub repeated_offset: [usize; 3], // repeated offsets are carried forward between blocks
    pub regen_size: u64,
}

#[derive(Debug, Clone)]
pub struct LiteralsBlockResult<F> {
    pub offset: usize,
    pub witness_rows: Vec<ZstdWitnessRow<F>>,
    pub literals: Vec<u64>,
    pub regen_size: usize,
}

#[allow(clippy::too_many_arguments)]
fn process_block_zstd<F: Field>(
    src: &[u8],
    decoded_bytes: &mut Vec<u8>,
    block_idx: u64,
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    block_size: usize,
    last_block: bool,
    repeated_offset: [usize; 3],
) -> BlockProcessingResult<F> {
    let expected_end_offset = byte_offset + block_size;
    let mut witness_rows = vec![];

    // 1-5 bytes LiteralSectionHeader
    let LiteralsHeaderProcessingResult {
        offset: byte_offset,
        witness_rows: rows,
        regen_size,
        compressed_size: _,
    } = process_block_zstd_literals_header::<F>(src, block_idx, byte_offset, last_row, randomness);

    witness_rows.extend_from_slice(&rows);

    let LiteralsBlockResult {
        offset: byte_offset,
        witness_rows: rows,
        literals,
        regen_size: _,
    } = {
        let last_row = rows.last().cloned().unwrap();
        let multiplier =
            (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
        let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;
        let tag = ZstdTag::ZstdBlockLiteralsRawBytes;
        let tag_next = ZstdTag::ZstdBlockSequenceHeader;
        let literals = src[byte_offset..(byte_offset + regen_size)].to_vec();
        let tag_rlc_iter = literals.iter().scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        });
        let tag_rlc = tag_rlc_iter.clone().last().expect("Literals must exist.");

        LiteralsBlockResult {
            offset: byte_offset + regen_size,
            witness_rows: literals
                .iter()
                .zip(tag_rlc_iter)
                .enumerate()
                .map(|(i, (&value_byte, tag_rlc_acc))| ZstdWitnessRow {
                    state: ZstdState {
                        tag,
                        tag_next,
                        block_idx,
                        max_tag_len: tag.max_len(),
                        tag_len: regen_size as u64,
                        tag_idx: (i + 1) as u64,
                        is_tag_change: i == 0,
                        tag_rlc,
                        tag_rlc_acc,
                    },
                    encoded_data: EncodedData {
                        byte_idx: (byte_offset + i + 1) as u64,
                        encoded_len: last_row.encoded_data.encoded_len,
                        value_byte,
                        value_rlc,
                        reverse: false,
                        ..Default::default()
                    },
                    decoded_data: DecodedData {
                        decoded_len: last_row.decoded_data.decoded_len,
                    },
                    bitstream_read_data: BitstreamReadRow::default(),
                    fse_data: FseDecodingRow::default(),
                })
                .collect::<Vec<_>>(),
            literals: literals.iter().map(|b| *b as u64).collect::<Vec<u64>>(),
            regen_size,
        }
    };

    witness_rows.extend_from_slice(&rows);

    let last_row = witness_rows.last().expect("last row expected to exist");

    let SequencesProcessingResult {
        offset,
        witness_rows: rows,
        fse_aux_tables,
        address_table_rows,
        original_bytes,
        sequence_info,
        sequence_exec,
        repeated_offset,
    } = process_sequences::<F>(
        src,
        decoded_bytes,
        block_idx,
        byte_offset,
        expected_end_offset,
        literals.clone(),
        last_row,
        last_block,
        randomness,
        repeated_offset,
    );

    // sanity check:
    assert_eq!(
        offset, expected_end_offset,
        "end offset after tag=SequencesData mismatch"
    );
    witness_rows.extend_from_slice(&rows);

    BlockProcessingResult {
        offset,
        witness_rows,
        literals,
        sequence_info,
        fse_aux_tables,
        address_table_rows,
        sequence_exec_result: SequenceExecResult {
            exec_trace: sequence_exec,
            recovered_bytes: original_bytes,
        },
        repeated_offset,
        regen_size: regen_size as u64,
    }
}

#[derive(Debug, Clone)]
pub struct SequencesProcessingResult<F> {
    pub offset: usize,
    pub witness_rows: Vec<ZstdWitnessRow<F>>,
    pub fse_aux_tables: [FseAuxiliaryTableData; 3], // LLT, MLT, CMOT
    pub address_table_rows: Vec<AddressTableRow>,   // Parsed sequence instructions
    pub original_bytes: Vec<u8>,                    // Recovered original input
    pub sequence_info: SequenceInfo,
    pub sequence_exec: Vec<SequenceExec>,
    pub repeated_offset: [usize; 3],
}

#[allow(clippy::too_many_arguments)]
fn process_sequences<F: Field>(
    src: &[u8],
    decoded_bytes: &mut Vec<u8>,
    block_idx: u64,
    byte_offset: usize,
    end_offset: usize,
    literals: Vec<u64>,
    last_row: &ZstdWitnessRow<F>,
    last_block: bool,
    randomness: Value<F>,
    mut repeated_offset: [usize; 3],
) -> SequencesProcessingResult<F> {
    // Initialize witness values
    let mut witness_rows: Vec<ZstdWitnessRow<F>> = vec![];
    let encoded_len = last_row.encoded_data.encoded_len;

    //////////////////////////////////////////////////////
    ///// Sequence Section Part 1: Sequence Header  //////
    //////////////////////////////////////////////////////
    let mut sequence_info = SequenceInfo {
        block_idx: block_idx as usize,
        ..Default::default()
    };

    let byte0 = *src
        .get(byte_offset)
        .expect("First byte of sequence header must exist.");
    assert!(byte0 > 0u8, "Sequences can't be of 0 length");

    let (num_of_sequences, num_sequence_header_bytes) = if byte0 < 128 {
        (byte0 as u64, 2usize)
    } else {
        let byte1 = *src
            .get(byte_offset + 1)
            .expect("Next byte of sequence header must exist.");
        if byte0 < 255 {
            ((((byte0 - 128) as u64) << 8) + byte1 as u64, 3)
        } else {
            let byte2 = *src
                .get(byte_offset + 2)
                .expect("Third byte of sequence header must exist.");
            ((byte1 as u64) + ((byte2 as u64) << 8) + 0x7F00, 4)
        }
    };
    sequence_info.num_sequences = num_of_sequences as usize;

    let compression_mode_byte = *src
        .get(byte_offset + num_sequence_header_bytes - 1)
        .expect("Compression mode byte must exist.");
    let mode_bits = value_bits_le(compression_mode_byte);

    let literal_lengths_mode = mode_bits[6] + mode_bits[7] * 2;
    let offsets_mode = mode_bits[4] + mode_bits[5] * 2;
    let match_lengths_mode = mode_bits[2] + mode_bits[3] * 2;
    let reserved = mode_bits[0] + mode_bits[1] * 2;

    assert!(reserved == 0, "Reserved bits must be 0");

    // Note: Only 2 modes of FSE encoding are accepted (instead of 4):
    // 0 - Predefined.
    // 2 - Variable bit packing.
    assert!(
        literal_lengths_mode == 2 || literal_lengths_mode == 0,
        "Only FSE_Compressed_Mode or Predefined are allowed"
    );
    assert!(
        offsets_mode == 2 || offsets_mode == 0,
        "Only FSE_Compressed_Mode or Predefined are allowed"
    );
    assert!(
        match_lengths_mode == 2 || match_lengths_mode == 0,
        "Only FSE_Compressed_Mode or Predefined are allowed"
    );
    sequence_info.compression_mode = [
        literal_lengths_mode > 0,
        offsets_mode > 0,
        match_lengths_mode > 0,
    ];

    let multiplier =
        (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
    let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;
    let is_all_predefined_fse = literal_lengths_mode + offsets_mode + match_lengths_mode < 1;

    // Add witness rows for the sequence header
    let sequence_header_start_offset = byte_offset;
    let sequence_header_end_offset = byte_offset + num_sequence_header_bytes;

    let tag_rlc_iter = src[sequence_header_start_offset..sequence_header_end_offset]
        .iter()
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        });
    let tag_rlc = tag_rlc_iter.clone().last().expect("Tag RLC must exist");

    let header_rows = src[sequence_header_start_offset..sequence_header_end_offset]
        .iter()
        .zip(tag_rlc_iter)
        .enumerate()
        .map(|(i, (&value_byte, tag_rlc_acc))| ZstdWitnessRow {
            state: ZstdState {
                tag: ZstdTag::ZstdBlockSequenceHeader,
                tag_next: if is_all_predefined_fse {
                    ZstdTag::ZstdBlockSequenceData
                } else {
                    ZstdTag::ZstdBlockSequenceFseCode
                },
                block_idx,
                max_tag_len: ZstdTag::ZstdBlockSequenceHeader.max_len(),
                tag_len: num_sequence_header_bytes as u64,
                tag_idx: (i + 1) as u64,
                is_tag_change: i == 0,
                tag_rlc,
                tag_rlc_acc,
            },
            encoded_data: EncodedData {
                byte_idx: (sequence_header_start_offset + i + 1) as u64,
                encoded_len: last_row.encoded_data.encoded_len,
                value_byte,
                value_rlc,
                reverse: false,
                ..Default::default()
            },
            decoded_data: DecodedData {
                decoded_len: last_row.decoded_data.decoded_len,
            },
            bitstream_read_data: BitstreamReadRow::default(),
            fse_data: FseDecodingRow::default(),
        })
        .collect::<Vec<_>>();

    witness_rows.extend_from_slice(&header_rows);

    /////////////////////////////////////////////////
    ///// Sequence Section Part 2: FSE Tables  //////
    /////////////////////////////////////////////////
    let byte_offset = sequence_header_end_offset;
    let fse_starting_byte_offset = byte_offset;

    // Literal Length Table (LLT)
    let (n_fse_bytes_llt, bit_boundaries_llt, table_llt) = FseAuxiliaryTableData::reconstruct(
        src,
        block_idx,
        FseTableKind::LLT,
        byte_offset,
        literal_lengths_mode < 2,
    )
    .expect("Reconstructing FSE-packed Literl Length (LL) table should not fail.");
    let llt = table_llt.parse_state_table();
    // Determine the accuracy log of LLT
    let al_llt = if literal_lengths_mode > 0 {
        bit_boundaries_llt
            .first()
            .expect("Accuracy Log should exist")
            .1
            + 5
    } else {
        6
    };

    // Cooked Match Offset Table (CMOT)
    let byte_offset = byte_offset + n_fse_bytes_llt;
    let (n_fse_bytes_cmot, bit_boundaries_cmot, table_cmot) = FseAuxiliaryTableData::reconstruct(
        src,
        block_idx,
        FseTableKind::MOT,
        byte_offset,
        offsets_mode < 2,
    )
    .expect("Reconstructing FSE-packed Cooked Match Offset (CMO) table should not fail.");
    let cmot = table_cmot.parse_state_table();
    // Determine the accuracy log of CMOT
    let al_cmot = if offsets_mode > 0 {
        bit_boundaries_cmot
            .first()
            .expect("Accuracy Log should exist")
            .1
            + 5
    } else {
        5
    };

    // Match Length Table (MLT)
    let byte_offset = byte_offset + n_fse_bytes_cmot;
    let (n_fse_bytes_mlt, bit_boundaries_mlt, table_mlt) = FseAuxiliaryTableData::reconstruct(
        src,
        block_idx,
        FseTableKind::MLT,
        byte_offset,
        match_lengths_mode < 2,
    )
    .expect("Reconstructing FSE-packed Match Length (ML) table should not fail.");
    let mlt = table_mlt.parse_state_table();
    // Determine the accuracy log of MLT
    let al_mlt = if match_lengths_mode > 0 {
        bit_boundaries_mlt
            .first()
            .expect("Accuracy Log should exist")
            .1
            + 5
    } else {
        6
    };

    // Add witness rows for the above three FSE tables
    let mut last_row = header_rows.last().cloned().unwrap();
    for (start_offset, end_offset, bit_boundaries, tag_len, table, is_fse_section_end) in [
        (
            fse_starting_byte_offset,
            fse_starting_byte_offset + n_fse_bytes_llt,
            bit_boundaries_llt,
            n_fse_bytes_llt as u64,
            &table_llt,
            offsets_mode + match_lengths_mode < 1,
        ),
        (
            fse_starting_byte_offset + n_fse_bytes_llt,
            fse_starting_byte_offset + n_fse_bytes_llt + n_fse_bytes_cmot,
            bit_boundaries_cmot,
            n_fse_bytes_cmot as u64,
            &table_cmot,
            match_lengths_mode < 1,
        ),
        (
            fse_starting_byte_offset + n_fse_bytes_llt + n_fse_bytes_cmot,
            fse_starting_byte_offset + n_fse_bytes_llt + n_fse_bytes_cmot + n_fse_bytes_mlt,
            bit_boundaries_mlt,
            n_fse_bytes_mlt as u64,
            &table_mlt,
            true,
        ),
    ] {
        if end_offset > start_offset {
            let mut tag_rlc_iter =
                src[start_offset..end_offset]
                    .iter()
                    .scan(Value::known(F::zero()), |acc, &byte| {
                        *acc = *acc * randomness + Value::known(F::from(byte as u64));
                        Some(*acc)
                    });
            let tag_rlc = tag_rlc_iter.clone().last().expect("Tag RLC must exist");

            let mut decoded: u64 = 0;
            let mut n_acc: usize = 0;
            let mut n_emitted: usize = 0;
            let mut current_tag_rlc_acc = Value::known(F::zero());
            let mut last_byte_idx: i64 = 0;
            let mut from_pos: (i64, i64) = (1, 0);
            let mut to_pos: (i64, i64) = (0, 0);
            let kind = table.table_kind;
            let mut next_symbol: i32 = -1;
            let mut is_repeating_bit_boundary: HashMap<usize, bool> = HashMap::new();

            let multiplier =
                (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
            let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;
            let mut last_symbol: i32 = 0;

            // Convert multi-bit read operations boundaries from the stream into a convenient format
            // so they can be easily converted into witness rows later.

            // Format:

            // symbol,                 The symbol being decoded now
            // n_emitted,              The total number of unique symbols decoded
            // from_byte_position,     Which byte the read operation starts at
            // from_bit_position,      Which bit position the read operation
            //                         starts at, with range ∈ [0, 8)
            // to_byte_position,       Which byte the read operation ends at
            // to_bit_position,        Which bit position the read operation ends at,
            //                         with range ∈ [0, 16)
            // value_read,             Bit value
            // value_decoded,          The decoded value is processed from the raw bitstring value
            // current_tag_value_acc,  Depending on the current byte position,
            //                         the accumulator increments accordingly
            // current_tag_rlc_acc,    Depending on the current byte position,
            //                         the accumulator increments accordingly
            // n_acc,                  How many states are already assigned to the current symbol
            // table_kind,             What FSE table is being decoded
            // table_size,             The size of current FSE table
            // is_repeating_bits,      Whether current bitstring represents repeat bits.
            //                         Repeat bits immediately follows a bitstring=1 read operation.
            //                         Repeat bits indicate how many 0-state symbols to skip.
            // is_trailing_bits,       FSE bitstreams may have trailing bits

            let bitstream_rows = bit_boundaries
                .iter()
                .enumerate()
                .map(|(bit_boundary_idx, (bit_idx, value_read, value_decoded))| {
                    // First calculate the start and end position of the current read operation
                    from_pos = if next_symbol == -1 { (1, -1) } else { to_pos };
                    from_pos.1 += 1;
                    if from_pos.1 == 8 || from_pos.1 == 16 {
                        from_pos = (from_pos.0 + 1, 0);
                    }
                    from_pos.1 = (from_pos.1 as u64).rem_euclid(8) as i64;
                    while from_pos.0 > last_byte_idx {
                        current_tag_rlc_acc = tag_rlc_iter.next().unwrap();
                        last_byte_idx += 1;
                    }

                    // Derive the end position based on how many bits are read
                    let to_byte_idx = (bit_idx - 1) / 8;
                    let mut to_bit_idx = bit_idx - to_byte_idx * (N_BITS_PER_BYTE as u32) - 1;
                    if from_pos.0 < (to_byte_idx + 1) as i64 {
                        to_bit_idx += 8;
                    }
                    to_pos = ((to_byte_idx + 1) as i64, to_bit_idx as i64);

                    if bit_boundary_idx < 1 {
                        // Read Scenarios 1: Accuracy log bits (Always the First Read)
                        next_symbol += 1;
                        assert_eq!(value_read, value_decoded, "no varbit packing for AL bits");
                        (
                            0,
                            n_emitted,
                            from_pos.0 as usize,
                            from_pos.1 as usize,
                            to_pos.0 as usize,
                            to_pos.1 as usize,
                            *value_read,
                            *value_decoded,
                            current_tag_rlc_acc,
                            n_acc,
                            kind as u64,
                            table.table_size,
                            false,
                            false,
                        )
                    } else if !is_repeating_bit_boundary.contains_key(&bit_boundary_idx) {
                        if n_acc >= (table.table_size as usize) {
                            // Read Scenarios 2: Trailing Bits
                            assert_eq!(
                                value_read, value_decoded,
                                "no varbit packing for trailing bits"
                            );
                            (
                                last_symbol as u64,
                                n_emitted,
                                from_pos.0 as usize,
                                from_pos.1 as usize,
                                to_pos.0 as usize,
                                to_pos.1 as usize,
                                *value_read,
                                *value_decoded,
                                current_tag_rlc_acc,
                                n_acc,
                                kind as u64,
                                table.table_size,
                                false,
                                true,
                            )
                        } else {
                            // Read Scenarios 3: Regular Decoding State
                            assert!(next_symbol >= 0);
                            decoded = next_symbol as u64;
                            n_emitted += 1;
                            last_symbol = next_symbol;
                            next_symbol += 1;
                            match *value_decoded {
                                0 => {
                                    // When a symbol has a value==0, it signifies a case of prob=-1
                                    // (or probability "less
                                    // than 1"), where
                                    // such symbols are allocated states from the
                                    // end and retreating. Exactly 1 state is allocated in this
                                    // case.
                                    n_acc += 1;
                                }
                                1 => {
                                    let mut repeating_bit_boundary_idx = bit_boundary_idx + 1;
                                    loop {
                                        let repeating_bits =
                                            bit_boundaries[repeating_bit_boundary_idx].1;
                                        next_symbol += repeating_bits as i32; // skip symbols
                                        is_repeating_bit_boundary
                                            .insert(repeating_bit_boundary_idx, true);

                                        if repeating_bits < 3 {
                                            break;
                                        } else {
                                            repeating_bit_boundary_idx += 1;
                                        }
                                    }
                                }
                                _ => {
                                    n_acc += (*value_decoded - 1) as usize;
                                }
                            }

                            (
                                decoded,
                                n_emitted,
                                from_pos.0 as usize,
                                from_pos.1 as usize,
                                to_pos.0 as usize,
                                to_pos.1 as usize,
                                *value_read,
                                *value_decoded,
                                current_tag_rlc_acc,
                                n_acc,
                                kind as u64,
                                table.table_size,
                                false,
                                false,
                            )
                        }
                    } else {
                        // Read Scenarios 3: Repeating Bits
                        let symbol = last_symbol as u64 + value_decoded;
                        last_symbol = symbol as i32;
                        assert_eq!(
                            value_read, value_decoded,
                            "no varbit packing for repeat-bits flag"
                        );
                        (
                            symbol,
                            n_emitted,
                            from_pos.0 as usize,
                            from_pos.1 as usize,
                            to_pos.0 as usize,
                            to_pos.1 as usize,
                            *value_read,
                            *value_decoded,
                            current_tag_rlc_acc,
                            n_acc,
                            // FseDecoder-specific witness values
                            kind as u64,
                            table.table_size,
                            true,
                            false,
                        )
                    }
                })
                .collect::<Vec<(
                    u64,
                    usize,
                    usize,
                    usize,
                    usize,
                    usize,
                    u64,
                    u64,
                    Value<F>,
                    usize,
                    u64,
                    u64,
                    bool,
                    bool,
                )>>();

            // Transform bitstream rows into witness rows
            for (j, row) in bitstream_rows.iter().enumerate() {
                witness_rows.push(ZstdWitnessRow {
                    state: ZstdState {
                        tag: ZstdTag::ZstdBlockSequenceFseCode,
                        tag_next: if is_fse_section_end {
                            ZstdTag::ZstdBlockSequenceData
                        } else {
                            ZstdTag::ZstdBlockSequenceFseCode
                        },
                        block_idx,
                        max_tag_len: ZstdTag::ZstdBlockSequenceFseCode.max_len(),
                        tag_len,
                        tag_idx: row.2 as u64,
                        is_tag_change: j == 0,
                        tag_rlc,
                        tag_rlc_acc: row.8,
                    },
                    encoded_data: EncodedData {
                        byte_idx: (start_offset + row.2) as u64,
                        encoded_len,
                        value_byte: src[start_offset + row.2 - 1],
                        value_rlc,
                        reverse: false,
                        ..Default::default()
                    },
                    bitstream_read_data: BitstreamReadRow {
                        bit_start_idx: row.3,
                        bit_end_idx: row.5,
                        bit_value: row.6,
                        is_zero_bit_read: false,
                        ..Default::default()
                    },
                    decoded_data: DecodedData {
                        decoded_len: last_row.decoded_data.decoded_len,
                    },
                    fse_data: FseDecodingRow {
                        table_kind: row.10,
                        table_size: row.11,
                        symbol: row.0,
                        num_emitted: row.1 as u64,
                        value_decoded: row.7,
                        probability_acc: row.9 as u64,
                        is_repeat_bits_loop: row.12,
                        is_trailing_bits: row.13,
                    },
                });

                // The maximum allowed accuracy log for literals length and match length tables is
                // 9, This provision will produce a skipped byte row in only one
                // scenario: The previous byte ended on the second last bit, and the
                // subsequent read consumes 9 bits, which produces a range covering
                // the second byte entirely, resulting in a nil row.
                if (row.5 - row.3 + 1) > 8 && row.5 >= 15 {
                    last_row = witness_rows.last().cloned().unwrap();
                    let byte_value = src[start_offset + row.2];

                    witness_rows.push(ZstdWitnessRow {
                        state: ZstdState {
                            tag: ZstdTag::ZstdBlockSequenceFseCode,
                            tag_next: if is_fse_section_end {
                                ZstdTag::ZstdBlockSequenceData
                            } else {
                                ZstdTag::ZstdBlockSequenceFseCode
                            },
                            block_idx,
                            max_tag_len: ZstdTag::ZstdBlockSequenceFseCode.max_len(),
                            tag_len,
                            tag_idx: (row.2 + 1) as u64,
                            is_tag_change: false,
                            tag_rlc,
                            tag_rlc_acc: row.8 * randomness
                                + Value::known(F::from(byte_value as u64)),
                        },
                        encoded_data: EncodedData {
                            byte_idx: (start_offset + row.2 + 1) as u64,
                            encoded_len,
                            value_byte: byte_value,
                            value_rlc,
                            reverse: false,
                            ..Default::default()
                        },
                        bitstream_read_data: BitstreamReadRow {
                            // Deterministic start and end bit idx note:
                            // There's only one scenario that can produce a nil row in the FSE table
                            // section. This read operation must end on
                            // the last bit of the second byte.
                            bit_start_idx: 7,
                            bit_end_idx: 7,
                            bit_value: 0,
                            is_zero_bit_read: false,
                            is_nil: true,
                            is_update_state: 0u64,
                            ..Default::default()
                        },
                        decoded_data: DecodedData {
                            decoded_len: last_row.decoded_data.decoded_len,
                        },
                        fse_data: FseDecodingRow {
                            table_kind: row.10,
                            table_size: row.11,
                            symbol: row.0,
                            num_emitted: row.1 as u64,
                            value_decoded: row.7,
                            probability_acc: row.9 as u64,
                            is_repeat_bits_loop: false,
                            is_trailing_bits: row.13,
                        },
                    })
                }

                last_row = witness_rows.last().cloned().unwrap();
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    ///// Sequence Section Part 3: Sequence Data (Instruction Bitstream)  //////
    ////////////////////////////////////////////////////////////////////////////

    // Reconstruct LLTV, CMOTV, and MLTV which specifies bit actions for a specific state
    let lltv = SequenceFixedStateActionTable::reconstruct_lltv();
    let cmotv = SequenceFixedStateActionTable::reconstruct_cmotv(CMOT_N);
    let mltv = SequenceFixedStateActionTable::reconstruct_mltv();

    // Decode sequence bitstream
    let byte_offset = byte_offset + n_fse_bytes_mlt;
    let sequence_bitstream = &src[byte_offset..end_offset]
        .iter()
        .rev()
        .clone()
        .flat_map(|v| {
            let mut bits = value_bits_le(*v);
            bits.reverse();
            bits
        })
        .collect::<Vec<u8>>();

    // Bitstream processing state values
    let _num_emitted: usize = 0;
    let n_sequence_data_bytes = end_offset - byte_offset;
    let mut last_byte_idx: usize = 1;
    let mut current_byte_idx: usize = 1;
    let mut current_bit_idx: usize = 0;

    // Update the last row
    let multiplier =
        (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
    let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

    let tag_rlc_iter =
        &src[byte_offset..end_offset]
            .iter()
            .scan(Value::known(F::zero()), |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            });
    let tag_rlc = tag_rlc_iter.clone().last().expect("Tag RLC must exist");
    let mut tag_rlc_iter = tag_rlc_iter
        .clone()
        .collect::<Vec<Value<F>>>()
        .into_iter()
        .rev();

    let mut next_tag_rlc_acc = tag_rlc_iter.next().unwrap();

    let mut padding_end_idx = 0;
    while sequence_bitstream[padding_end_idx] == 0 {
        padding_end_idx += 1;
    }

    // Add a witness row for leading 0s and the sentinel 1-bit
    witness_rows.push(ZstdWitnessRow {
        state: ZstdState {
            tag: ZstdTag::ZstdBlockSequenceData,
            tag_next: if last_block {
                ZstdTag::Null
            } else {
                ZstdTag::BlockHeader
            },
            block_idx,
            max_tag_len: ZstdTag::ZstdBlockSequenceData.max_len(),
            tag_len: n_sequence_data_bytes as u64,
            tag_idx: 1_u64,
            is_tag_change: true,
            tag_rlc,
            tag_rlc_acc: next_tag_rlc_acc,
        },
        encoded_data: EncodedData {
            byte_idx: (byte_offset + current_byte_idx) as u64,
            encoded_len,
            value_byte: src[end_offset - current_byte_idx],
            value_rlc,
            reverse: true,
            reverse_len: n_sequence_data_bytes as u64,
            reverse_idx: (n_sequence_data_bytes - (current_byte_idx - 1)) as u64,
        },
        bitstream_read_data: BitstreamReadRow {
            bit_start_idx: 0usize,
            bit_end_idx: padding_end_idx,
            bit_value: 1u64,
            is_zero_bit_read: false,
            ..Default::default()
        },
        decoded_data: last_row.decoded_data.clone(),
        fse_data: FseDecodingRow::default(),
    });

    // Exclude the leading zero section
    while sequence_bitstream[current_bit_idx] == 0 {
        (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
    }
    // Exclude the sentinel 1-bit
    (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);

    // Update accumulators
    if current_byte_idx > last_byte_idx {
        next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
        last_byte_idx = current_byte_idx;
    }

    // Now the actual data-bearing bitstream starts
    // The sequence bitstream is interleaved by 6 bit processing strands.
    // The interleaving order is: CMOVBits, MLVBits, LLVBits, LLFBits, MLFBits, CMOFBits
    let mut seq_idx: usize = 0;
    let mut decoded_bitstring_values: Vec<(SequenceDataTag, u64)> = vec![];
    let mut raw_sequence_instructions: Vec<(usize, usize, usize)> = vec![]; // offset_state, match_length, literal_length
    let mut curr_instruction: [usize; 3] = [0, 0, 0];

    // Note: mode and order_idx produces 6 distinct decoding state
    let mut mode: usize = 1; // use 0 or 1 to denote whether bitstream produces data or next decoding state
    let mut order_idx: usize = 0; // use 0, 1, 2 to denote the order of decoded value within current mode

    let mut state_baselines: [usize; 3] = [0, 0, 0]; // 3 states for LL, ML, CMO
    let mut decoding_baselines: [usize; 3] = [0, 0, 0]; // 3 decoding bl for CMO, ML, LL

    let data_tags = [
        SequenceDataTag::CookedMatchOffsetValue,
        SequenceDataTag::MatchLengthValue,
        SequenceDataTag::LiteralLengthValue,
        SequenceDataTag::LiteralLengthFse,
        SequenceDataTag::MatchLengthFse,
        SequenceDataTag::CookedMatchOffsetFse,
    ];
    let next_nb_to_read_for_states: [usize; 3] =
        [al_llt as usize, al_mlt as usize, al_cmot as usize]; // Obtained from accuracy log
    let next_nb_to_read_for_values: [usize; 3] = [0, 0, 0];
    let mut nb_switch = [next_nb_to_read_for_values, next_nb_to_read_for_states];
    let v_tables = [cmotv, mltv, lltv];
    let f_tables = [llt, mlt, cmot];

    let mut is_init = true;
    let mut nb = nb_switch[mode][order_idx];
    let bitstream_end_bit_idx = n_sequence_data_bytes * N_BITS_PER_BYTE;
    let mut table_kind;
    let mut table_size;
    let mut last_states: [u64; 3] = [0, 0, 0];
    let mut last_symbols: [u64; 3] = [0, 0, 0];
    let mut current_decoding_state;
    let mut tail_holding_bit = false;

    while current_bit_idx + nb <= bitstream_end_bit_idx {
        let bitstring_value =
            be_bits_to_value(&sequence_bitstream[current_bit_idx..(current_bit_idx + nb)]);
        let curr_baseline;

        if mode > 0 {
            // For the initial baseline determination, ML and CMO positions are flipped.
            if is_init {
                order_idx = [0, 2, 1][order_idx];
            }

            if order_idx < 1 {
                seq_idx += 1;
            }

            let new_decoded = (data_tags[mode * 3 + order_idx], bitstring_value);
            decoded_bitstring_values.push(new_decoded);

            current_decoding_state = (mode * 3 + order_idx) as u64;

            table_kind = match new_decoded.0 {
                SequenceDataTag::CookedMatchOffsetFse | SequenceDataTag::CookedMatchOffsetValue => {
                    table_cmot.table_kind as u64
                }
                SequenceDataTag::MatchLengthFse | SequenceDataTag::MatchLengthValue => {
                    table_mlt.table_kind as u64
                }
                SequenceDataTag::LiteralLengthFse | SequenceDataTag::LiteralLengthValue => {
                    table_llt.table_kind as u64
                }
            };
            table_size = match new_decoded.0 {
                SequenceDataTag::CookedMatchOffsetFse | SequenceDataTag::CookedMatchOffsetValue => {
                    table_cmot.table_size
                }
                SequenceDataTag::MatchLengthFse | SequenceDataTag::MatchLengthValue => {
                    table_mlt.table_size
                }
                SequenceDataTag::LiteralLengthFse | SequenceDataTag::LiteralLengthValue => {
                    table_llt.table_size
                }
            };

            // FSE state update step
            curr_baseline = state_baselines[order_idx];
            let new_state = (curr_baseline as u64) + bitstring_value;
            last_states[order_idx] = new_state;
            let new_state_params = f_tables[order_idx]
                .get(&new_state)
                .expect("State should exist.");
            let state_symbol = new_state_params.0;
            last_symbols[order_idx] = state_symbol;

            let value_idx = 3 - order_idx - 1;

            // Update baseline and nb for next FSE state transition
            state_baselines[order_idx] = new_state_params.1 as usize;
            nb_switch[1][order_idx] = new_state_params.2 as usize;

            // Update baseline and nb for next value decoding
            decoding_baselines[value_idx] = v_tables[value_idx].states_to_actions
                [state_symbol as usize]
                .1
                 .0 as usize;
            nb_switch[0][value_idx] = v_tables[value_idx].states_to_actions[state_symbol as usize]
                .1
                 .1 as usize;

            // Flip back the idx for first step
            if is_init {
                order_idx = [0, 2, 1][order_idx];
            }
        } else {
            let new_decoded = (data_tags[mode * 3 + order_idx], bitstring_value);
            decoded_bitstring_values.push(new_decoded);

            current_decoding_state = (mode * 3 + order_idx) as u64;

            table_kind = match new_decoded.0 {
                SequenceDataTag::CookedMatchOffsetFse | SequenceDataTag::CookedMatchOffsetValue => {
                    table_cmot.table_kind as u64
                }
                SequenceDataTag::MatchLengthFse | SequenceDataTag::MatchLengthValue => {
                    table_mlt.table_kind as u64
                }
                SequenceDataTag::LiteralLengthFse | SequenceDataTag::LiteralLengthValue => {
                    table_llt.table_kind as u64
                }
            };
            table_size = match new_decoded.0 {
                SequenceDataTag::CookedMatchOffsetFse | SequenceDataTag::CookedMatchOffsetValue => {
                    table_cmot.table_size
                }
                SequenceDataTag::MatchLengthFse | SequenceDataTag::MatchLengthValue => {
                    table_mlt.table_size
                }
                SequenceDataTag::LiteralLengthFse | SequenceDataTag::LiteralLengthValue => {
                    table_llt.table_size
                }
            };

            // Value decoding step
            curr_baseline = decoding_baselines[order_idx];
            let new_value = (curr_baseline as u64) + bitstring_value;
            curr_instruction[order_idx] = new_value as usize;
        }

        // bitstream witness row data
        let from_bit_idx = current_bit_idx.rem_euclid(8);
        let to_bit_idx = if nb > 0 {
            from_bit_idx + (nb - 1)
        } else {
            from_bit_idx
        };

        // Add a witness row
        witness_rows.push(ZstdWitnessRow {
            state: ZstdState {
                tag: ZstdTag::ZstdBlockSequenceData,
                tag_next: if last_block {
                    ZstdTag::Null
                } else {
                    ZstdTag::BlockHeader
                },
                block_idx,
                max_tag_len: ZstdTag::ZstdBlockSequenceData.max_len(),
                tag_len: n_sequence_data_bytes as u64,
                tag_idx: current_byte_idx as u64,
                is_tag_change: false,
                tag_rlc,
                tag_rlc_acc: next_tag_rlc_acc,
            },
            encoded_data: EncodedData {
                byte_idx: (byte_offset + current_byte_idx) as u64,
                encoded_len,
                value_byte: if end_offset - current_byte_idx < src.len() {
                    src[end_offset - current_byte_idx]
                } else {
                    src.last().cloned().unwrap()
                },
                value_rlc,
                reverse: true,
                reverse_len: n_sequence_data_bytes as u64,
                reverse_idx: (n_sequence_data_bytes - (current_byte_idx - 1)) as u64,
            },
            bitstream_read_data: BitstreamReadRow {
                bit_start_idx: from_bit_idx,
                bit_end_idx: to_bit_idx,
                bit_value: bitstring_value,
                is_zero_bit_read: (nb == 0),
                is_seq_init: is_init,
                seq_idx,
                states: last_states,
                symbols: last_symbols,
                values: [
                    curr_instruction[2] as u64,
                    curr_instruction[1] as u64,
                    curr_instruction[0] as u64,
                ],
                baseline: curr_baseline as u64,
                is_nil: false,
                is_update_state: (current_decoding_state >= 3) as u64,
            },
            decoded_data: last_row.decoded_data.clone(),
            fse_data: FseDecodingRow {
                table_kind,
                table_size,
                ..Default::default()
            },
        });

        // When the range of a multi-byte read operation from the bitstream covers an entire byte,
        // a separate row needs to be added for each of such byte to ensure continuity of the value
        // accumulators. These compensating rows have is_nil=true. At most, two bytes can be
        // entirely covered by a bitstream read operation.
        let multi_byte_boundaries: [usize; 2] = [15, 23];
        let mut skipped_bits = 0usize;

        for boundary in multi_byte_boundaries {
            if to_bit_idx >= boundary {
                // Skip over covered bytes for byte and bit index
                for _ in 0..N_BITS_PER_BYTE {
                    (current_byte_idx, current_bit_idx) =
                        increment_idx(current_byte_idx, current_bit_idx);
                }
                // Increment accumulators for nil row
                if current_byte_idx > last_byte_idx && current_byte_idx <= n_sequence_data_bytes {
                    next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
                    last_byte_idx = current_byte_idx;
                }
                skipped_bits += N_BITS_PER_BYTE;

                let wrap_by = match to_bit_idx {
                    15 => 8,
                    16..=23 => 16,
                    v => unreachable!(
                        "unexpected bit_index_end={:?} in (table={:?}, update_f?={:?}) (bit_index_start={:?}, bitstring_len={:?})",
                        v, table_kind, (current_decoding_state >= 3), from_bit_idx, to_bit_idx - from_bit_idx + 1,
                    ),
                };
                witness_rows.push(ZstdWitnessRow {
                    state: ZstdState {
                        tag: ZstdTag::ZstdBlockSequenceData,
                        tag_next: if last_block {
                            ZstdTag::Null
                        } else {
                            ZstdTag::BlockHeader
                        },
                        block_idx,
                        max_tag_len: ZstdTag::ZstdBlockSequenceData.max_len(),
                        tag_len: n_sequence_data_bytes as u64,
                        tag_idx: current_byte_idx as u64,
                        is_tag_change: false,
                        tag_rlc,
                        tag_rlc_acc: next_tag_rlc_acc,
                    },
                    encoded_data: EncodedData {
                        byte_idx: (byte_offset + current_byte_idx) as u64,
                        encoded_len,
                        value_byte: if end_offset - current_byte_idx < src.len() {
                            src[end_offset - current_byte_idx]
                        } else {
                            src.last().cloned().unwrap()
                        },
                        value_rlc,
                        reverse: true,
                        reverse_len: n_sequence_data_bytes as u64,
                        reverse_idx: (n_sequence_data_bytes - (current_byte_idx - 1)) as u64,
                    },
                    bitstream_read_data: BitstreamReadRow {
                        bit_start_idx: to_bit_idx - wrap_by,
                        bit_end_idx: to_bit_idx - wrap_by,
                        bit_value: 0,
                        is_zero_bit_read: false,
                        is_seq_init: is_init,
                        seq_idx,
                        states: last_states,
                        symbols: last_symbols,
                        values: [
                            curr_instruction[2] as u64,
                            curr_instruction[1] as u64,
                            curr_instruction[0] as u64,
                        ],
                        baseline: curr_baseline as u64,
                        is_nil: true,
                        is_update_state: (current_decoding_state >= 3) as u64,
                    },
                    decoded_data: last_row.decoded_data.clone(),
                    fse_data: FseDecodingRow {
                        table_kind,
                        table_size,
                        ..Default::default()
                    },
                })
            }
        }

        // Update all variables that indicate current decoding states
        order_idx += 1;
        if mode > 0 {
            if order_idx > 2 {
                is_init = false;
                mode = 0; // switch to data mode
                order_idx = 0;
            }
        } else if order_idx > 2 {
            mode = 1; // switch to FSE mode
            order_idx = 0;

            // Three elements (MO, ML and LL) are all decoded. Add the instruction.
            let new_instruction = (
                curr_instruction[0],
                curr_instruction[1],
                curr_instruction[2],
            );

            raw_sequence_instructions.push(new_instruction);
        }

        let next_nb = if is_init {
            // On the first step, ML and CMO are flipped
            let true_idx = [0, 2, 1][order_idx];
            nb_switch[mode][true_idx]
        } else {
            nb_switch[mode][order_idx]
        };

        // Adjust the end position of the current read operation:
        // If the next operation reads 0 bits, the ending bit position should stay on
        // the last bit, instead of incrementing to the next position. When the nb=0 streak breaks,
        // the held off position is released.
        if nb > 0 && next_nb > 0 {
            for _ in 0..(nb - skipped_bits) {
                (current_byte_idx, current_bit_idx) =
                    increment_idx(current_byte_idx, current_bit_idx);
            }
        } else if nb > 0 && next_nb == 0 {
            tail_holding_bit = true;
            for _ in 0..(nb - skipped_bits - 1) {
                (current_byte_idx, current_bit_idx) =
                    increment_idx(current_byte_idx, current_bit_idx);
            }
        } else if nb == 0 && next_nb > 0 && tail_holding_bit {
            (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
            tail_holding_bit = false;
        }

        if current_byte_idx > last_byte_idx && current_byte_idx <= n_sequence_data_bytes {
            next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
            last_byte_idx = current_byte_idx;
        }

        // Update the next nb for the next read operation
        nb = next_nb;
    }

    // Process raw sequence instructions
    let mut address_table_rows: Vec<AddressTableRow> = vec![];
    let mut literal_len_acc: usize = 0;

    for (idx, inst) in raw_sequence_instructions.iter().enumerate() {
        let actual_offset = if inst.0 > 3 {
            inst.0 - 3
        } else {
            let repeat_idx = inst.0;
            if inst.2 == 0 {
                if repeat_idx == 3 {
                    repeated_offset[0] - 1
                } else {
                    repeated_offset[repeat_idx]
                }
            } else {
                repeated_offset[repeat_idx - 1]
            }
        } as u64;

        literal_len_acc += inst.2;

        // Update repeated offset
        if inst.0 > 3 {
            repeated_offset[2] = repeated_offset[1];
            repeated_offset[1] = repeated_offset[0];
            repeated_offset[0] = inst.0 - 3;
        } else {
            let mut repeat_idx = inst.0;
            if inst.2 == 0 {
                repeat_idx += 1;
            }

            if repeat_idx == 2 {
                repeated_offset.swap(1, 0);
            } else if repeat_idx == 3 {
                let result = repeated_offset[2];
                repeated_offset[2] = repeated_offset[1];
                repeated_offset[1] = repeated_offset[0];
                repeated_offset[0] = result;
            } else if repeat_idx == 4 {
                let result = repeated_offset[0] - 1;
                assert!(result > 0, "corruptied data");
                repeated_offset[2] = repeated_offset[1];
                repeated_offset[1] = repeated_offset[0];
                repeated_offset[0] = result;
            } else {
                // repeat 1
            }
        };

        address_table_rows.push(AddressTableRow {
            s_padding: 0,
            instruction_idx: idx as u64,
            literal_length: inst.2 as u64,
            cooked_match_offset: inst.0 as u64,
            match_length: inst.1 as u64,
            literal_length_acc: literal_len_acc as u64,
            repeated_offset1: repeated_offset[0] as u64,
            repeated_offset2: repeated_offset[1] as u64,
            repeated_offset3: repeated_offset[2] as u64,
            actual_offset,
        });
    }

    // Executing sequence instructions to acquire the original input.
    // At this point, the address table rows are not padded. Paddings will be added as sequence
    // instructions progress.
    let mut recovered_inputs: Vec<u8> = vec![];
    let mut seq_exec_info: Vec<SequenceExec> = vec![];
    let mut current_literal_pos: usize = 0;

    for inst in address_table_rows.iter() {
        let new_literal_pos = current_literal_pos + (inst.literal_length as usize);
        if new_literal_pos > current_literal_pos {
            let r = current_literal_pos..new_literal_pos;
            seq_exec_info.push(SequenceExec(
                inst.instruction_idx as usize,
                SequenceExecInfo::LiteralCopy(r.clone()),
            ));
            let ext_slice = literals[r].iter().map(|&v| v as u8).collect::<Vec<u8>>();
            recovered_inputs.extend_from_slice(ext_slice.as_slice());
            decoded_bytes.extend_from_slice(ext_slice.as_slice());
        }

        let match_pos = decoded_bytes.len() - (inst.actual_offset as usize);
        if inst.match_length > 0 {
            let r = match_pos..(inst.match_length as usize + match_pos);
            seq_exec_info.push(SequenceExec(
                inst.instruction_idx as usize,
                SequenceExecInfo::BackRef(r.clone()),
            ));
            let matched_and_repeated_bytes = if inst.match_length <= inst.actual_offset {
                Vec::from(&decoded_bytes[r])
            } else {
                let l = inst.match_length as usize;
                let r_prime = match_pos..decoded_bytes.len();
                let matched_bytes = Vec::from(&decoded_bytes[r_prime]);
                matched_bytes.iter().cycle().take(l).copied().collect()
            };
            recovered_inputs.extend_from_slice(matched_and_repeated_bytes.as_slice());
            decoded_bytes.extend_from_slice(matched_and_repeated_bytes.as_slice());
        }
        current_literal_pos = new_literal_pos;
    }

    // Add remaining literal bytes
    if current_literal_pos < literals.len() {
        let r = current_literal_pos..literals.len();
        seq_exec_info.push(SequenceExec(
            sequence_info.num_sequences,
            SequenceExecInfo::LiteralCopy(r.clone()),
        ));
        let ext_slice = literals[r].iter().map(|&v| v as u8).collect::<Vec<u8>>();
        recovered_inputs.extend_from_slice(ext_slice.as_slice());
        decoded_bytes.extend_from_slice(ext_slice.as_slice());
    }

    SequencesProcessingResult {
        offset: end_offset,
        witness_rows,
        fse_aux_tables: [table_llt, table_cmot, table_mlt],
        address_table_rows,
        original_bytes: recovered_inputs,
        sequence_info,
        sequence_exec: seq_exec_info,
        repeated_offset,
    }
}

#[derive(Debug, Clone)]
pub struct LiteralsHeaderProcessingResult<F> {
    pub offset: usize,
    pub witness_rows: Vec<ZstdWitnessRow<F>>,
    pub regen_size: usize,
    pub compressed_size: usize,
}

fn process_block_zstd_literals_header<F: Field>(
    src: &[u8],
    block_idx: u64,
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
) -> LiteralsHeaderProcessingResult<F> {
    let lh_bytes = src
        .iter()
        .skip(byte_offset)
        .take(N_MAX_LITERAL_HEADER_BYTES)
        .cloned()
        .collect::<Vec<u8>>();

    let literals_block_type = BlockType::from(lh_bytes[0] & 0x3);
    let size_format = (lh_bytes[0] >> 2) & 3;

    let [n_bits_fmt, n_bits_regen, n_bits_compressed, _n_streams, n_bytes_header, _branch]: [usize;
        6] = match literals_block_type {
        BlockType::RawBlock => match size_format {
            0b00 | 0b10 => [1, 5, 0, 1, 1, 0],
            0b01 => [2, 12, 0, 1, 2, 1],
            0b11 => [2, 20, 0, 1, 3, 2],
            _ => unreachable!("size_format out of bound"),
        },
        _ => unreachable!("BlockType::* unexpected. Must be raw bytes for literals."),
    };

    // Bits for representing regenerated_size and compressed_size
    let sizing_bits = &lh_bytes.clone().into_iter().fold(vec![], |mut acc, b| {
        acc.extend(value_bits_le(b));
        acc
    })[(2 + n_bits_fmt)..(n_bytes_header * N_BITS_PER_BYTE)];

    let regen_size = le_bits_to_value(&sizing_bits[0..n_bits_regen]) as usize;
    let compressed_size =
        le_bits_to_value(&sizing_bits[n_bits_regen..(n_bits_regen + n_bits_compressed)]) as usize;
    let tag_next = match literals_block_type {
        BlockType::RawBlock => ZstdTag::ZstdBlockLiteralsRawBytes,
        _ => unreachable!("BlockType::* unexpected. Must be raw bytes for literals."),
    };

    let tag_rlc_iter =
        lh_bytes
            .iter()
            .take(n_bytes_header)
            .scan(Value::known(F::zero()), |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            });
    let tag_rlc = tag_rlc_iter.clone().last().expect("Tag RLC expected");

    let multiplier =
        (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
    let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

    LiteralsHeaderProcessingResult {
        offset: byte_offset + n_bytes_header,
        witness_rows: lh_bytes
            .iter()
            .take(n_bytes_header)
            .zip(tag_rlc_iter)
            .enumerate()
            .map(|(i, (&value_byte, tag_rlc_acc))| ZstdWitnessRow {
                state: ZstdState {
                    tag: ZstdTag::ZstdBlockLiteralsHeader,
                    tag_next,
                    block_idx,
                    max_tag_len: ZstdTag::ZstdBlockLiteralsHeader.max_len(),
                    tag_len: n_bytes_header as u64,
                    tag_idx: (i + 1) as u64,
                    is_tag_change: i == 0,
                    tag_rlc,
                    tag_rlc_acc,
                },
                encoded_data: EncodedData {
                    byte_idx: (byte_offset + i + 1) as u64,
                    encoded_len: last_row.encoded_data.encoded_len,
                    value_byte,
                    reverse: false,
                    value_rlc,
                    ..Default::default()
                },
                bitstream_read_data: BitstreamReadRow::default(),
                decoded_data: last_row.decoded_data.clone(),
                fse_data: FseDecodingRow::default(),
            })
            .collect::<Vec<_>>(),
        regen_size,
        compressed_size,
    }
}

/// Result for processing multiple blocks from compressed data
#[derive(Debug, Clone)]
pub struct MultiBlockProcessResult<F> {
    pub witness_rows: Vec<ZstdWitnessRow<F>>,
    pub literal_bytes: Vec<Vec<u64>>, // literals
    pub fse_aux_tables: Vec<FseAuxiliaryTableData>,
    pub block_info_arr: Vec<BlockInfo>,
    pub sequence_info_arr: Vec<SequenceInfo>,
    pub address_table_rows: Vec<Vec<AddressTableRow>>,
    pub sequence_exec_results: Vec<SequenceExecResult>,
}

/// Process a slice of bytes into decompression circuit witness rows
pub fn process<F: Field>(src: &[u8], randomness: Value<F>) -> MultiBlockProcessResult<F> {
    let mut witness_rows = vec![];
    let mut decoded_bytes: Vec<u8> = vec![];
    let mut literals: Vec<Vec<u64>> = vec![];
    let mut fse_aux_tables: Vec<FseAuxiliaryTableData> = vec![];
    let mut block_info_arr: Vec<BlockInfo> = vec![];
    let mut sequence_info_arr: Vec<SequenceInfo> = vec![];
    let mut address_table_arr: Vec<Vec<AddressTableRow>> = vec![];
    let mut sequence_exec_info_arr: Vec<SequenceExecResult> = vec![];

    // FrameHeaderDescriptor and FrameContentSize
    let (mut byte_offset, rows) = process_frame_header::<F>(
        src,
        0, // frame header starts at offset=0
        &ZstdWitnessRow::init(src.len()),
        randomness,
    );
    witness_rows.extend_from_slice(&rows);

    let mut block_idx: u64 = 1;
    let mut repeated_offset = [1, 4, 8];
    loop {
        let AggregateBlockResult {
            offset,
            witness_rows: rows,
            block_info,
            sequence_info,
            literal_bytes: new_literals,
            fse_aux_tables: new_fse_aux_tables,
            address_table_rows,
            sequence_exec_result,
            repeated_offset: end_repeated_offset,
        } = process_block::<F>(
            src,
            &mut decoded_bytes,
            block_idx,
            byte_offset,
            witness_rows.last().expect("last row expected to exist"),
            randomness,
            repeated_offset,
        );
        log::debug!("processed block={:?}: offset={:?}", block_idx, offset);

        witness_rows.extend_from_slice(&rows);
        literals.push(new_literals);
        for fse_aux_table in new_fse_aux_tables {
            fse_aux_tables.push(fse_aux_table);
        }

        block_info_arr.push(block_info);
        sequence_info_arr.push(sequence_info);
        address_table_arr.push(address_table_rows);
        sequence_exec_info_arr.push(sequence_exec_result);

        if block_info.is_last_block {
            assert!(offset >= src.len());
            break;
        } else {
            repeated_offset = end_repeated_offset;
            block_idx += 1;
            byte_offset = offset;
        }
    }

    MultiBlockProcessResult {
        witness_rows,
        literal_bytes: literals,
        fse_aux_tables,
        block_info_arr,
        sequence_info_arr,
        address_table_rows: address_table_arr,
        sequence_exec_results: sequence_exec_info_arr,
    }
}

#[cfg(test)]
mod tests {
    use eth_types::H256;
    use ethers_core::utils::keccak256;
    use std::{fs, fs::File, io::Write};

    use crate::witgen::init_zstd_encoder;

    #[test]
    #[ignore]
    fn compression_ratio() -> Result<(), std::io::Error> {
        use csv::WriterBuilder;

        let get_compression_ratio = |data: &[u8]| -> Result<(u64, u64, H256), std::io::Error> {
            let raw_len = data.len();
            let compressed = {
                // compression level = 0 defaults to using level=3, which is zstd's default.
                let mut encoder = init_zstd_encoder(None);

                // set source length, which will be reflected in the frame header.
                encoder.set_pledged_src_size(Some(raw_len as u64))?;

                encoder.write_all(data)?;
                encoder.finish()?
            };
            let hash = keccak256(&compressed);
            let compressed_len = compressed.len();
            Ok((raw_len as u64, compressed_len as u64, hash.into()))
        };

        let mut batch_files = fs::read_dir("./data")?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        batch_files.sort();

        let batches = batch_files
            .iter()
            .map(fs::read_to_string)
            .filter_map(|data| data.ok())
            .map(|data| hex::decode(data.trim_end()).expect("Failed to decode hex data"))
            .collect::<Vec<Vec<u8>>>();

        let file = File::create("modified-ratio.csv")?;
        let mut writer = WriterBuilder::new().from_writer(file);

        // Write headers to CSV
        writer.write_record(["ID", "Len(input)", "Compression Ratio"])?;

        // Test and store results in CSV
        for (i, batch) in batches.iter().enumerate() {
            let (raw_len, compr_len, keccak_hash) = get_compression_ratio(batch)?;
            println!(
                "batch{:0>3}, raw_size={:6}, compr_size={:6}, compr_keccak_hash={:64x}",
                i, raw_len, compr_len, keccak_hash
            );

            // Write input and result to CSV
            let compr_ratio = raw_len as f64 / compr_len as f64;
            writer.write_record(&[i.to_string(), raw_len.to_string(), compr_ratio.to_string()])?;
        }

        // Flush the CSV writer
        writer.flush()?;

        Ok(())
    }

    #[test]
    fn test_zstd_witness_processing_batch_data() -> Result<(), std::io::Error> {
        use super::*;
        use halo2_proofs::halo2curves::bn256::Fr;

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

        for raw_input_bytes in batches.into_iter() {
            let compressed = {
                // compression level = 0 defaults to using level=3, which is zstd's default.
                let mut encoder = init_zstd_encoder(None);

                // set source length, which will be reflected in the frame header.
                encoder.set_pledged_src_size(Some(raw_input_bytes.len() as u64))?;

                encoder.write_all(&raw_input_bytes)?;
                encoder.finish()?
            };

            let MultiBlockProcessResult {
                witness_rows: _w,
                literal_bytes: _l,
                fse_aux_tables: _f,
                block_info_arr: _b,
                sequence_info_arr: _s,
                address_table_rows: _a,
                sequence_exec_results,
            } = process::<Fr>(&compressed, Value::known(Fr::from(123456789)));

            let decoded_bytes = sequence_exec_results
                .into_iter()
                .flat_map(|r| r.recovered_bytes)
                .collect::<Vec<u8>>();

            assert!(raw_input_bytes == decoded_bytes);
        }

        Ok(())
    }
}
