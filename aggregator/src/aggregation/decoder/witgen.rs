use std::collections::BTreeMap;

use eth_types::Field;
use ethers_core::k256::pkcs8::der::Sequence;
use halo2_proofs::circuit::Value;

// witgen_debug
use std::{io, io::Write};

mod params;
pub use params::*;

mod types;
pub use types::{ZstdTag::*, *};

pub mod util;
use util::{le_bits_to_value, value_bits_le};

use crate::aggregation::decoder::witgen::util::{be_bits_to_value, increment_idx};

const CMOT_N: u64 = 31;

const TAG_MAX_LEN: [(ZstdTag, u64); 8] = [
    (FrameHeaderDescriptor, 1),
    (FrameContentSize, 8),
    (BlockHeader, 3),
    (ZstdBlockLiteralsHeader, 5),
    (ZstdBlockLiteralsRawBytes, 1048575), // (1 << 20) - 1
    (ZstdBlockSequenceHeader, 4),
    (ZstdBlockFseCode, 128),
    (ZstdBlockSequenceData, 1048575), // (1 << 20) - 1
];

fn lookup_max_tag_len(tag: ZstdTag) -> u64 {
    TAG_MAX_LEN.iter().find(|record| record.0 == tag).unwrap().1
}

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

    // FrameContentSize bytes are read in little-endian, hence its in reverse mode.
    let fcs_bytes = src
        .iter()
        .skip(byte_offset + 1)
        .take(fcs_tag_len)
        // .rev()
        .cloned()
        .collect::<Vec<u8>>();
    let fcs_bytes_rev = src
        .iter()
        .skip(byte_offset + 1)
        .take(fcs_tag_len)
        .rev()
        .cloned()
        .collect::<Vec<u8>>();
    let fcs = {
        let fcs = fcs_bytes_rev
            .iter()
            .fold(0u64, |acc, &byte| acc * 256u64 + (byte as u64));
        match fcs_tag_len {
            2 => fcs + 256,
            _ => fcs,
        }
    };
    let fcs_tag_value_iter = fcs_bytes
        .iter()
        .rev()
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * Value::known(F::from(256u64)) + Value::known(F::from(byte as u64));
            Some(*acc)
        });
    let fcs_tag_value = fcs_tag_value_iter
        .clone()
        .last()
        .expect("FrameContentSize expected");
    let fcs_value_rlcs = fcs_bytes
        .iter()
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        })
        .collect::<Vec<Value<F>>>();

    let tag_rlc_iter = fcs_bytes
        .iter()
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        })
        .collect::<Vec<Value<F>>>();
    let tag_rlc = *(tag_rlc_iter.clone().last().expect("Tag RLC expected"));

    let aux_1 = fcs_value_rlcs
        .last()
        .expect("FrameContentSize bytes expected");
    let aux_2 = fhd_value_rlc;

    (
        byte_offset + 1 + fcs_tag_len,
        std::iter::once(ZstdWitnessRow {
            state: ZstdState {
                tag: ZstdTag::FrameHeaderDescriptor,
                tag_next: ZstdTag::FrameContentSize,
                max_tag_len: lookup_max_tag_len(ZstdTag::FrameHeaderDescriptor),
                tag_len: 1,
                tag_idx: 1,
                tag_value: Value::known(F::from(*fhd_byte as u64)),
                tag_value_acc: Value::known(F::from(*fhd_byte as u64)),
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
            decoded_data: DecodedData {
                decoded_len: fcs,
                decoded_len_acc: 0,
                total_decoded_len: last_row.decoded_data.total_decoded_len + fcs,
                decoded_byte: 0,
                decoded_value_rlc: Value::known(F::zero()),
            },
            bitstream_read_data: BitstreamReadRow::default(),
            fse_data: FseTableRow::default(),
        })
        .chain(
            fcs_bytes_rev
                .iter()
                .zip(fcs_tag_value_iter)
                .zip(fcs_value_rlcs.iter().rev())
                .zip(tag_rlc_iter.iter().rev())
                .enumerate()
                .map(
                    |(i, (((&value_byte, tag_value_acc), _value_rlc), &tag_rlc_acc))| {
                        ZstdWitnessRow {
                            state: ZstdState {
                                tag: ZstdTag::FrameContentSize,
                                tag_next: ZstdTag::BlockHeader,
                                max_tag_len: lookup_max_tag_len(ZstdTag::FrameContentSize),
                                tag_len: fcs_tag_len as u64,
                                tag_idx: (i + 1) as u64,
                                tag_value: fcs_tag_value,
                                tag_value_acc,
                                is_tag_change: i == 0,
                                tag_rlc,
                                tag_rlc_acc,
                            },
                            encoded_data: EncodedData {
                                byte_idx: (byte_offset + 2 + i) as u64,
                                encoded_len: last_row.encoded_data.encoded_len,
                                value_byte,
                                reverse: true,
                                reverse_idx: (fcs_tag_len - i) as u64,
                                reverse_len: fcs_tag_len as u64,
                                aux_1: *aux_1,
                                aux_2,
                                value_rlc: fhd_value_rlc,
                            },
                            decoded_data: DecodedData {
                                decoded_len: fcs,
                                decoded_len_acc: 0,
                                total_decoded_len: last_row.decoded_data.total_decoded_len + fcs,
                                decoded_byte: 0,
                                decoded_value_rlc: Value::known(F::zero()),
                            },
                            bitstream_read_data: BitstreamReadRow::default(),
                            fse_data: FseTableRow::default(),
                        }
                    },
                ),
        )
        .collect::<Vec<_>>(),
    )
}

type AggregateBlockResult<F> = (
    usize,
    Vec<ZstdWitnessRow<F>>,
    bool,
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
    [FseAuxiliaryTableData; 3], // 3 sequence section FSE tables
);
fn process_block<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
) -> AggregateBlockResult<F> {
    let mut witness_rows = vec![];

    let (byte_offset, rows, last_block, block_type, block_size) =
        process_block_header(src, byte_offset, last_row, randomness);
    witness_rows.extend_from_slice(&rows);

    let last_row = rows.last().expect("last row expected to exist");
    let (_byte_offset, rows, literals, lstream_len, aux_data, fse_aux_tables) = match block_type {
        BlockType::ZstdCompressedBlock => process_block_zstd(
            src,
            byte_offset,
            last_row,
            randomness,
            block_size,
            last_block,
        ),
        _ => unreachable!("BlockType::ZstdCompressedBlock expected"),
    };
    witness_rows.extend_from_slice(&rows);

    (
        byte_offset,
        witness_rows,
        last_block,
        literals,
        lstream_len,
        aux_data,
        fse_aux_tables,
    )
}

fn process_block_header<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
) -> (usize, Vec<ZstdWitnessRow<F>>, bool, BlockType, usize) {
    let bh_bytes = src
        .iter()
        .skip(byte_offset)
        .take(N_BLOCK_HEADER_BYTES)
        .cloned()
        .collect::<Vec<u8>>();
    let last_block = (bh_bytes[0] & 1) == 1;
    let block_type = BlockType::from((bh_bytes[0] >> 1) & 3);
    let block_size =
        (bh_bytes[2] as usize * 256 * 256 + bh_bytes[1] as usize * 256 + bh_bytes[0] as usize) >> 3;

    let tag_next = match block_type {
        BlockType::ZstdCompressedBlock => ZstdTag::ZstdBlockLiteralsHeader,
        _ => unreachable!("BlockType::ZstdCompressedBlock expected"),
    };

    let tag_value_iter = bh_bytes
        .iter()
        .rev()
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * Value::known(F::from(256u64)) + Value::known(F::from(byte as u64));
            Some(*acc)
        });
    let tag_value = tag_value_iter.clone().last().expect("BlockHeader expected");

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

    // BlockHeader follows FrameContentSize which is processed in reverse order.
    // Hence value_rlc at the first BlockHeader byte will be calculated as:
    //
    // value_rlc::cur == aux_1::prev * (rand ^ reverse_len) * rand
    //      + aux_2::prev * rand
    //      + value_byte::cur
    let acc_start = last_row.encoded_data.aux_1
        * randomness.map(|r| r.pow([last_row.encoded_data.reverse_len, 0, 0, 0]))
        + last_row.encoded_data.aux_2;
    let _value_rlcs = bh_bytes
        .iter()
        .scan(acc_start, |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        })
        .collect::<Vec<Value<F>>>();

    (
        byte_offset + N_BLOCK_HEADER_BYTES,
        bh_bytes
            .iter()
            .rev()
            .zip(tag_value_iter)
            .zip(tag_rlc_iter.iter().rev())
            .enumerate()
            .map(
                |(i, ((&value_byte, tag_value_acc), tag_rlc_acc))| ZstdWitnessRow {
                    state: ZstdState {
                        tag: ZstdTag::BlockHeader,
                        tag_next,
                        max_tag_len: lookup_max_tag_len(ZstdTag::BlockHeader),
                        tag_len: N_BLOCK_HEADER_BYTES as u64,
                        tag_idx: (i + 1) as u64,
                        tag_value,
                        tag_value_acc,
                        is_tag_change: i == 0,
                        tag_rlc,
                        tag_rlc_acc: *tag_rlc_acc,
                    },
                    encoded_data: EncodedData {
                        byte_idx: (byte_offset + i + 1) as u64,
                        encoded_len: last_row.encoded_data.encoded_len,
                        value_byte,
                        reverse: true,
                        value_rlc,
                        ..Default::default()
                    },
                    bitstream_read_data: BitstreamReadRow::default(),
                    decoded_data: last_row.decoded_data.clone(),
                    fse_data: FseTableRow::default(),
                },
            )
            .collect::<Vec<_>>(),
        last_block,
        block_type,
        block_size,
    )
}

type BlockProcessingResult<F> = (
    usize,
    Vec<ZstdWitnessRow<F>>,
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
    [FseAuxiliaryTableData; 3], // 3 sequence section FSE tables
);

type LiteralsBlockResult<F> = (usize, Vec<ZstdWitnessRow<F>>, Vec<u64>, Vec<u64>, Vec<u64>);

#[allow(unused_variables)]
fn process_block_zstd<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    block_size: usize,
    last_block: bool,
) -> BlockProcessingResult<F> {
    let end_offset = byte_offset + block_size;
    let mut witness_rows = vec![];

    // 1-5 bytes LiteralSectionHeader
    let literals_header_result: LiteralsHeaderProcessingResult<F> =
        process_block_zstd_literals_header::<F>(src, byte_offset, last_row, randomness);
    let (
        byte_offset,
        rows,
        _literals_block_type,
        n_streams,
        regen_size,
        compressed_size,
        (branch, sf_max),
    ) = literals_header_result;

    witness_rows.extend_from_slice(&rows);

    let literals_block_result: LiteralsBlockResult<F> = {
        let tag = ZstdTag::ZstdBlockLiteralsRawBytes;
        let tag_next = ZstdTag::ZstdBlockSequenceHeader;
        let literals = src[byte_offset..(byte_offset + regen_size)].to_vec();
        let value_rlc_iter = literals
            .iter()
            .scan(last_row.encoded_data.value_rlc, |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            });
        let decoded_value_rlc_iter =
            literals
                .iter()
                .scan(last_row.decoded_data.decoded_value_rlc, |acc, &byte| {
                    *acc = *acc * randomness + Value::known(F::from(byte as u64));
                    Some(*acc)
                });
        let tag_value_iter = literals.iter().scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        });
        let tag_value = tag_value_iter.clone().last().expect("Literals must exist.");
        let tag_rlc_iter = literals.iter().scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        });
        let tag_rlc = tag_value_iter.clone().last().expect("Literals must exist.");

        (
            byte_offset + regen_size,
            literals
                .iter()
                .zip(tag_value_iter)
                .zip(value_rlc_iter)
                .zip(decoded_value_rlc_iter)
                .zip(tag_rlc_iter)
                .enumerate()
                .map(
                    |(
                        i,
                        (
                            (((&value_byte, tag_value_acc), value_rlc), decoded_value_rlc),
                            tag_rlc_acc,
                        ),
                    )| {
                        ZstdWitnessRow {
                            state: ZstdState {
                                tag,
                                tag_next,
                                max_tag_len: lookup_max_tag_len(tag),
                                tag_len: regen_size as u64,
                                tag_idx: (i + 1) as u64,
                                tag_value,
                                tag_value_acc,
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
                                decoded_len_acc: last_row.decoded_data.decoded_len + (i as u64) + 1,
                                total_decoded_len: last_row.decoded_data.total_decoded_len,
                                decoded_byte: value_byte,
                                decoded_value_rlc,
                            },
                            bitstream_read_data: BitstreamReadRow::default(),
                            fse_data: FseTableRow::default(),
                        }
                    },
                )
                .collect::<Vec<_>>(),
            literals.iter().map(|b| *b as u64).collect::<Vec<u64>>(),
            vec![regen_size as u64, 0, 0, 0],
            vec![0, 0, 0, 0],
        )
    };

    let (byte_offset, rows, literals, lstream_len, aux_data) = literals_block_result;
    witness_rows.extend_from_slice(&rows);

    let last_row = witness_rows.last().expect("last row expected to exist");
    let (bytes_offset, rows, fse_aux_tables, address_table_rows) =
        process_sequences::<F>(src, byte_offset, end_offset, last_row, randomness);
    witness_rows.extend_from_slice(&rows);

    (
        bytes_offset,
        witness_rows,
        literals,
        lstream_len,
        vec![
            regen_size as u64,
            compressed_size as u64,
            aux_data[0],
            aux_data[1],
            aux_data[2],
            aux_data[3],
            branch,
            sf_max as u64,
        ],
        fse_aux_tables,
    )
}

type SequencesProcessingResult<F> = (
    usize,
    Vec<ZstdWitnessRow<F>>,
    [FseAuxiliaryTableData; 3], // LLT, MLT, CMOT
    Vec<AddressTableRow>,
);

fn process_sequences<F: Field>(
    src: &[u8],
    byte_offset: usize,
    end_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
) -> SequencesProcessingResult<F> {
    // Initialize witness rows
    let mut witness_rows: Vec<ZstdWitnessRow<F>> = vec![];

    // Other consistent values
    let encoded_len = last_row.encoded_data.encoded_len;
    let decoded_data = last_row.decoded_data.clone();

    // First, process the sequence header
    let byte0 = src
        .get(byte_offset)
        .expect("First byte of sequence header must exist.")
        .clone();
    assert!(byte0 > 0u8, "Sequences can't be of 0 length");

    let (_num_of_sequences, num_sequence_header_bytes) = if byte0 < 128 {
        (byte0 as u64, 2usize)
    } else {
        let byte1 = src
            .get(byte_offset + 1)
            .expect("Next byte of sequence header must exist.")
            .clone();
        if byte0 < 255 {
            ((((byte0 - 128) as u64) << 8) + byte1 as u64, 3)
        } else {
            let byte2 = src
                .get(byte_offset + 2)
                .expect("Third byte of sequence header must exist.")
                .clone();
            ((byte1 as u64) + ((byte2 as u64) << 8) + 0x7F00, 4)
        }
    };

    // witgen_debug
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let compression_mode_byte = src
        .get(byte_offset + num_sequence_header_bytes - 1)
        .expect("Compression mode byte must exist.")
        .clone();
    let mode_bits = value_bits_le(compression_mode_byte);

    let literal_lengths_mode = mode_bits[6] + mode_bits[7] * 2;
    let offsets_mode = mode_bits[4] + mode_bits[5] * 2;
    let match_lengths_mode = mode_bits[2] + mode_bits[3] * 2;
    let reserved = mode_bits[0] + mode_bits[1] * 2;

    assert!(reserved == 0, "Reserved bits must be 0");

    // TODO: Treatment of other encoding modes
    assert!(
        literal_lengths_mode == 2,
        "Only FSE_Compressed_Mode is allowed"
    );
    assert!(offsets_mode == 2, "Only FSE_Compressed_Mode is allowed");
    assert!(
        match_lengths_mode == 2,
        "Only FSE_Compressed_Mode is allowed"
    );

    // witgen_debug. TODO: Add rows for the header

    // Second, process the sequence tables (encoded using FSE)
    let byte_offset = byte_offset + num_sequence_header_bytes;

    // Literal Length Table (LLT)
    let (n_fse_bytes_llt, bit_boundaries_llt, table_llt) =
        FseAuxiliaryTableData::reconstruct(src, byte_offset)
            .expect("Reconstructing FSE-packed Literl Length (LL) table should not fail.");
    let llt = table_llt.parse_state_table();
    let al_llt = bit_boundaries_llt
        .first()
        .expect("Accuracy Log should exist")
        .1
        + 5;

    // Cooked Match Offset Table (CMOT)
    let byte_offset = byte_offset + n_fse_bytes_llt;
    let (n_fse_bytes_cmot, bit_boundaries_cmot, table_cmot) =
        FseAuxiliaryTableData::reconstruct(src, byte_offset)
            .expect("Reconstructing FSE-packed Cooked Match Offset (CMO) table should not fail.");
    let cmot = table_cmot.parse_state_table();
    let al_cmot = bit_boundaries_cmot
        .first()
        .expect("Accuracy Log should exist")
        .1
        + 5;

    // Match Length Table (MLT)
    let byte_offset = byte_offset + n_fse_bytes_cmot;
    let (n_fse_bytes_mlt, bit_boundaries_mlt, table_mlt) =
        FseAuxiliaryTableData::reconstruct(src, byte_offset)
            .expect("Reconstructing FSE-packed Match Length (ML) table should not fail.");
    let mlt = table_mlt.parse_state_table();
    let al_mlt = bit_boundaries_mlt
        .first()
        .expect("Accuracy Log should exist")
        .1
        + 5;

    // TODO: Add FSE witness rows

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
    let mut num_emitted: usize = 0;
    let n_sequence_data_bytes = end_offset - byte_offset;
    let mut last_byte_idx: usize = 1;
    let mut current_byte_idx: usize = 1;
    let mut current_bit_idx: usize = 0;

    // Update the last row
    let multiplier =
        (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
    let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

    let value_rlc_iter =
        &src[byte_offset..end_offset]
            .iter()
            .scan(Value::known(F::zero()), |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            });
    let mut value_rlc_iter = value_rlc_iter
        .clone()
        .collect::<Vec<Value<F>>>()
        .into_iter()
        .rev();

    let tag_value_iter =
        &src[byte_offset..end_offset]
            .iter()
            .scan(Value::known(F::zero()), |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            });
    let tag_value = tag_value_iter.clone().last().expect("Tag value must exist");
    let mut tag_value_iter = tag_value_iter
        .clone()
        .collect::<Vec<Value<F>>>()
        .into_iter()
        .rev();

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

    let mut next_tag_value_acc = tag_value_iter.next().unwrap();
    let next_value_rlc_acc = value_rlc_iter.next().unwrap();
    let mut next_tag_rlc_acc = tag_rlc_iter.next().unwrap();

    let aux_1 = next_value_rlc_acc;
    // witgen_debug
    // let aux_2 = witness_rows[witness_rows.len() - 1].encoded_data.value_rlc;

    let mut padding_end_idx = 0;
    while sequence_bitstream[padding_end_idx] == 0 {
        padding_end_idx += 1;
    }

    // Add a witness row for leading 0s and the sentinel 1-bit
    witness_rows.push(ZstdWitnessRow {
        state: ZstdState {
            tag: ZstdTag::ZstdBlockSequenceData,
            tag_next: ZstdTag::ZstdBlockSequenceData, // witgen_debug
            max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockSequenceData),
            tag_len: n_sequence_data_bytes as u64,
            tag_idx: 1_u64,
            tag_value,
            tag_value_acc: next_tag_value_acc,
            is_tag_change: true,
            tag_rlc,
            tag_rlc_acc: next_tag_rlc_acc,
        },
        encoded_data: EncodedData {
            byte_idx: (byte_offset + current_byte_idx) as u64,
            encoded_len,
            value_byte: src[byte_offset + current_byte_idx],
            value_rlc,
            reverse: true,
            reverse_len: n_sequence_data_bytes as u64,
            reverse_idx: (n_sequence_data_bytes - (current_byte_idx - 1)) as u64,
            aux_1,
            aux_2: Value::known(F::zero()), // witgen_debug
        },
        bitstream_read_data: BitstreamReadRow {
            bit_start_idx: 0usize,
            bit_end_idx: padding_end_idx,
            bit_value: 1u64,
            is_zero_bit_read: false,
        },
        decoded_data: last_row.decoded_data.clone(),
        fse_data: FseTableRow::default(),
    });

    // Exclude the leading zero section
    while sequence_bitstream[current_bit_idx] == 0 {
        (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
    }
    // Exclude the sentinel 1-bit
    (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);

    // Update accumulators
    if current_byte_idx > last_byte_idx {
        next_tag_value_acc = tag_value_iter.next().unwrap();
        next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
        last_byte_idx = current_byte_idx;
    }

    // Now the actual data-bearing bitstream starts
    // The sequence bitstream is interleaved by 6 bit processing strands.
    // The interleaving order is: CMOVBits, MLVBits, LLVBits, LLFBits, MLFBits, CMOFBits
    let mut decoded_bitstring_values: Vec<(SequenceDataTag, u64)> = vec![];
    let mut raw_sequence_instructions: Vec<(usize, usize, usize)> = vec![]; // offset_state, match_length, literal_length
    let mut curr_instruction: [usize; 3] = [0, 0, 0];

    // Note: mode and order_idx produces 6 distinct decoding state
    let mut mode: usize = 1; // use 0 or 1 to denote whether bitstream produces data or next decoding state
    let mut order_idx: usize = 0; // use 0, 1, 2 to denote the order of decoded value within current mode

    let mut state_baselines: [usize; 3] = [0, 0, 0]; // 3 states for LL, ML, CMO
    let mut decoding_baselines: [usize; 3] = [0, 0, 0]; // 3 decoding bl for CMO, ML, LL

    let data_tags = [
        SequenceDataTag::CookedMatchOffset_Value,
        SequenceDataTag::MatchLength_Value,
        SequenceDataTag::LiteralLength_Value,
        SequenceDataTag::LiteralLength_FSE,
        SequenceDataTag::MatchLength_FSE,
        SequenceDataTag::CookedMatchOffset_FSE,
    ];
    let next_nb_to_read_for_states: [usize; 3] =
        [al_llt as usize, al_mlt as usize, al_cmot as usize]; // Obtained from accuracy log
    let next_nb_to_read_for_values: [usize; 3] = [0, 0, 0];
    let mut nb_switch = [next_nb_to_read_for_values, next_nb_to_read_for_states];
    let v_tables = [cmotv, mltv, lltv];
    let f_tables = [llt, mlt, cmot];

    let mut is_init = true;
    let mut nb = nb_switch[mode][order_idx];
    while current_bit_idx + nb <= n_sequence_data_bytes * N_BITS_PER_BYTE {
        let bitstring_value =
            be_bits_to_value(&sequence_bitstream[current_bit_idx..(current_bit_idx + nb)]);

        let new_decoded = (data_tags[mode * 3 + order_idx], bitstring_value);
        decoded_bitstring_values.push(new_decoded);

        if mode > 0 {
            // For the initial baseline determination, ML and CMO positions are flipped.
            if is_init {
                order_idx = [0, 2, 1][order_idx];
            }

            // FSE state update step
            let new_state = (state_baselines[order_idx] as u64) + bitstring_value;
            let new_state_params = f_tables[order_idx]
                .get(&new_state)
                .expect("State should exist.");
            let state_symbol = new_state_params.0;

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

            order_idx += 1;

            if order_idx > 2 {
                is_init = false;
                mode = 0; // switch to data mode
                order_idx = 0;
            }
        } else {
            // Value decoding step
            let new_value = (decoding_baselines[order_idx] as u64) + bitstring_value;
            curr_instruction[order_idx] = new_value as usize;

            order_idx += 1;

            if order_idx > 2 {
                mode = 1; // switch to FSE mode
                order_idx = 0;

                // Add the instruction
                let new_instruction = (
                    curr_instruction[0],
                    curr_instruction[1],
                    curr_instruction[2],
                );

                raw_sequence_instructions.push(new_instruction);
            }
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
                tag_next: ZstdTag::ZstdBlockSequenceData, // witgen_debug
                max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockSequenceData),
                tag_len: n_sequence_data_bytes as u64,
                tag_idx: current_byte_idx as u64,
                tag_value,
                tag_value_acc: next_tag_value_acc,
                is_tag_change: true,
                tag_rlc,
                tag_rlc_acc: next_tag_rlc_acc,
            },
            encoded_data: EncodedData {
                byte_idx: (byte_offset + current_byte_idx) as u64,
                encoded_len,
                // value_byte: src[byte_offset + current_byte_idx], // witgen_debug, idx overflow
                value_byte: src[0], // TODO
                value_rlc,
                reverse: true,
                reverse_len: n_sequence_data_bytes as u64,
                reverse_idx: (n_sequence_data_bytes - (current_byte_idx - 1)) as u64,
                aux_1,
                aux_2: Value::known(F::zero()), // witgen_debug
            },
            bitstream_read_data: BitstreamReadRow {
                bit_start_idx: from_bit_idx,
                bit_end_idx: to_bit_idx,
                bit_value: bitstring_value,
                is_zero_bit_read: (nb == 0),
            },
            decoded_data: last_row.decoded_data.clone(),
            fse_data: FseTableRow::default(), // TODO: Clarify alternating FSE/data segments
        });

        for _ in 0..nb {
            (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
        }
        if current_byte_idx > last_byte_idx && current_byte_idx <= n_sequence_data_bytes {
            next_tag_value_acc = tag_value_iter.next().unwrap();
            next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
            last_byte_idx = current_byte_idx;
        }

        if is_init {
            // On the first step, ML and CMO are flipped
            let true_idx = [0, 2, 1][order_idx];
            nb = nb_switch[mode][true_idx];
        } else {
            nb = nb_switch[mode][order_idx];
        }
    }

    // witgen_debug
    write!(
        handle,
        "raw_sequence_instructions: {:?}",
        raw_sequence_instructions
    )
    .unwrap();
    writeln!(handle).unwrap();

    // Process raw sequence instructions
    let mut address_table_rows: Vec<AddressTableRow> = vec![];
    let mut literal_len_acc: usize = 0;
    let mut repeated_offset: [usize; 3] = [1, 4, 8];

    for (idx, inst) in raw_sequence_instructions.iter().enumerate() {
        let actual_offset = if inst.0 > 3 {
            inst.0 - 3
        } else {
            let mut repeat_idx = inst.0;
            if inst.2 == 0 {
                repeat_idx += 1;
                if repeat_idx > 3 {
                    repeat_idx = 1;
                }
            }

            repeated_offset[repeat_idx]
        } as u64;

        literal_len_acc += inst.2;

        // TODO: Address table rows are not padded right now. witgen_debug
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

        // Update repeated offset
        if inst.0 > 3 {
            repeated_offset[2] = repeated_offset[1];
            repeated_offset[1] = repeated_offset[0];
            repeated_offset[0] = inst.0 - 3;
        } else {
            let mut repeat_idx = inst.0;
            if inst.2 == 0 {
                repeat_idx += 1;
                if repeat_idx > 3 {
                    repeat_idx = 1;
                }
            }

            if repeat_idx == 2 {
                let result = repeated_offset[1];
                repeated_offset[1] = repeated_offset[0];
                repeated_offset[0] = result;
            } else if repeat_idx == 3 {
                let result = repeated_offset[2];
                repeated_offset[2] = repeated_offset[1];
                repeated_offset[1] = repeated_offset[0];
                repeated_offset[0] = result;
            } else {
                // repeat 1
            }
        };
    }

    (
        end_offset,
        witness_rows,
        [table_llt, table_mlt, table_cmot],
        address_table_rows,
    )
}

type LiteralsHeaderProcessingResult<F> = (
    usize,
    Vec<ZstdWitnessRow<F>>,
    BlockType,
    usize,
    usize,
    usize,
    (u64, bool),
);

fn process_block_zstd_literals_header<F: Field>(
    src: &[u8],
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
    let sf_max = size_format == 3;

    let [n_bits_fmt, n_bits_regen, n_bits_compressed, n_streams, n_bytes_header, branch]: [usize;
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

    let regen_size = le_bits_to_value(&sizing_bits[0..n_bits_regen]);
    let compressed_size =
        le_bits_to_value(&sizing_bits[n_bits_regen..(n_bits_regen + n_bits_compressed)]);

    let tag_next = match literals_block_type {
        BlockType::RawBlock => ZstdTag::ZstdBlockLiteralsRawBytes,
        _ => unreachable!("BlockType::* unexpected. Must be raw bytes for literals."),
    };

    let tag_value_iter =
        lh_bytes
            .iter()
            .take(n_bytes_header)
            .scan(Value::known(F::zero()), |acc, &byte| {
                *acc = *acc * Value::known(F::from(256u64)) + Value::known(F::from(byte as u64));
                Some(*acc)
            });
    let tag_value = tag_value_iter
        .clone()
        .last()
        .expect("LiteralsHeader expected");

    let tag_rlc_iter =
        lh_bytes
            .iter()
            .take(n_bytes_header)
            .scan(Value::known(F::zero()), |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            });
    let tag_rlc = tag_rlc_iter.clone().last().expect("Tag RLC expected");

    let value_rlc_iter =
        lh_bytes
            .iter()
            .take(n_bytes_header)
            .scan(last_row.encoded_data.value_rlc, |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            });

    let multiplier =
        (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
    let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

    (
        byte_offset + n_bytes_header,
        lh_bytes
            .iter()
            .take(n_bytes_header)
            .zip(tag_value_iter)
            .zip(value_rlc_iter)
            .zip(tag_rlc_iter)
            .enumerate()
            .map(
                |(i, (((&value_byte, tag_value_acc), _v_rlc), tag_rlc_acc))| ZstdWitnessRow {
                    state: ZstdState {
                        tag: ZstdTag::ZstdBlockLiteralsHeader,
                        tag_next,
                        max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockLiteralsHeader),
                        tag_len: n_bytes_header as u64,
                        tag_idx: (i + 1) as u64,
                        tag_value,
                        tag_value_acc,
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
                    fse_data: FseTableRow::default(),
                },
            )
            .collect::<Vec<_>>(),
        literals_block_type,
        n_streams,
        regen_size as usize,
        compressed_size as usize,
        (branch as u64, sf_max),
    )
}

/// Result for processing multiple blocks from compressed data
pub type MultiBlockProcessResult<F> = (
    Vec<ZstdWitnessRow<F>>,
    Vec<u64>,
    Vec<u64>,
    Vec<FseAuxiliaryTableData>,
);

/// Process a slice of bytes into decompression circuit witness rows
pub fn process<F: Field>(src: &[u8], randomness: Value<F>) -> MultiBlockProcessResult<F> {
    let mut witness_rows = vec![];
    let mut literals: Vec<u64> = vec![];
    let mut aux_data: Vec<u64> = vec![];
    let mut fse_aux_tables: Vec<FseAuxiliaryTableData> = vec![];
    let byte_offset = 0;

    // FrameHeaderDescriptor and FrameContentSize
    let (byte_offset, rows) = process_frame_header::<F>(
        src,
        byte_offset,
        &ZstdWitnessRow::init(src.len()),
        randomness,
    );
    witness_rows.extend_from_slice(&rows);

    loop {
        let (
            _byte_offset,
            rows,
            last_block,
            new_literals,
            lstream_lens,
            pipeline_data,
            new_fse_aux_tables,
        ) = process_block::<F>(
            src,
            byte_offset,
            rows.last().expect("last row expected to exist"),
            randomness,
        );
        witness_rows.extend_from_slice(&rows);
        literals.extend_from_slice(&new_literals);
        aux_data.extend_from_slice(&lstream_lens);
        aux_data.extend_from_slice(&pipeline_data);
        for fse_aux_table in new_fse_aux_tables {
            fse_aux_tables.push(fse_aux_table);
        }

        if last_block {
            // TODO: Recover this assertion after the sequence section decoding is completed.
            // assert!(byte_offset >= src.len());
            break;
        }
    }

    (witness_rows, literals, aux_data, fse_aux_tables)
}

#[cfg(test)]
mod tests {
    // witgen_debug
    use super::*;
    // use bitstream_io::write;
    // use halo2_proofs::halo2curves::bn256::Fr;
    // use serde_json::from_str;

    use std::{
        fs::{self, File},
        // witgen_debug
        // io::{self, Write},
    };

    // witgen_debug
    // #[test]
    // #[ignore]
    // fn compression_ratio() -> Result<(), std::io::Error> {
    //     use csv::WriterBuilder;
    //     use super::*;

    //     let get_compression_ratio = |data: &[u8]| -> Result<(u64, u64, H256), std::io::Error> {
    //         let raw_len = data.len();
    //         let compressed = {
    //             // compression level = 0 defaults to using level=3, which is zstd's default.
    //             let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0)?;

    //             // disable compression of literals, i.e. literals will be raw bytes.
    //             encoder.set_parameter(zstd::stream::raw::CParameter::LiteralCompressionMode(
    //                 zstd::zstd_safe::ParamSwitch::Disable,
    //             ))?;
    //             // set target block size to fit within a single block.
    //             encoder
    //                 .set_parameter(zstd::stream::raw::CParameter::TargetCBlockSize(124 * 1024))?;
    //             // do not include the checksum at the end of the encoded data.
    //             encoder.include_checksum(false)?;
    //             // do not include magic bytes at the start of the frame since we will have a
    // single             // frame.
    //             encoder.include_magicbytes(false)?;
    //             // set source length, which will be reflected in the frame header.
    //             encoder.set_pledged_src_size(Some(raw_len as u64))?;
    //             // include the content size to know at decode time the expected size of decoded
    //             // data.
    //             encoder.include_contentsize(true)?;

    //             encoder.write_all(data)?;
    //             encoder.finish()?
    //         };
    //         let hash = keccak256(&compressed);
    //         let compressed_len = compressed.len();
    //         Ok((raw_len as u64, compressed_len as u64, hash.into()))
    //     };

    //     let mut batch_files = fs::read_dir("./data")?
    //         .map(|entry| entry.map(|e| e.path()))
    //         .collect::<Result<Vec<_>, std::io::Error>>()?;
    //     batch_files.sort();

    //     let batches = batch_files
    //         .iter()
    //         .map(fs::read_to_string)
    //         .filter_map(|data| data.ok())
    //         .map(|data| hex::decode(data.trim_end()).expect("Failed to decode hex data"))
    //         .collect::<Vec<Vec<u8>>>();

    //     let file = File::create("modified-ratio.csv")?;
    //     let mut writer = WriterBuilder::new().from_writer(file);

    //     // Write headers to CSV
    //     writer.write_record(["ID", "Len(input)", "Compression Ratio"])?;

    //     // Test and store results in CSV
    //     for (i, batch) in batches.iter().enumerate() {
    //         let (raw_len, compr_len, keccak_hash) = get_compression_ratio(batch)?;
    //         println!(
    //             "batch{:0>3}, raw_size={:6}, compr_size={:6}, compr_keccak_hash={:64x}",
    //             i, raw_len, compr_len, keccak_hash
    //         );

    //         // Write input and result to CSV
    //         let compr_ratio = raw_len as f64 / compr_len as f64;
    //         writer.write_record(&[i.to_string(), raw_len.to_string(), compr_ratio.to_string()])?;
    //     }

    //     // Flush the CSV writer
    //     writer.flush()?;

    //     Ok(())
    // }

    #[test]
    fn batch_compression_zstd() -> Result<(), std::io::Error> {
        use halo2_proofs::halo2curves::bn256::Fr;
        use hex::FromHex;

        use super::*;
        let raw = <Vec<u8>>::from_hex(r#"0100000000000231fb0000000064e588f7000000000000000000000000000000000000000000000000000000000000000000000000007a12000006000000000219f90216038510229a150083039bd49417afd0263d6909ba1f9a8eac697f76532365fb95880234e1a857498000b901a45ae401dc0000000000000000000000000000000000000000000000000000000064e58a1400000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e404e45aaf0000000000000000000000005300000000000000000000000000000000000004000000000000000000000000d9692f1748afee00face2da35242417dd05a86150000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000c3100d07a5997a7f9f9cdde967d396f9a2aed6a60000000000000000000000000000000000000000000000000234e1a8574980000000000000000000000000000000000000000000000000049032ac61d5dce9e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000083104ec1a053077484b4d7a88434c2d03c30c3c55bd3a82b259f339f1c0e1e1244189009c5a01c915dd14aed1b824bf610a95560e380ea3213f0bf345df3bddff1acaf7da84d000002d8f902d5068510229a1500830992fd94bbad0e891922a8a4a7e9c39d4cc0559117016fec87082b6be7f5b757b90264ac9650d800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000164883164560000000000000000000000005300000000000000000000000000000000000004000000000000000000000000ffd2ece82f7959ae184d10fe17865d27b4f0fb9400000000000000000000000000000000000000000000000000000000000001f4fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffce9f6fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcea0a00000000000000000000000000000000000000000000000000082b6be7f5b75700000000000000000000000000000000000000000000000000000000004c4b40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006aea61ea08dd6e4834cd43a257ed52d9a31dd3b90000000000000000000000000000000000000000000000000000000064e58a1400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000412210e8a0000000000000000000000000000000000000000000000000000000083104ec2a0bc501c59bceb707d958423bad14c0d0daec84ad067f7e42209ad2cb8d904a55da00a04de4c79ed24b7a82d523b5de63c7ff68a3b7bb519546b3fe4ba8bc90a396600000137f9013480850f7eb06980830317329446ce46951d12710d85bc4fe10bb29c6ea501207787019945ca262000b8c4b2dd898a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000065e4e8d7bd50191abfee6e5bcdc4d16ddfe9975e000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000083104ec2a037979a5225dd156f51abf9a8601e9156e1b1308c0474d69af98c55627886232ea048ac197295187e7ad48aa34cc37c2625434fa812449337732d8522014f4eacfc00000137f9013480850f7eb06980830317329446ce46951d12710d85bc4fe10bb29c6ea501207787019945ca262000b8c4b2dd898a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000065e4e8d7bd50191abfee6e5bcdc4d16ddfe9975e000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000083104ec1a087269dbb9e987e5d58ecd3bcb724cbc4e6c843eb9095de16a25263aebfe06f5aa07f3ac49b6847ba51c5319174e51e088117742240f8555c5c1d77108cf0df90d700000137f9013480850f7eb06980830317329446ce46951d12710d85bc4fe10bb29c6ea501207787019945ca262000b8c4b2dd898a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000065e4e8d7bd50191abfee6e5bcdc4d16ddfe9975e000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000083104ec1a04abdb8572dcabf1996825de6f753124eed41c1292fcfdc4d9a90cb4f8a0f8ff1a06ef25857e2cc9d0fa8b6ecc03b4ba6ef6f3ec1515d570fcc9102e2aa653f347a00000137f9013480850f7eb06980830317329446ce46951d12710d85bc4fe10bb29c6ea501207787019945ca262000b8c4b2dd898a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000065e4e8d7bd50191abfee6e5bcdc4d16ddfe9975e000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000083104ec2a0882202163cbb9a299709b443b663fbab459440deabfbe183e999c98c00ea80c2a010ecb1e5196f0b1ee3d067d9a158b47b1376706e42ce2e769cf8e986935781dd"#)
            .expect("FromHex failure");

        let compressed = {
            // compression level = 0 defaults to using level=3, which is zstd's default.
            let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0)?;

            // disable compression of literals, i.e. literals will be raw bytes.
            encoder.set_parameter(zstd::stream::raw::CParameter::LiteralCompressionMode(
                zstd::zstd_safe::ParamSwitch::Disable,
            ))?;
            // set target block size to fit within a single block.
            encoder.set_parameter(zstd::stream::raw::CParameter::TargetCBlockSize(124 * 1024))?;
            // do not include the checksum at the end of the encoded data.
            encoder.include_checksum(false)?;
            // do not include magic bytes at the start of the frame since we will have a single
            // frame.
            encoder.include_magicbytes(false)?;
            // set source length, which will be reflected in the frame header.
            encoder.set_pledged_src_size(Some(raw.len() as u64))?;
            // include the content size to know at decode time the expected size of decoded data.
            encoder.include_contentsize(true)?;

            encoder.write_all(&raw)?;
            encoder.finish()?
        };

        let (_witness_rows, _decoded_literals, _aux_data, _fse_aux_tables) =
            process::<Fr>(&compressed, Value::known(Fr::from(123456789)));

        Ok(())
    }

    // witgen_debug
    #[test]
    fn batch_compression_zstd_working_example() -> Result<(), std::io::Error> {
        use super::*;
        use halo2_proofs::halo2curves::bn256::Fr;
        use hex::FromHex;

        // witgen_debug
        let raw: Vec<u8> = String::from("Romeo and Juliet@Excerpt from Act 2, Scene 2@@JULIET@O Romeo, Romeo! wherefore art thou Romeo?@Deny thy father and refuse thy name;@Or, if thou wilt not, be but sworn my love,@And I'll no longer be a Capulet.@@ROMEO@[Aside] Shall I hear more, or shall I speak at this?@@JULIET@'Tis but thy name that is my enemy;@Thou art thyself, though not a Montague.@What's Montague? it is nor hand, nor foot,@Nor arm, nor face, nor any other part@Belonging to a man. O, be some other name!@What's in a name? that which we call a rose@By any other name would smell as sweet;@So Romeo would, were he not Romeo call'd,@Retain that dear perfection which he owes@Without that title. Romeo, doff thy name,@And for that name which is no part of thee@Take all myself.@@ROMEO@I take thee at thy word:@Call me but love, and I'll be new baptized;@Henceforth I never will be Romeo.@@JULIET@What man art thou that thus bescreen'd in night@So stumblest on my counsel?").as_bytes().to_vec();

        let compressed = {
            let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0)?;

            // disable compression of literals, i.e. literals will be raw bytes.
            encoder.set_parameter(zstd::stream::raw::CParameter::LiteralCompressionMode(
                zstd::zstd_safe::ParamSwitch::Disable,
            ))?;
            // set target block size to fit within a single block.
            encoder.set_parameter(zstd::stream::raw::CParameter::TargetCBlockSize(124 * 1024))?;
            // set source length, which will be reflected in the frame header.
            encoder.set_pledged_src_size(Some(raw.len() as u64))?;
            // do not include the checksum at the end of the encoded data.
            encoder.include_checksum(false)?;
            // do not include magic bytes at the start of the frame since we will have a single
            // frame.
            encoder.include_magicbytes(false)?;
            // include the content size to know at decode time the expected size of decoded data.
            encoder.include_contentsize(true)?;

            encoder.write_all(&raw)?;
            encoder.finish()?
        };

        let (_witness_rows, _decoded_literals, _aux_data, _fse_aux_tables) =
            process::<Fr>(&compressed, Value::known(Fr::from(123456789)));

        Ok(())
    }
}
