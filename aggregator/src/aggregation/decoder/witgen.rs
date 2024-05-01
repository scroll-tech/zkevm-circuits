use std::collections::BTreeMap;

use eth_types::Field;
use halo2_proofs::circuit::Value;

mod params;
pub use params::*;

mod types;
pub use types::{ZstdTag::*, *};

pub mod util;
use util::{be_bits_to_value, increment_idx, le_bits_to_value, value_bits_le};

use crate::aggregation::decoder::tables::FseTableKind;

const TAG_MAX_LEN: [(ZstdTag, u64); 13] = [
    (FrameHeaderDescriptor, 1),
    (FrameContentSize, 8),
    (BlockHeader, 3),
    (RawBlockBytes, 8388607), // (1 << 23) - 1
    (RleBlockBytes, 8388607),
    (ZstdBlockLiteralsHeader, 5),
    (ZstdBlockLiteralsRawBytes, 1048575), // (1 << 20) - 1
    (ZstdBlockLiteralsRleBytes, 1048575),
    (ZstdBlockLiteralsHeader, 5),
    (ZstdBlockFseCode, 128),
    (ZstdBlockHuffmanCode, 128), // header_byte < 128
    (ZstdBlockJumpTable, 6),
    (ZstdBlockLstream, 1000), // 1kB hard-limit
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
            huffman_data: HuffmanData::default(),
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
                            huffman_data: HuffmanData::default(),
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
    FseAuxiliaryTableData,
    HuffmanCodesData,
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
    let (_byte_offset, rows, literals, lstream_len, aux_data, fse_aux_table, huffman_codes) =
        match block_type {
            BlockType::RawBlock => process_block_raw(
                src,
                byte_offset,
                last_row,
                randomness,
                block_size,
                last_block,
            ),
            BlockType::RleBlock => process_block_rle(
                src,
                byte_offset,
                last_row,
                randomness,
                block_size,
                last_block,
            ),
            BlockType::ZstdCompressedBlock => process_block_zstd(
                src,
                byte_offset,
                last_row,
                randomness,
                block_size,
                last_block,
            ),
            BlockType::Reserved => unreachable!("Reserved block type not expected"),
        };
    witness_rows.extend_from_slice(&rows);

    (
        byte_offset,
        witness_rows,
        last_block,
        literals,
        lstream_len,
        aux_data,
        fse_aux_table,
        huffman_codes,
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
        BlockType::RawBlock => ZstdTag::RawBlockBytes,
        BlockType::RleBlock => ZstdTag::RleBlockBytes,
        BlockType::ZstdCompressedBlock => ZstdTag::ZstdBlockLiteralsHeader,
        _ => unreachable!("BlockType::Reserved unexpected"),
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
                    huffman_data: HuffmanData::default(),
                    fse_data: FseTableRow::default(),
                },
            )
            .collect::<Vec<_>>(),
        last_block,
        block_type,
        block_size,
    )
}

fn process_raw_bytes<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    n_bytes: usize,
    tag: ZstdTag,
    tag_next: ZstdTag,
) -> (usize, Vec<ZstdWitnessRow<F>>) {
    let value_rlc_iter = src.iter().skip(byte_offset).take(n_bytes).scan(
        last_row.encoded_data.value_rlc,
        |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        },
    );
    let decoded_value_rlc_iter = src.iter().skip(byte_offset).take(n_bytes).scan(
        last_row.decoded_data.decoded_value_rlc,
        |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        },
    );
    let tag_value_iter =
        src.iter()
            .skip(byte_offset)
            .take(n_bytes)
            .scan(Value::known(F::zero()), |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            });
    let tag_value = tag_value_iter
        .clone()
        .last()
        .expect("Raw bytes must be of non-zero length");

    (
        byte_offset + n_bytes,
        src.iter()
            .skip(byte_offset)
            .take(n_bytes)
            .zip(tag_value_iter)
            .zip(value_rlc_iter)
            .zip(decoded_value_rlc_iter)
            .enumerate()
            .map(
                |(i, (((&value_byte, tag_value_acc), value_rlc), decoded_value_rlc))| {
                    ZstdWitnessRow {
                        state: ZstdState {
                            tag,
                            tag_next,
                            max_tag_len: lookup_max_tag_len(tag),
                            tag_len: n_bytes as u64,
                            tag_idx: (i + 1) as u64,
                            tag_value,
                            tag_value_acc,
                            is_tag_change: i == 0,
                            tag_rlc: Value::known(F::zero()),
                            tag_rlc_acc: Value::known(F::zero()),
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
                        huffman_data: HuffmanData::default(),
                        fse_data: FseTableRow::default(),
                    }
                },
            )
            .collect::<Vec<_>>(),
    )
}

fn process_rle_bytes<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    n_bytes: usize,
    tag: ZstdTag,
    tag_next: ZstdTag,
) -> (usize, Vec<ZstdWitnessRow<F>>) {
    let rle_byte = src[byte_offset];
    let value_rlc =
        last_row.encoded_data.value_rlc * randomness + Value::known(F::from(rle_byte as u64));
    let decoded_value_rlc_iter = std::iter::repeat(rle_byte).take(n_bytes).scan(
        last_row.decoded_data.decoded_value_rlc,
        |acc, byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        },
    );
    let tag_value = Value::known(F::from(rle_byte as u64));

    (
        byte_offset + 1,
        std::iter::repeat(rle_byte)
            .take(n_bytes)
            .zip(decoded_value_rlc_iter)
            .enumerate()
            .map(|(i, (value_byte, decoded_value_rlc))| ZstdWitnessRow {
                state: ZstdState {
                    tag,
                    tag_next,
                    max_tag_len: lookup_max_tag_len(tag),
                    tag_len: n_bytes as u64,
                    tag_idx: (i + 1) as u64,
                    tag_value,
                    tag_value_acc: tag_value,
                    is_tag_change: i == 0,
                    tag_rlc: Value::known(F::zero()),
                    tag_rlc_acc: Value::known(F::zero()),
                },
                encoded_data: EncodedData {
                    byte_idx: (byte_offset + 1) as u64,
                    encoded_len: last_row.encoded_data.encoded_len,
                    value_byte,
                    reverse: false,
                    value_rlc,
                    ..Default::default()
                },
                decoded_data: DecodedData {
                    decoded_len: last_row.decoded_data.decoded_len,
                    decoded_len_acc: last_row.decoded_data.decoded_len_acc + (i as u64) + 1,
                    total_decoded_len: last_row.decoded_data.total_decoded_len,
                    decoded_byte: value_byte,
                    decoded_value_rlc,
                },
                bitstream_read_data: BitstreamReadRow::default(),
                huffman_data: HuffmanData::default(),
                fse_data: FseTableRow::default(),
            })
            .collect::<Vec<_>>(),
    )
}

type BlockProcessingResult<F> = (
    usize,
    Vec<ZstdWitnessRow<F>>,
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
    FseAuxiliaryTableData,
    HuffmanCodesData,
);

fn process_block_raw<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    block_size: usize,
    last_block: bool,
) -> BlockProcessingResult<F> {
    let tag_next = if last_block {
        ZstdTag::Null
    } else {
        ZstdTag::BlockHeader
    };

    let (byte_offset, rows) = process_raw_bytes(
        src,
        byte_offset,
        last_row,
        randomness,
        block_size,
        ZstdTag::RawBlockBytes,
        tag_next,
    );

    let fse_aux_table = FseAuxiliaryTableData {
        block_idx: 0,
        table_kind: FseTableKind::LLT,
        table_size: 0,
        sym_to_states: BTreeMap::default(),
        sym_to_sorted_states: BTreeMap::default(),
    };
    let huffman_weights = HuffmanCodesData {
        byte_offset: 0,
        weights: vec![],
    };

    (
        byte_offset,
        rows.clone(),
        vec![],
        vec![rows.len() as u64, 0, 0, 0],
        vec![0, 0, 0, 0, 0, 0],
        fse_aux_table,
        huffman_weights,
    )
}

fn process_block_rle<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    block_size: usize,
    last_block: bool,
) -> BlockProcessingResult<F> {
    let tag_next = if last_block {
        ZstdTag::Null
    } else {
        ZstdTag::BlockHeader
    };

    let (byte_offset, rows) = process_rle_bytes(
        src,
        byte_offset,
        last_row,
        randomness,
        block_size,
        ZstdTag::RleBlockBytes,
        tag_next,
    );

    let fse_aux_table = FseAuxiliaryTableData {
        block_idx: 0,
        table_kind: FseTableKind::LLT,
        table_size: 0,
        sym_to_states: BTreeMap::default(),
        sym_to_sorted_states: BTreeMap::default(),
    };
    let huffman_weights = HuffmanCodesData {
        byte_offset: 0,
        weights: vec![],
    };

    (
        byte_offset,
        rows.clone(),
        vec![],
        vec![rows.len() as u64, 0, 0, 0],
        vec![0, 0, 0, 0, 0, 0],
        fse_aux_table,
        huffman_weights,
    )
}

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
    let mut witness_rows = vec![];

    // 1-5 bytes LiteralSectionHeader
    let literals_header_result: LiteralsHeaderProcessingResult<F> =
        process_block_zstd_literals_header::<F>(src, byte_offset, last_row, randomness);
    let (
        byte_offset,
        rows,
        literals_block_type,
        n_streams,
        regen_size,
        compressed_size,
        (branch, sf_max),
    ) = literals_header_result;
    // let (
    //     byte_offset,
    //     rows,
    //     literals_block_type,
    //     n_streams,
    //     regen_size,
    //     compressed_size,
    //     (branch, sf_max),
    // ) = process_block_zstd_literals_header::<F>(src, byte_offset, last_row, randomness);

    witness_rows.extend_from_slice(&rows);
    let mut fse_aux_table = FseAuxiliaryTableData {
        block_idx: 0,
        table_kind: FseTableKind::LLT,
        table_size: 0,
        sym_to_states: BTreeMap::default(),
        sym_to_sorted_states: BTreeMap::default(),
    };
    let mut huffman_weights = HuffmanCodesData {
        byte_offset: 0,
        weights: vec![],
    };

    // Depending on the literals block type, decode literals section accordingly
    let literals_block_result: LiteralsBlockResult<F> = match literals_block_type {
        BlockType::RawBlock => {
            let (byte_offset, rows) = process_raw_bytes(
                src,
                byte_offset,
                rows.last().expect("last row expected to exist"),
                randomness,
                regen_size,
                ZstdTag::ZstdBlockLiteralsRawBytes,
                ZstdTag::ZstdBlockSequenceHeader,
            );

            (
                byte_offset,
                rows.clone(),
                vec![],
                vec![rows.len() as u64, 0, 0, 0],
                vec![0, 0, 0, 0],
            )
        }
        BlockType::RleBlock => {
            let (byte_offset, rows) = process_rle_bytes(
                src,
                byte_offset,
                rows.last().expect("last row expected to exist"),
                randomness,
                regen_size,
                ZstdTag::ZstdBlockLiteralsRleBytes,
                ZstdTag::ZstdBlockSequenceHeader,
            );

            (
                byte_offset,
                rows.clone(),
                vec![],
                vec![rows.len() as u64, 0, 0, 0],
                vec![0, 0, 0, 0],
            )
        }
        BlockType::ZstdCompressedBlock => {
            let mut huffman_rows = vec![];

            let (
                bytes_offset,
                rows,
                huffman_codes,
                n_huffman_bytes,
                huffman_byte_offset,
                last_rlc,
                huffman_idx,
                fse_size,
                fse_accuracy,
                n_huffman_bitstream_bytes,
                fse_aux_data,
            ) = process_block_zstd_huffman_code(
                src,
                byte_offset,
                rows.last().expect("last row must exist"),
                randomness,
                n_streams,
            );
            huffman_rows.extend_from_slice(&rows);
            fse_aux_table = fse_aux_data;
            huffman_weights = huffman_codes.clone();

            // Subtract huffman header (1-byte), len of huffman bytes and 6-byte jump table (if
            // n_streams > 1)
            let mut literal_stream_size = compressed_size - (n_huffman_bytes + 1);
            if n_streams > 1 {
                literal_stream_size -= 6;
            }

            // Start decoding the literal section
            let mut stream_offset = bytes_offset;

            let (bytes_offset, rows, lstream_lens) = process_block_zstd_huffman_jump_table(
                src,
                stream_offset,
                huffman_rows.last().expect("last row should exist"),
                literal_stream_size,
                n_streams,
                randomness,
                last_rlc,
            );
            huffman_rows.extend_from_slice(&rows);
            stream_offset = bytes_offset;

            let mut literals: Vec<u64> = vec![];

            // for idx in 0..n_streams {
            for (idx, l_len) in lstream_lens.iter().enumerate().take(n_streams) {
                let (byte_offset, rows, symbols) = process_block_zstd_lstream(
                    src,
                    stream_offset,
                    *l_len as usize,
                    huffman_rows.last().expect("last row should exist"),
                    randomness,
                    idx,
                    &huffman_codes,
                    huffman_byte_offset,
                );
                huffman_rows.extend_from_slice(&rows);
                literals.extend_from_slice(&symbols);

                stream_offset = byte_offset;
            }

            (
                stream_offset,
                huffman_rows,
                literals,
                lstream_lens,
                vec![
                    huffman_idx as u64,
                    fse_size,
                    fse_accuracy,
                    n_huffman_bitstream_bytes,
                ],
            )
        }
        _ => unreachable!("Invalid literals section BlockType"),
    };
    let (bytes_offset, rows, literals, lstream_len, aux_data) = literals_block_result;
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
        fse_aux_table,
        huffman_weights,
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
        BlockType::RawBlock | BlockType::RleBlock => match size_format {
            0b00 | 0b10 => [1, 5, 0, 1, 1, 0],
            0b01 => [2, 12, 0, 1, 2, 1],
            0b11 => [2, 20, 0, 1, 3, 2],
            _ => unreachable!("size_format out of bound"),
        },
        BlockType::ZstdCompressedBlock => match size_format {
            0b00 => [2, 10, 10, 1, 3, 3],
            0b01 => [2, 10, 10, 4, 3, 3],
            0b10 => [2, 14, 14, 4, 4, 4],
            0b11 => [2, 18, 18, 4, 5, 5],
            _ => unreachable!("size_format out of bound"),
        },
        _ => unreachable!("BlockType::Reserved unexpected or treeless literal section"),
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
        BlockType::RleBlock => ZstdTag::ZstdBlockLiteralsRleBytes,
        BlockType::ZstdCompressedBlock => ZstdTag::ZstdBlockFseCode,
        _ => unreachable!("BlockType::Reserved unexpected or treeless literal section"),
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
                    huffman_data: HuffmanData::default(),
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

type HuffmanCodeProcessingResult<F> = (
    usize,
    Vec<ZstdWitnessRow<F>>,
    HuffmanCodesData,
    usize,
    usize,
    Value<F>,
    usize,
    u64,
    u64,
    u64,
    FseAuxiliaryTableData,
);

fn process_block_zstd_huffman_code<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    n_streams: usize,
) -> HuffmanCodeProcessingResult<F> {
    // Preserve this value for later construction of HuffmanCodesDataTable
    let huffman_code_byte_offset = byte_offset;

    // Other consistent values
    let encoded_len = last_row.encoded_data.encoded_len;
    let decoded_data = last_row.decoded_data.clone();

    // Get the next tag
    let tag_next = ZstdTag::ZstdBlockHuffmanCode;

    // Parse the header byte
    let mut witness_rows: Vec<ZstdWitnessRow<F>> = vec![];
    let header_byte = src[byte_offset];
    assert!(header_byte < 128, "FSE encoded huffman weights assumed");
    let n_bytes = header_byte as usize;

    let multiplier =
        (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
    let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

    // Add a witness row for Huffman header
    let mut huffman_header_row: ZstdWitnessRow<F> = ZstdWitnessRow {
        state: ZstdState {
            tag: ZstdTag::ZstdBlockFseCode,
            tag_next,
            max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockFseCode),
            tag_len: 0_u64, /* There's no information at this point about the length of FSE
                             * table bytes. So this value has to be modified later. */
            tag_idx: 1_u64,
            tag_value: Value::default(), // Must be changed after FSE table length is known
            tag_value_acc: Value::default(), // Must be changed after FSE table length is known
            is_tag_change: true,
            tag_rlc: Value::known(F::zero()), // Must be changed after FSE table length is known
            tag_rlc_acc: Value::known(F::zero()), // Must be changed after FSE table length is known
        },
        encoded_data: EncodedData {
            byte_idx: (byte_offset + 1) as u64,
            encoded_len,
            value_byte: header_byte,
            value_rlc,
            reverse: false,
            ..Default::default()
        },
        bitstream_read_data: BitstreamReadRow {
            bit_start_idx: 0usize,
            bit_end_idx: 7usize,
            bit_value: header_byte as u64,
            is_zero_bit_read: false,
        },
        decoded_data: decoded_data.clone(),
        huffman_data: HuffmanData::default(),
        fse_data: FseTableRow::default(),
    };

    // Recover the FSE table for generating Huffman weights
    // TODO(ray): this part is redundant however to compile, we have added the required args to the
    // ``reconstruct`` method.
    let (n_fse_bytes, bit_boundaries, table) =
        FseAuxiliaryTableData::reconstruct(src, 1, FseTableKind::LLT, byte_offset + 1)
            .expect("Reconstructing FSE table should not fail.");

    // Witness generation
    let accuracy_log = (src[byte_offset + 1] & 0b1111) + 5;

    let mut tag_value_iter = src.iter().skip(byte_offset).take(n_fse_bytes + 1).scan(
        Value::known(F::zero()),
        |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        },
    );
    let tag_value = tag_value_iter.clone().last().expect("Tag value must exist");

    let mut tag_rlc_iter = src.iter().skip(byte_offset).take(n_fse_bytes + 1).scan(
        Value::known(F::zero()),
        |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        },
    );
    let tag_rlc = tag_rlc_iter.clone().last().expect("Tag RLC must exist");

    // Backfill missing data on the huffman header row
    huffman_header_row.state.tag_len = (n_fse_bytes + 1usize) as u64;
    huffman_header_row.state.tag_value = tag_value;
    huffman_header_row.state.tag_value_acc =
        tag_value_iter.next().expect("Next value should exist");
    huffman_header_row.state.tag_rlc = tag_rlc;
    huffman_header_row.state.tag_rlc_acc = tag_rlc_iter.next().expect("Next value expected");
    witness_rows.push(huffman_header_row);

    // Process bit boundaries into bitstream reader info
    let mut decoded: u8 = 0;
    let mut n_acc: usize = 0;
    let mut current_tag_value_acc = Value::known(F::zero());
    let mut current_tag_rlc_acc = Value::known(F::zero());
    let mut last_byte_idx: i64 = 0;
    let mut from_pos: (i64, i64) = (1, 0);
    let mut to_pos: (i64, i64) = (0, 0);

    let bitstream_rows = bit_boundaries
        .iter()
        .enumerate()
        .map(|(sym, (bit_idx, value))| {
            from_pos = if sym == 0 { (1, -1) } else { to_pos };

            from_pos.1 += 1;
            if from_pos.1 == 8 {
                from_pos = (from_pos.0 + 1, 0);
            }
            from_pos.1 = (from_pos.1 as u64).rem_euclid(8) as i64;

            if from_pos.0 > last_byte_idx {
                current_tag_value_acc = tag_value_iter.next().unwrap();
                current_tag_rlc_acc = tag_rlc_iter.next().unwrap();
                last_byte_idx = from_pos.0;
            }

            let to_byte_idx = (bit_idx - 1) / 8;
            let mut to_bit_idx = bit_idx - to_byte_idx * (N_BITS_PER_BYTE as u32) - 1;

            if from_pos.0 < (to_byte_idx + 1) as i64 {
                to_bit_idx += 8;
            }

            to_pos = ((to_byte_idx + 1) as i64, to_bit_idx as i64);

            if sym > 0 && n_acc < (1 << accuracy_log) {
                decoded = (sym - 1) as u8;
                n_acc += (*value - 1) as usize;
            }

            (
                decoded,
                from_pos.0 as usize,
                from_pos.1 as usize,
                to_pos.0 as usize,
                to_pos.1 as usize,
                *value,
                current_tag_value_acc,
                current_tag_rlc_acc,
                0,
                n_acc,
            )
        })
        .collect::<Vec<(
            u8,
            usize,
            usize,
            usize,
            usize,
            u64,
            Value<F>,
            Value<F>,
            usize,
            usize,
        )>>();

    // Add witness rows for FSE representation bytes
    for row in bitstream_rows {
        witness_rows.push(ZstdWitnessRow {
            state: ZstdState {
                tag: ZstdTag::ZstdBlockFseCode,
                tag_next,
                max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockFseCode),
                tag_len: (n_fse_bytes + 1) as u64,
                tag_idx: (row.1 + 1) as u64, // count the huffman header byte
                tag_value,
                tag_value_acc: row.6,
                is_tag_change: false,
                tag_rlc,
                tag_rlc_acc: row.7,
            },
            encoded_data: EncodedData {
                byte_idx: (byte_offset + row.1 + 1) as u64, // count the huffman header byte
                encoded_len,
                value_byte: src[byte_offset + row.1],
                value_rlc,
                reverse: false,
                ..Default::default()
            },
            bitstream_read_data: BitstreamReadRow {
                bit_start_idx: row.2,
                bit_end_idx: row.4,
                bit_value: row.5,
                is_zero_bit_read: false,
            },
            decoded_data: DecodedData {
                decoded_len: last_row.decoded_data.decoded_len,
                decoded_len_acc: last_row.decoded_data.decoded_len_acc,
                total_decoded_len: last_row.decoded_data.total_decoded_len,
                decoded_byte: row.0,
                decoded_value_rlc: last_row.decoded_data.decoded_value_rlc,
            },
            huffman_data: HuffmanData::default(),
            fse_data: FseTableRow {
                state: 0,
                symbol: 0,
                baseline: 0,
                num_bits: 0,
                num_emitted: 0,
                is_state_skipped: false,
            },
        });
    }

    // Now start decoding the huffman weights using the actual Huffman code section
    let tag_next = if n_streams > 1 {
        ZstdTag::ZstdBlockJumpTable
    } else {
        ZstdTag::ZstdBlockLstream
    };

    // Update the last row
    let last_row = witness_rows.last().expect("Last row exists");
    let multiplier =
        (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
    let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

    // Bitstream processing state values
    let mut num_emitted: usize = 0;
    let n_huffman_code_bytes = n_bytes - n_fse_bytes;
    let mut last_byte_idx: usize = 1;
    let mut current_byte_idx: usize = 1; // byte_idx is 1-indexed
    let mut current_bit_idx: usize = 0;

    // Construct the Huffman bitstream
    let huffman_bitstream = src
        .iter()
        .skip(byte_offset + n_fse_bytes + 1)
        .take(n_huffman_code_bytes)
        .rev()
        .clone()
        .flat_map(|v| {
            let mut bits = value_bits_le(*v);
            bits.reverse();
            bits
        })
        .collect::<Vec<u8>>();

    // Accumulators for Huffman code section
    let mut value_rlc_iter = src
        .iter()
        .skip(byte_offset + n_fse_bytes + 1)
        .take(n_huffman_code_bytes)
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        })
        .collect::<Vec<Value<F>>>()
        .into_iter()
        .rev();
    let mut tag_value_iter = src
        .iter()
        .skip(byte_offset + n_fse_bytes + 1)
        .take(n_huffman_code_bytes)
        .rev()
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        });
    let tag_value = tag_value_iter.clone().last().expect("Tag value must exist");
    let tag_rlc_iter = src
        .iter()
        .skip(byte_offset + n_fse_bytes + 1)
        .take(n_huffman_code_bytes)
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        });
    let tag_rlc = tag_rlc_iter.clone().last().expect("Tag RLC must exist");
    let mut tag_rlc_iter = tag_rlc_iter.collect::<Vec<Value<F>>>().into_iter().rev();

    let mut next_tag_value_acc = tag_value_iter.next().unwrap();
    let next_value_rlc_acc = value_rlc_iter.next().unwrap();
    let mut next_tag_rlc_acc = tag_rlc_iter.next().unwrap();

    let aux_1 = next_value_rlc_acc;
    let aux_2 = witness_rows[witness_rows.len() - 1].encoded_data.value_rlc;

    let mut padding_end_idx: usize = 0;
    while huffman_bitstream[padding_end_idx] == 0 {
        padding_end_idx += 1;
    }

    // Add a witness row for leading 0s and the sentinel 1-bit
    witness_rows.push(ZstdWitnessRow {
        state: ZstdState {
            tag: ZstdTag::ZstdBlockHuffmanCode,
            tag_next,
            max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockHuffmanCode),
            tag_len: n_huffman_code_bytes as u64,
            tag_idx: 1_u64,
            tag_value,
            tag_value_acc: next_tag_value_acc,
            is_tag_change: true,
            tag_rlc,
            tag_rlc_acc: next_tag_rlc_acc,
        },
        encoded_data: EncodedData {
            byte_idx: (byte_offset + n_fse_bytes + 1 + current_byte_idx) as u64,
            encoded_len,
            value_byte: src
                [byte_offset + n_fse_bytes + 1 + n_huffman_code_bytes - current_byte_idx],
            value_rlc,
            reverse: true,
            reverse_len: n_huffman_code_bytes as u64,
            reverse_idx: (n_huffman_code_bytes - (current_byte_idx - 1)) as u64,
            aux_1,
            aux_2,
        },
        bitstream_read_data: BitstreamReadRow {
            bit_value: 1u64,
            bit_start_idx: 0usize,
            bit_end_idx: padding_end_idx,
            is_zero_bit_read: false,
        },
        huffman_data: HuffmanData::default(),
        decoded_data: last_row.decoded_data.clone(),
        fse_data: FseTableRow::default(),
    });

    // Exclude the leading zero section
    while huffman_bitstream[current_bit_idx] == 0 {
        (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
    }
    // Exclude the sentinel 1-bit
    (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);

    // Update accumulator
    if current_byte_idx > last_byte_idx {
        next_tag_value_acc = tag_value_iter.next().unwrap();
        next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
        last_byte_idx = current_byte_idx;
    }

    // Now the actual weight-bearing bitstream starts
    // The Huffman bitstream is decoded by two interleaved states reading the stream in alternating
    // order. The FSE table for the two independent decoding strands are the same.
    let mut color: usize = 0; // use 0, 1 (colors) to denote two alternating decoding strands.
    let mut prev_baseline: [u64; 2] = [0, 0];
    let mut next_nb_to_read: [usize; 2] = [accuracy_log as usize, accuracy_log as usize];
    let mut decoded_weights: Vec<u8> = vec![];
    let mut fse_table_idx: u64 = 1;

    // Convert FSE auxiliary data into a state-indexed representation
    let fse_state_table = table.clone().parse_state_table();

    while current_bit_idx + next_nb_to_read[color] <= (n_huffman_code_bytes) * N_BITS_PER_BYTE {
        let nb = next_nb_to_read[color];
        let bitstring_value =
            be_bits_to_value(&huffman_bitstream[current_bit_idx..(current_bit_idx + nb)]);
        let next_state = prev_baseline[color] + bitstring_value;

        let from_bit_idx = current_bit_idx.rem_euclid(8);
        let to_bit_idx = if nb > 0 {
            from_bit_idx + (nb - 1)
        } else {
            from_bit_idx
        };

        // Lookup the FSE table row for the state
        let fse_row = fse_state_table
            .get(&{ next_state })
            .expect("next state should be in fse table");

        // Decode the symbol
        decoded_weights.push(fse_row.0 as u8);
        num_emitted += 1;

        // Add a witness row
        witness_rows.push(ZstdWitnessRow {
            state: ZstdState {
                tag: ZstdTag::ZstdBlockHuffmanCode,
                tag_next,
                max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockHuffmanCode),
                tag_len: (n_huffman_code_bytes) as u64,
                tag_idx: current_byte_idx as u64,
                tag_value,
                tag_value_acc: next_tag_value_acc,
                is_tag_change: false,
                tag_rlc,
                tag_rlc_acc: next_tag_rlc_acc,
            },
            encoded_data: EncodedData {
                byte_idx: (byte_offset + n_fse_bytes + 1 + current_byte_idx) as u64,
                encoded_len,
                value_byte: src
                    [byte_offset + n_fse_bytes + 1 + n_huffman_code_bytes - current_byte_idx],
                value_rlc,
                reverse: true,
                reverse_len: n_huffman_code_bytes as u64,
                reverse_idx: (n_huffman_code_bytes - (current_byte_idx - 1)) as u64,
                aux_1,
                aux_2,
            },
            bitstream_read_data: BitstreamReadRow {
                bit_value: bitstring_value,
                bit_start_idx: from_bit_idx,
                bit_end_idx: to_bit_idx,
                is_zero_bit_read: (nb == 0),
            },
            fse_data: FseTableRow {
                state: next_state,
                symbol: fse_row.0,
                baseline: fse_row.1,
                num_bits: fse_row.2,
                num_emitted: num_emitted as u64,
                // TODO(ray): pls check where to get this field from.
                is_state_skipped: false,
            },
            huffman_data: HuffmanData::default(),
            decoded_data: decoded_data.clone(),
        });

        // increment fse idx
        fse_table_idx += 1;

        // Advance byte and bit marks. Get next acc value if byte changes
        for _ in 0..nb {
            (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
        }
        if current_byte_idx > last_byte_idx && current_byte_idx <= n_huffman_code_bytes {
            next_tag_value_acc = tag_value_iter.next().unwrap();
            next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
            last_byte_idx = current_byte_idx;
        }

        // Preparing for next state
        prev_baseline[color] = fse_row.1;
        next_nb_to_read[color] = fse_row.2 as usize;

        color = if color > 0 { 0 } else { 1 };
    }

    // Construct HuffmanCodesTable
    let huffman_codes = HuffmanCodesData {
        byte_offset: (huffman_code_byte_offset + 1) as u64,
        weights: decoded_weights
            .into_iter()
            .map(|w| FseSymbol::from(w as usize))
            .collect(),
    };

    // rlc after a reverse section
    let mul =
        (0..(n_huffman_code_bytes - 1)).fold(Value::known(F::one()), |acc, _| acc * randomness);
    let new_value_rlc_init_value = aux_2 * mul + aux_1;

    (
        byte_offset + 1 + n_fse_bytes + n_huffman_code_bytes,
        witness_rows,
        huffman_codes,
        n_bytes,
        huffman_code_byte_offset + 1,
        new_value_rlc_init_value,
        byte_offset + 1,
        (1 << accuracy_log) as u64,
        accuracy_log as u64,
        n_huffman_code_bytes as u64,
        table, // FSE table
    )
}

fn process_block_zstd_huffman_jump_table<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    literal_stream_size: usize,
    n_streams: usize,
    randomness: Value<F>,
    last_rlc: Value<F>,
) -> (usize, Vec<ZstdWitnessRow<F>>, Vec<u64>) {
    if n_streams <= 1 {
        (byte_offset, vec![], vec![literal_stream_size as u64])
    } else {
        // Note: The decompressed size of each stream is equal to (regen_size + 3) / 4
        // but the compressed bitstream length will be different.
        // Jump table provides information on the length of first 3 bitstreams.

        let jt_bytes = src
            .iter()
            .skip(byte_offset)
            .take(N_JUMP_TABLE_BYTES)
            .cloned()
            .map(|x| x as u64)
            .collect::<Vec<u64>>();

        let l1: u64 = jt_bytes[0] + jt_bytes[1] * 256;
        let l2: u64 = jt_bytes[2] + jt_bytes[3] * 256;
        let l3: u64 = jt_bytes[4] + jt_bytes[5] * 256;
        let l4: u64 = (literal_stream_size as u64) - l1 - l2 - l3;

        let value_rlc_iter =
            src.iter()
                .skip(byte_offset)
                .take(N_JUMP_TABLE_BYTES)
                .scan(last_rlc, |acc, &byte| {
                    *acc = *acc * randomness + Value::known(F::from(byte as u64));
                    Some(*acc)
                });
        let multiplier =
            (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
        let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

        let tag_value_iter = src.iter().skip(byte_offset).take(N_JUMP_TABLE_BYTES).scan(
            Value::known(F::zero()),
            |acc, &byte| {
                *acc = *acc * Value::known(F::from(256u64)) + Value::known(F::from(byte as u64));
                Some(*acc)
            },
        );
        let tag_value = tag_value_iter
            .clone()
            .last()
            .expect("Tag value must exist.");
        let tag_rlc_iter = src.iter().skip(byte_offset).take(N_JUMP_TABLE_BYTES).scan(
            Value::known(F::zero()),
            |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            },
        );
        let tag_rlc = tag_rlc_iter.clone().last().expect("Tag value must exist.");

        (
            byte_offset + N_JUMP_TABLE_BYTES,
            src.iter()
                .skip(byte_offset)
                .take(N_JUMP_TABLE_BYTES)
                .zip(tag_value_iter)
                .zip(value_rlc_iter)
                .zip(tag_rlc_iter)
                .enumerate()
                .map(
                    |(i, (((&value_byte, tag_value_acc), _v_rlc), tag_rlc_acc))| ZstdWitnessRow {
                        state: ZstdState {
                            tag: ZstdTag::ZstdBlockJumpTable,
                            tag_next: ZstdTag::ZstdBlockLstream,
                            max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockJumpTable),
                            tag_len: N_JUMP_TABLE_BYTES as u64,
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
                        bitstream_read_data: BitstreamReadRow {
                            bit_start_idx: 0,
                            bit_end_idx: 7,
                            bit_value: value_byte as u64,
                            is_zero_bit_read: false,
                        },
                        decoded_data: last_row.decoded_data.clone(),
                        huffman_data: HuffmanData::default(),
                        fse_data: FseTableRow::default(),
                    },
                )
                .collect::<Vec<_>>(),
            vec![l1, l2, l3, l4],
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn process_block_zstd_lstream<F: Field>(
    src: &[u8],
    byte_offset: usize,
    len: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    stream_idx: usize,
    huffman_code: &HuffmanCodesData,
    huffman_code_byte_offset: usize,
) -> (usize, Vec<ZstdWitnessRow<F>>, Vec<u64>) {
    // Obtain literal stream bits (reversed).
    let lstream_bits = src
        .iter()
        .skip(byte_offset)
        .take(len)
        .rev()
        .clone()
        .flat_map(|v| {
            let mut bits = value_bits_le(*v);
            bits.reverse();
            bits
        })
        .collect::<Vec<u8>>();

    // Bitstream processing state helper values
    let mut witness_rows: Vec<ZstdWitnessRow<F>> = vec![];
    let mut last_byte_idx: usize = 1;
    let mut current_byte_idx: usize = 1;
    let mut current_bit_idx: usize = 0;
    let mut decoded_len_acc = last_row.decoded_data.decoded_len_acc;
    let mut decoded_rlc = last_row.decoded_data.decoded_value_rlc;

    // accumulators
    let aux_1 = last_row.encoded_data.value_rlc;
    let multiplier =
        (0..last_row.state.tag_len).fold(Value::known(F::one()), |acc, _| acc * randomness);
    let value_rlc = last_row.encoded_data.value_rlc * multiplier + last_row.state.tag_rlc;

    let mut tag_value_acc =
        src.iter()
            .skip(byte_offset)
            .take(len)
            .rev()
            .scan(Value::known(F::zero()), |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            });
    let tag_value = tag_value_acc.clone().last().expect("Tag value exists");

    let tag_rlc_iter =
        src.iter()
            .skip(byte_offset)
            .take(len)
            .scan(Value::known(F::zero()), |acc, &byte| {
                *acc = *acc * randomness + Value::known(F::from(byte as u64));
                Some(*acc)
            });
    let tag_rlc = tag_rlc_iter.clone().last().expect("Tag value exists");
    let mut tag_rlc_iter = tag_rlc_iter.collect::<Vec<Value<F>>>().into_iter().rev();

    // Decide the next tag
    let tag_next = match stream_idx {
        0..=2 => ZstdTag::ZstdBlockLstream,
        3 => ZstdTag::ZstdBlockSequenceHeader,
        _ => unreachable!("stream_idx value out of range"),
    };

    let mut padding_end_idx = 0;
    while lstream_bits[padding_end_idx] == 0 {
        padding_end_idx += 1;
    }

    let mut next_tag_value_acc = tag_value_acc.next().unwrap();
    let mut next_tag_rlc_acc = tag_rlc_iter.next().unwrap();

    // Add a witness row for leading 0s and sentinel 1-bit
    witness_rows.push(ZstdWitnessRow {
        state: ZstdState {
            tag: ZstdTag::ZstdBlockLstream,
            tag_next,
            max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockLstream),
            tag_len: len as u64,
            tag_idx: current_byte_idx as u64,
            tag_value,
            tag_value_acc: next_tag_value_acc,
            is_tag_change: true,
            tag_rlc,
            tag_rlc_acc: next_tag_rlc_acc,
        },
        encoded_data: EncodedData {
            byte_idx: (byte_offset + current_byte_idx) as u64,
            encoded_len: last_row.encoded_data.encoded_len,
            value_byte: src[byte_offset + len - current_byte_idx],
            value_rlc,
            // reverse specific values
            reverse: true,
            reverse_len: len as u64,
            reverse_idx: (len - (current_byte_idx - 1)) as u64,
            aux_1,
            aux_2: tag_value,
        },
        huffman_data: HuffmanData {
            byte_offset: huffman_code_byte_offset as u64,
            bit_value: 1u8,
            stream_idx,
            k: (0, padding_end_idx as u8),
        },
        bitstream_read_data: BitstreamReadRow {
            bit_value: 1u64,
            bit_start_idx: 0usize,
            bit_end_idx: padding_end_idx,
            is_zero_bit_read: false,
        },
        decoded_data: DecodedData {
            decoded_len: last_row.decoded_data.decoded_len,
            decoded_len_acc: last_row.decoded_data.decoded_len_acc,
            total_decoded_len: last_row.decoded_data.total_decoded_len,
            decoded_byte: 0,
            decoded_value_rlc: last_row.decoded_data.decoded_value_rlc,
        },
        fse_data: FseTableRow::default(),
    });

    // Exclude the leading zero section
    while lstream_bits[current_bit_idx] == 0 {
        (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);
    }
    // Exclude the sentinel 1-bit
    (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);

    // Update accumulator
    if current_byte_idx > last_byte_idx {
        next_tag_value_acc = tag_value_acc.next().unwrap();
        next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
        last_byte_idx = current_byte_idx;
    }

    // Now the actual symbol-bearing bitstream starts
    let (max_bitstring_len, huffman_bitstring_map) = huffman_code.parse_bitstring_map();
    let mut decoded_symbols: Vec<u64> = vec![];
    let mut bitstring_acc: String = String::from("");
    let mut cur_bitstring_len: usize = 0;

    while current_bit_idx < len * N_BITS_PER_BYTE {
        if huffman_bitstring_map.contains_key(bitstring_acc.as_str()) {
            let sym = *huffman_bitstring_map.get(bitstring_acc.as_str()).unwrap();
            decoded_symbols.push(sym);

            let from_byte_idx = current_byte_idx;
            let from_bit_idx = current_bit_idx;

            // advance byte and bit marks to the last bit
            for _ in 0..(cur_bitstring_len - 1) {
                (current_byte_idx, current_bit_idx) =
                    increment_idx(current_byte_idx, current_bit_idx);
            }
            let end_bit_idx = if current_byte_idx > from_byte_idx {
                current_bit_idx.rem_euclid(8) + 8
            } else {
                current_bit_idx.rem_euclid(8)
            };
            (current_byte_idx, current_bit_idx) = increment_idx(current_byte_idx, current_bit_idx);

            decoded_len_acc += 1;
            decoded_rlc = decoded_rlc * randomness + Value::known(F::from(sym));

            // Add a witness row for emitted symbol
            witness_rows.push(ZstdWitnessRow {
                state: ZstdState {
                    tag: ZstdTag::ZstdBlockLstream,
                    tag_next,
                    max_tag_len: lookup_max_tag_len(ZstdTag::ZstdBlockLstream),
                    tag_len: len as u64,
                    tag_idx: from_byte_idx as u64,
                    tag_value,
                    tag_value_acc: next_tag_value_acc,
                    is_tag_change: false,
                    tag_rlc,
                    tag_rlc_acc: next_tag_rlc_acc,
                },
                encoded_data: EncodedData {
                    byte_idx: (byte_offset + from_byte_idx) as u64,
                    encoded_len: last_row.encoded_data.encoded_len,
                    value_byte: src[byte_offset + len - from_byte_idx],
                    value_rlc,
                    // reverse specific values
                    reverse: true,
                    reverse_len: len as u64,
                    reverse_idx: (len - from_byte_idx + 1) as u64,
                    aux_1,
                    aux_2: tag_value,
                },
                huffman_data: HuffmanData {
                    byte_offset: huffman_code_byte_offset as u64,
                    bit_value: u8::from_str_radix(bitstring_acc.as_str(), 2).unwrap(),
                    stream_idx,
                    k: (from_bit_idx.rem_euclid(8) as u8, end_bit_idx as u8),
                },
                bitstream_read_data: BitstreamReadRow {
                    bit_value: u8::from_str_radix(bitstring_acc.as_str(), 2).unwrap() as u64,
                    bit_start_idx: from_bit_idx.rem_euclid(8),
                    bit_end_idx: end_bit_idx,
                    is_zero_bit_read: false,
                },
                decoded_data: DecodedData {
                    decoded_len: last_row.decoded_data.decoded_len,
                    decoded_len_acc,
                    total_decoded_len: last_row.decoded_data.total_decoded_len,
                    decoded_byte: sym as u8,
                    decoded_value_rlc: decoded_rlc,
                },
                fse_data: FseTableRow::default(),
            });

            // Update accumulator
            if current_byte_idx > last_byte_idx && current_byte_idx <= len {
                next_tag_value_acc = tag_value_acc.next().unwrap();
                next_tag_rlc_acc = tag_rlc_iter.next().unwrap();
                last_byte_idx = current_byte_idx;
            }

            // Reset decoding state
            bitstring_acc = String::from("");
            cur_bitstring_len = 0;
        } else {
            if lstream_bits[current_bit_idx + cur_bitstring_len] > 0 {
                bitstring_acc.push('1');
            } else {
                bitstring_acc.push('0');
            }
            cur_bitstring_len += 1;

            if cur_bitstring_len > max_bitstring_len as usize {
                panic!("Reading bit len greater than max bitstring len not allowed.");
            }
        }
    }

    (byte_offset + len, witness_rows, decoded_symbols)
}

/// Result for processing multiple blocks from compressed data
pub type MultiBlockProcessResult<F> = (
    Vec<ZstdWitnessRow<F>>,
    Vec<u64>,
    Vec<u64>,
    Vec<FseAuxiliaryTableData>,
    Vec<HuffmanCodesData>,
);

/// Process a slice of bytes into decompression circuit witness rows
pub fn process<F: Field>(src: &[u8], randomness: Value<F>) -> MultiBlockProcessResult<F> {
    let mut witness_rows = vec![];
    let mut literals: Vec<u64> = vec![];
    let mut aux_data: Vec<u64> = vec![];
    let mut fse_aux_tables: Vec<FseAuxiliaryTableData> = vec![];
    let mut huffman_codes: Vec<HuffmanCodesData> = vec![];
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
            fse_aux_table,
            huffman_code,
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
        fse_aux_tables.push(fse_aux_table);
        huffman_codes.push(huffman_code);

        if last_block {
            // TODO: Recover this assertion after the sequence section decoding is completed.
            // assert!(byte_offset >= src.len());
            break;
        }
    }

    (
        witness_rows,
        literals,
        aux_data,
        fse_aux_tables,
        huffman_codes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use eth_types::H256;
    use ethers_core::utils::keccak256;
    use halo2_proofs::halo2curves::bn256::Fr;

    use std::{
        fs::{self, File},
        io::Write,
    };

    #[test]
    #[ignore]
    fn compression_ratio() -> Result<(), std::io::Error> {
        use csv::WriterBuilder;

        let get_compression_ratio = |data: &[u8]| -> Result<(u64, u64, H256), std::io::Error> {
            let raw_len = data.len();
            let compressed = {
                // compression level = 0 defaults to using level=3, which is zstd's default.
                let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0)?;

                // disable compression of literals, i.e. literals will be raw bytes.
                encoder.set_parameter(zstd::stream::raw::CParameter::LiteralCompressionMode(
                    zstd::zstd_safe::ParamSwitch::Disable,
                ))?;
                // set target block size to fit within a single block.
                encoder
                    .set_parameter(zstd::stream::raw::CParameter::TargetCBlockSize(124 * 1024))?;
                // do not include the checksum at the end of the encoded data.
                encoder.include_checksum(false)?;
                // do not include magic bytes at the start of the frame since we will have a single
                // frame.
                encoder.include_magicbytes(false)?;
                // set source length, which will be reflected in the frame header.
                encoder.set_pledged_src_size(Some(raw_len as u64))?;
                // include the content size to know at decode time the expected size of decoded
                // data.
                encoder.include_contentsize(true)?;

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

        let (_witness_rows, _decoded_literals, _aux_data, _fse_aux_tables, _huffman_codes) =
            process::<Fr>(&compressed, Value::known(Fr::from(123456789)));

        Ok(())
    }

    // Verify correct interleaved decoding of FSE-coded Huffman Weights
    // Example link: https://nigeltao.github.io/blog/2022/zstandard-part-5-fse.html
    #[test]
    fn interleaved_huffman_code_fse() -> Result<(), std::io::Error> {
        // Input includes FSE table representation (normalized symbol frequencies) and the actual
        // Huffman bitstream For structure reference: https://nigeltao.github.io/blog/2022/zstandard-part-2-structure.html
        let input: [u8; 36] = [
            0x23, 0x30, 0x6f, 0x9b, 0x03, 0x7d, 0xc7, 0x16, 0x0b, 0xbe, 0xc8, 0xf2, 0xd0, 0x22,
            0x4b, 0x6b, 0xbc, 0x54, 0x5d, 0xa9, 0xd4, 0x93, 0xef, 0xc4, 0x54, 0x96, 0xb2, 0xe2,
            0xa8, 0xa8, 0x24, 0x1c, 0x54, 0x40, 0x29, 0x01,
        ];

        let (
            _byte_offset,
            _witness_rows,
            huffman_codes,
            _n_huffan_bytes,
            _huffman_byte_offset,
            _last_rlc,
            _huffman_idx,
            _fse_size,
            _fse_accuracy,
            _n_huffman_bitstream_bytes,
            _fse_aux_data,
        ) = process_block_zstd_huffman_code::<Fr>(
            &input,
            0,
            &ZstdWitnessRow::init(0),
            Value::known(Fr::from(123456789)),
            4,
        );

        let expected_weights: Vec<FseSymbol> = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 6, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 3, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            1, 2, 0, 0, 0, 2, 0, 1, 1, 1, 1, 1, 0, 0, 1, 2, 1, 0, 1, 1, 1, 2, 0, 0, 1, 1, 1, 1, 0,
            1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 5, 3, 3, 3, 6, 3, 2, 4, 4, 0, 1, 4, 4, 5, 5, 2, 0, 4, 4,
            5, 3, 1, 3, 1, 3,
        ]
        .into_iter()
        .map(FseSymbol::from)
        .collect::<Vec<FseSymbol>>();

        assert_eq!(
            huffman_codes.weights, expected_weights,
            "Huffman weights should be correctly decoded with interleaved states"
        );

        Ok(())
    }

    // Verify correct decoding of literal bitstream using a HuffmanCode table
    // Example link: https://nigeltao.github.io/blog/2022/zstandard-part-4-huffman.html
    #[test]
    fn decode_literal_bitstream() -> Result<(), std::io::Error> {
        let huffman_codes = HuffmanCodesData {
            byte_offset: 0,
            weights: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 6, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 3, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0,
                0, 0, 1, 2, 0, 0, 0, 2, 0, 1, 1, 1, 1, 1, 0, 0, 1, 2, 1, 0, 1, 1, 1, 2, 0, 0, 1, 1,
                1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 5, 3, 3, 3, 6, 3, 2, 4, 4, 0, 1, 4, 4, 5, 5,
                2, 0, 4, 4, 5, 3, 1, 3, 1, 3,
            ]
            .into_iter()
            .map(FseSymbol::from)
            .collect::<Vec<FseSymbol>>(),
        };

        let lstream1: [u8; 85] = [
            0xcc, 0x51, 0x73, 0x3a, 0x85, 0x9e, 0xf7, 0x59, 0xfc, 0xc5, 0xca, 0x6a, 0x7a, 0xd9,
            0x82, 0x9c, 0x65, 0xc5, 0x45, 0x92, 0xe3, 0x0d, 0xf3, 0xef, 0x71, 0xee, 0xdc, 0xd5,
            0xa2, 0xe3, 0x48, 0xad, 0xa3, 0xbc, 0x41, 0x7a, 0x3c, 0xaa, 0xd6, 0xeb, 0xd0, 0x77,
            0xea, 0xdc, 0x5d, 0x41, 0x06, 0x50, 0x1c, 0x49, 0x0f, 0x07, 0x10, 0x05, 0x88, 0x84,
            0x94, 0x02, 0xfc, 0x3c, 0xe3, 0x60, 0x25, 0xc0, 0xcb, 0x0c, 0xb8, 0xa9, 0x73, 0xbc,
            0x13, 0x77, 0xc6, 0xe2, 0x20, 0xed, 0x17, 0x7b, 0x12, 0xdc, 0x24, 0x5a, 0xdf, 0xb4,
            0x21,
        ];

        let (_byte_offset, _witness_rows, decoded_symbols) = process_block_zstd_lstream::<Fr>(
            &lstream1,
            0,
            85,
            &ZstdWitnessRow::init(0),
            Value::known(Fr::from(123456789)),
            1,
            &huffman_codes,
            0,
        );

        let ascii_symbols: String = decoded_symbols
            .iter()
            .filter_map(|&s| char::from_u32(s as u32))
            .collect();
        let expected_decoded_ascii: String = String::from("Romeo and Juliet\nExcerpt from Act 2, Scene 2\n\nJULIET\nO ,! wherefore art thou?\nDeny thy fatherrefusename;\nOr, ifwilt not, be but sworn my l");

        assert_eq!(
            ascii_symbols, expected_decoded_ascii,
            "Expect correct decoding"
        );

        Ok(())
    }

    #[test]
    fn decode_literal_section() -> Result<(), std::io::Error> {
        let encoded: [u8; 555] = [
            // 0x28, 0xb5, 0x2f, 0xfd, // magic numbers are removed
            0x60, // originally 0x64. unset the checksum bit.
            0xae, 0x02, 0x0d, 0x11, 0x00, 0x76, 0x62, 0x5e, 0x23, 0x30, 0x6f, 0x9b, 0x03, 0x7d,
            0xc7, 0x16, 0x0b, 0xbe, 0xc8, 0xf2, 0xd0, 0x22, 0x4b, 0x6b, 0xbc, 0x54, 0x5d, 0xa9,
            0xd4, 0x93, 0xef, 0xc4, 0x54, 0x96, 0xb2, 0xe2, 0xa8, 0xa8, 0x24, 0x1c, 0x54, 0x40,
            0x29, 0x01, 0x55, 0x00, 0x57, 0x00, 0x51, 0x00, 0xcc, 0x51, 0x73, 0x3a, 0x85, 0x9e,
            0xf7, 0x59, 0xfc, 0xc5, 0xca, 0x6a, 0x7a, 0xd9, 0x82, 0x9c, 0x65, 0xc5, 0x45, 0x92,
            0xe3, 0x0d, 0xf3, 0xef, 0x71, 0xee, 0xdc, 0xd5, 0xa2, 0xe3, 0x48, 0xad, 0xa3, 0xbc,
            0x41, 0x7a, 0x3c, 0xaa, 0xd6, 0xeb, 0xd0, 0x77, 0xea, 0xdc, 0x5d, 0x41, 0x06, 0x50,
            0x1c, 0x49, 0x0f, 0x07, 0x10, 0x05, 0x88, 0x84, 0x94, 0x02, 0xfc, 0x3c, 0xe3, 0x60,
            0x25, 0xc0, 0xcb, 0x0c, 0xb8, 0xa9, 0x73, 0xbc, 0x13, 0x77, 0xc6, 0xe2, 0x20, 0xed,
            0x17, 0x7b, 0x12, 0xdc, 0x24, 0x5a, 0xdf, 0xb4, 0x21, 0x9a, 0xcb, 0x8f, 0xc7, 0x58,
            0x54, 0x11, 0xa9, 0xf1, 0x47, 0x82, 0x9b, 0xba, 0x60, 0xb4, 0x92, 0x28, 0x0e, 0xfb,
            0x8b, 0x1e, 0x92, 0x23, 0x6a, 0xcf, 0xbf, 0xe5, 0x45, 0xb5, 0x7e, 0xeb, 0x81, 0xf1,
            0x78, 0x4b, 0xad, 0x17, 0x4d, 0x81, 0x9f, 0xbc, 0x67, 0xa7, 0x56, 0xee, 0xb4, 0xd9,
            0xe1, 0x95, 0x21, 0x66, 0x0c, 0x95, 0x83, 0x27, 0xde, 0xac, 0x37, 0x20, 0x91, 0x22,
            0x07, 0x0b, 0x91, 0x86, 0x94, 0x1a, 0x7b, 0xf6, 0x4c, 0xb0, 0xc0, 0xe8, 0x2e, 0x49,
            0x65, 0xd6, 0x34, 0x63, 0x0c, 0x88, 0x9b, 0x1c, 0x48, 0xca, 0x2b, 0x34, 0xa9, 0x6b,
            0x99, 0x3b, 0xee, 0x13, 0x3b, 0x7c, 0x93, 0x0b, 0xf7, 0x0d, 0x49, 0x69, 0x18, 0x57,
            0xbe, 0x3b, 0x64, 0x45, 0x1d, 0x92, 0x63, 0x7f, 0xe8, 0xf9, 0xa1, 0x19, 0x7b, 0x7b,
            0x6e, 0xd8, 0xa3, 0x90, 0x23, 0x82, 0xf4, 0xa7, 0xce, 0xc8, 0xf8, 0x90, 0x15, 0xb3,
            0x14, 0xf4, 0x40, 0xe7, 0x02, 0x78, 0xd3, 0x17, 0x71, 0x23, 0xb1, 0x19, 0xad, 0x6b,
            0x49, 0xae, 0x13, 0xa4, 0x75, 0x38, 0x51, 0x47, 0x89, 0x67, 0xb0, 0x39, 0xb4, 0x53,
            0x86, 0xa4, 0xac, 0xaa, 0xa3, 0x34, 0x89, 0xca, 0x2e, 0xe9, 0xc1, 0xfe, 0xf2, 0x51,
            0xc6, 0x51, 0x73, 0xaa, 0xf7, 0x9d, 0x2d, 0xed, 0xd9, 0xb7, 0x4a, 0xb2, 0xb2, 0x61,
            0xe4, 0xef, 0x98, 0xf7, 0xc5, 0xef, 0x51, 0x9b, 0xd8, 0xdc, 0x60, 0x6c, 0x41, 0x76,
            0xaf, 0x78, 0x1a, 0x62, 0xb5, 0x4c, 0x1e, 0x21, 0x39, 0x9a, 0x5f, 0xac, 0x9d, 0xe0,
            0x62, 0xe8, 0xe9, 0x2f, 0x2f, 0x48, 0x02, 0x8d, 0x53, 0xc8, 0x91, 0xf2, 0x1a, 0xd2,
            0x7c, 0x0a, 0x7c, 0x48, 0xbf, 0xda, 0xa9, 0xe3, 0x38, 0xda, 0x34, 0xce, 0x76, 0xa9,
            0xda, 0x15, 0x91, 0xde, 0x21, 0xf5, 0x55, 0x46, 0xa8, 0x21, 0x9d, 0x51, 0xcc, 0x18,
            0x42, 0x44, 0x81, 0x8c, 0x94, 0xb4, 0x50, 0x1e, 0x20, 0x42, 0x82, 0x98, 0xc2, 0x3b,
            0x10, 0x48, 0xec, 0xa6, 0x39, 0x63, 0x13, 0xa7, 0x01, 0x94, 0x40, 0xff, 0x88, 0x0f,
            0x98, 0x07, 0x4a, 0x46, 0x38, 0x05, 0xa9, 0xcb, 0xf6, 0xc8, 0x21, 0x59, 0xaa, 0x38,
            0x45, 0xbf, 0x5c, 0xf8, 0x55, 0x9e, 0x9f, 0x04, 0xed, 0xc8, 0x03, 0x42, 0x2a, 0x4b,
            0xf6, 0x78, 0x7e, 0x23, 0x67, 0x15, 0xa2, 0x79, 0x29, 0xf4, 0x9b, 0x7e, 0x00, 0xbc,
            0x2f, 0x46, 0x96, 0x99, 0xea, 0xf1, 0xee, 0x1c, 0x6e, 0x06, 0x9c, 0xdb, 0xe4, 0x8c,
            0xc2, 0x05, 0xf7, 0x54, 0x51, 0x84, 0xc0, 0x33, 0x02, 0x01, 0xb1, 0x8c, 0x80, 0xdc,
            0x99, 0x8f, 0xcb, 0x46, 0xff, 0xd1, 0x25, 0xb5, 0xb6, 0x3a, 0xf3, 0x25, 0xbe, 0x85,
            0x50, 0x84, 0xf5, 0x86, 0x5a, 0x71, 0xf7, 0xbd, 0xa1, 0x4c, 0x52, 0x4f, 0x20, 0xa3,
            0x61, 0x23, 0x77, 0x12, 0xd3, 0xb1, 0x58, 0x75, 0x22, 0x01, 0x12, 0x70, 0xec, 0x14,
            0x91, 0xf9, 0x85, 0x61, 0xd5, 0x7e, 0x98, 0x84, 0xc9, 0x76, 0x84, 0xbc, 0xb8, 0xfe,
            0x4e, 0x53, 0xa5, 0x06, 0x82, 0x14, 0x95, 0x51,
        ];

        let (_witness_rows, decoded_literals, _aux_data, _fse_aux_tables, _huffman_codes) =
            process::<Fr>(&encoded, Value::known(Fr::from(123456789)));

        let decoded_literal_string: String = decoded_literals
            .iter()
            .filter_map(|&s| char::from_u32(s as u32))
            .collect();
        let expected_literal_string = String::from("Romeo and Juliet\nExcerpt from Act 2, Scene 2\n\nJULIET\nO ,! wherefore art thou?\nDeny thy fatherrefusename;\nOr, ifwilt not, be but sworn my love,\nAnd I'll no longera Capulet.\n\nROMEO\n[Aside] Shall I hear more, or sspeak at this?'Tis that isenemy;\nTyself,gh a Montague.\nWhat's? inor hand,foot,\nNor armaceany opart\nBeing to a man. Osome!in a?which we ca rose\nBy would smell as sweet;\nSo, were he'd,\nRetaindear perfectionhe owes\nWithoitle.dofffor oee\nTake mI t hy word:\nCebe new baptized;\nHencth I never will. manthus bescreen'dnightstumblest on my counsel?\n");

        assert_eq!(
            decoded_literal_string, expected_literal_string,
            "Decode the correct literal string"
        );

        Ok(())
    }
}
