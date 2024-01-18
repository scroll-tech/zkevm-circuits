use bitstream_io::huffman;
use bus_mapping::circuit_input_builder::Block;
use eth_types::Field;
use halo2_proofs::circuit::Value;

mod params;
use num::Integer;
pub use params::*;

mod types;
use serde::de::value;
pub use types::*;

#[cfg(test)]
mod tui;
#[cfg(test)]
use tui::draw_rows;

mod util;
use util::{value_bits_le, le_bits_to_value, increment_idx};

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
        .rev()
        .cloned()
        .collect::<Vec<u8>>();
    let fcs = {
        let fcs = fcs_bytes
            .iter()
            .fold(0u64, |acc, &byte| acc * 256u64 + (byte as u64));
        match fcs_tag_len {
            2 => fcs + 256,
            _ => fcs,
        }
    };
    let fcs_tag_value_iter = fcs_bytes
        .iter()
        .scan(Value::known(F::zero()), |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
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
                tag_len: 1,
                tag_idx: 1,
                tag_value: Value::known(F::from(*fhd_byte as u64)),
                tag_value_acc: Value::known(F::from(*fhd_byte as u64)),
            },
            encoded_data: EncodedData {
                byte_idx: (byte_offset + 1) as u64,
                encoded_len: last_row.encoded_data.encoded_len,
                value_byte: *fhd_byte,
                value_rlc: fhd_value_rlc,
                ..Default::default()
            },
            decoded_data: DecodedData {
                decoded_len: fcs,
                decoded_len_acc: 0,
                total_decoded_len: last_row.decoded_data.total_decoded_len + fcs,
                decoded_byte: 0,
                decoded_value_rlc: last_row.decoded_data.decoded_value_rlc,
            },
            huffman_data: HuffmanData::default(),
            fse_data: FseTableRow::default(),
        })
        .chain(
            fcs_bytes
                .iter()
                .zip(fcs_tag_value_iter)
                .zip(fcs_value_rlcs.iter().rev())
                .enumerate()
                .map(
                    |(i, ((&value_byte, tag_value_acc), &value_rlc))| ZstdWitnessRow {
                        state: ZstdState {
                            tag: ZstdTag::FrameContentSize,
                            tag_next: ZstdTag::BlockHeader,
                            tag_len: fcs_tag_len as u64,
                            tag_idx: (i + 1) as u64,
                            tag_value: fcs_tag_value,
                            tag_value_acc,
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
                            value_rlc,
                        },
                        decoded_data: last_row.decoded_data.clone(),
                        huffman_data: HuffmanData::default(),
                        fse_data: FseTableRow::default(),
                    },
                ),
        )
        .collect::<Vec<_>>(),
    )
}

fn process_block<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
) -> (usize, Vec<ZstdWitnessRow<F>>, bool) {
    let mut witness_rows = vec![];

    let (byte_offset, rows, last_block, block_type, block_size) =
        process_block_header(src, byte_offset, last_row, randomness);
    witness_rows.extend_from_slice(&rows);

    let last_row = rows.last().expect("last row expected to exist");
    let (_byte_offset, rows) = match block_type {
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

    (byte_offset, witness_rows, last_block)
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

    let tag_value_iter = bh_bytes.iter().scan(Value::known(F::zero()), |acc, &byte| {
        *acc = *acc * randomness + Value::known(F::from(byte as u64));
        Some(*acc)
    });
    let tag_value = tag_value_iter.clone().last().expect("BlockHeader expected");

    // BlockHeader follows FrameContentSize which is processed in reverse order.
    // Hence value_rlc at the first BlockHeader byte will be calculated as:
    //
    // value_rlc::cur == aux_1::prev * (rand ^ reverse_len) * rand
    //      + aux_2::prev * rand
    //      + value_byte::cur
    let acc_start = last_row.encoded_data.aux_1
        * randomness.map(|r| r.pow([last_row.encoded_data.reverse_len, 0, 0, 0]))
        + last_row.encoded_data.aux_2;
    let value_rlcs = bh_bytes
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
            .zip(tag_value_iter)
            .zip(value_rlcs.iter())
            .enumerate()
            .map(
                |(i, ((&value_byte, tag_value_acc), &value_rlc))| ZstdWitnessRow {
                    state: ZstdState {
                        tag: ZstdTag::BlockHeader,
                        tag_next,
                        tag_len: N_BLOCK_HEADER_BYTES as u64,
                        tag_idx: (i + 1) as u64,
                        tag_value,
                        tag_value_acc,
                    },
                    encoded_data: EncodedData {
                        byte_idx: (byte_offset + i + 1) as u64,
                        encoded_len: last_row.encoded_data.encoded_len,
                        value_byte,
                        reverse: false,
                        value_rlc,
                        ..Default::default()
                    },
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
    let tag_value_iter = src.iter().skip(byte_offset).take(n_bytes).scan(
        Value::known(F::zero()),
        |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        },
    );
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
                            tag_len: n_bytes as u64,
                            tag_idx: (i + 1) as u64,
                            tag_value,
                            tag_value_acc,
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
                    tag_len: n_bytes as u64,
                    tag_idx: (i + 1) as u64,
                    tag_value,
                    tag_value_acc: tag_value,
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
                huffman_data: HuffmanData::default(),
                fse_data: FseTableRow::default(),
            })
            .collect::<Vec<_>>(),
    )
}

fn process_block_raw<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    block_size: usize,
    last_block: bool,
) -> (usize, Vec<ZstdWitnessRow<F>>) {
    let tag_next = if last_block {
        ZstdTag::Null
    } else {
        ZstdTag::BlockHeader
    };

    process_raw_bytes(
        src,
        byte_offset,
        last_row,
        randomness,
        block_size,
        ZstdTag::RawBlockBytes,
        tag_next,
    )
}

fn process_block_rle<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    block_size: usize,
    last_block: bool,
) -> (usize, Vec<ZstdWitnessRow<F>>) {
    let tag_next = if last_block {
        ZstdTag::Null
    } else {
        ZstdTag::BlockHeader
    };

    process_rle_bytes(
        src, 
        byte_offset, 
        last_row, 
        randomness, 
        block_size, 
        ZstdTag::RleBlockBytes, 
        tag_next,
    )
}

#[allow(unused_variables)]
fn process_block_zstd<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    block_size: usize,
    last_block: bool,
) -> (usize, Vec<ZstdWitnessRow<F>>) {
    let mut witness_rows = vec![];

    // 1-5 bytes LiteralSectionHeader
    let (
        byte_offset, 
        rows, 
        literals_block_type, 
        n_streams, 
        regen_size, 
        compressed_size
    ) = process_block_zstd_literals_header::<F>(
        src, 
        byte_offset, 
        last_row, 
        randomness
    );
    witness_rows.extend_from_slice(&rows);

    // Depending on the literals block type, decode literals section accordingly
    let (bytes_offset, rows) = match literals_block_type {
        BlockType::RawBlock => {
            process_raw_bytes(
                src, 
                byte_offset, 
                rows.last().expect("last row expected to exist"), 
                randomness, 
                regen_size, 
                ZstdTag::ZstdBlockLiteralsRawBytes, 
                ZstdTag::ZstdBlockSequenceHeader,
            )
        },
        BlockType::RleBlock => {
            process_rle_bytes(
                src, 
                byte_offset, 
                rows.last().expect("last row expected to exist"), 
                randomness, 
                regen_size, 
                ZstdTag::ZstdBlockLiteralsRleBytes, 
                ZstdTag::ZstdBlockSequenceHeader,
            )
        },
        BlockType::ZstdCompressedBlock => {
            let mut huffman_rows = vec![];

            let (bytes_offset, rows, is_direct, n_bytes) = process_block_zstd_huffman_header(
                src,
                byte_offset,
                rows.last().expect("last row expected to exist"),
                randomness,
            );
            huffman_rows.extend_from_slice(&rows);

            let (bytes_offset, rows, huffman_codes) = if is_direct {
                process_block_zstd_huffman_code_direct(
                    src, 
                    byte_offset, 
                    &huffman_rows[0], 
                    randomness,
                    n_bytes,
                )
            } else {
                process_block_zstd_huffman_code_fse(
                    src, 
                    byte_offset, 
                    &huffman_rows[0], 
                    randomness,
                    n_bytes,
                )
            };
            huffman_rows.extend_from_slice(&rows);

            let mut stream_offset = byte_offset;

            if n_streams > 1 {
                let (byte_offset, rows, lstream_lens) = process_block_zstd_huffman_jump_table(
                    src, 
                    stream_offset, 
                    huffman_rows.last().expect("last row should exist"),
                    randomness
                );
                huffman_rows.extend_from_slice(&rows);
            }

            for idx in 0..n_streams {
                let (byte_offset, rows) = process_block_zstd_lstream(
                    src, 
                    stream_offset,
                    n_bytes,
                    huffman_rows.last().expect("last row should exist"),
                    randomness,
                    idx,
                    &huffman_codes
                );
                huffman_rows.extend_from_slice(&rows);

                stream_offset = byte_offset;
            }
            
            (stream_offset, huffman_rows)
        },
        _ => unreachable!("Invalid literals section BlockType")
    };
    witness_rows.extend_from_slice(&rows);

    (bytes_offset, witness_rows)
}

fn process_block_zstd_literals_header<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
) -> (usize, Vec<ZstdWitnessRow<F>>, BlockType, usize, usize, usize) {
    let lh_bytes = src
        .iter()
        .skip(byte_offset)
        .take(N_MAX_LITERAL_HEADER_BYTES)
        .cloned()
        .collect::<Vec<u8>>();

    let literals_block_type = BlockType::from(lh_bytes[0] & 0x3);
    let size_format = lh_bytes[0] & 3;

    let [n_bits_fmt, n_bits_regen, n_bits_compressed, n_streams, n_bytes_header]: [usize; 5] = match literals_block_type {
        BlockType::RawBlock | BlockType::RleBlock => {
            match size_format {
                0b00 | 0b10 => [1, 5, 0, 1, 1],
                0b01 => [2, 12, 0, 1, 2],
                0b11 => [2, 20, 0, 1, 3],
                _ => unreachable!("size_format out of bound")
            }
        },
        BlockType::ZstdCompressedBlock => {
            match size_format {
                0b00 => [2, 10, 10, 1, 3],
                0b01 => [2, 10, 10, 4, 3],
                0b10 => [2, 14, 14, 4, 4],
                0b11 => [2, 18, 18, 4, 5],
                _ => unreachable!("size_format out of bound")
            }
        },
        _ => unreachable!("BlockType::Reserved unexpected or treeless literal section")
    };

    // Bits for representing regenerated_size and compressed_size
    let sizing_bits = &lh_bytes.clone().into_iter().fold(vec![], |mut acc, b| {
        acc.extend(value_bits_le(b));
        acc
    })[(2 + n_bits_fmt)..(n_bytes_header * N_BITS_PER_BYTE)];

    let regen_size = le_bits_to_value(&sizing_bits[0..n_bits_regen]);
    let compressed_size = le_bits_to_value(&sizing_bits[n_bits_regen..(n_bits_regen + n_bits_compressed)]);

    let tag_next = match literals_block_type {
        BlockType::RawBlock => ZstdTag::ZstdBlockLiteralsRawBytes,
        BlockType::RleBlock => ZstdTag::ZstdBlockLiteralsRleBytes,
        BlockType::ZstdCompressedBlock => ZstdTag::ZstdBlockHuffmanHeader,
        _ => unreachable!("BlockType::Reserved unexpected or treeless literal section"),
    };

    let tag_value_iter = lh_bytes.iter().take(n_bytes_header).scan(Value::known(F::zero()), |acc, &byte| {
        *acc = *acc * randomness + Value::known(F::from(byte as u64));
        Some(*acc)
    });
    let tag_value = tag_value_iter.clone().last().expect("LiteralsHeader expected");

    let value_rlc_iter = lh_bytes
        .iter()
        .take(n_bytes_header)
        .scan(last_row.encoded_data.value_rlc, |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        });

    (
        byte_offset + n_bytes_header,
        lh_bytes
            .iter()
            .take(n_bytes_header)
            .zip(tag_value_iter)
            .zip(value_rlc_iter)
            .enumerate()
            .map(
                |(i, ((&value_byte, tag_value_acc), value_rlc))| ZstdWitnessRow {
                    state: ZstdState {
                        tag: ZstdTag::ZstdBlockLiteralsHeader,
                        tag_next,
                        tag_len: n_bytes_header as u64,
                        tag_idx: (i + 1) as u64,
                        tag_value,
                        tag_value_acc,
                    },
                    encoded_data: EncodedData {
                        byte_idx: (byte_offset + i + 1) as u64,
                        encoded_len: last_row.encoded_data.encoded_len,
                        value_byte,
                        reverse: false,
                        value_rlc,
                        ..Default::default()
                    },
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
    )
}

fn process_block_zstd_huffman_header<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
) -> (usize, Vec<ZstdWitnessRow<F>>, bool, usize) {
    let header_byte = src[byte_offset];

    let value_rlc =
        last_row.encoded_data.value_rlc * randomness + Value::known(F::from(header_byte as u64));
    let decoded_value_rlc = 
        last_row.decoded_data.decoded_value_rlc + randomness + Value::known(F::from(header_byte as u64));
    let tag_value = Value::known(F::from(header_byte as u64));

    let n_bytes = if header_byte < 128 {
        header_byte
    } else {
        let n_sym = header_byte - 127;
        if n_sym.is_odd() {
            (n_sym + 1) / 2
        } else {
            n_sym / 2
        }
    };

    (
        byte_offset + 1,
        vec![ZstdWitnessRow {
            state: ZstdState {
                tag: ZstdTag::ZstdBlockHuffmanHeader,
                tag_next: ZstdTag::ZstdBlockFseCode,
                tag_len: 1 as u64,
                tag_idx: 1 as u64,
                tag_value,
                tag_value_acc: tag_value,
            },
            encoded_data: EncodedData {
                byte_idx: (byte_offset + 1) as u64,
                encoded_len: last_row.encoded_data.encoded_len,
                value_byte: header_byte,
                reverse: false,
                value_rlc,
                ..Default::default()
            },
            decoded_data: DecodedData {
                decoded_len: last_row.decoded_data.decoded_len,
                decoded_len_acc: last_row.decoded_data.decoded_len_acc + 1,
                total_decoded_len: last_row.decoded_data.total_decoded_len,
                decoded_byte: header_byte,
                decoded_value_rlc,
            },
            huffman_data: HuffmanData::default(),
            fse_data: FseTableRow::default(),
        }],
        header_byte >= 127,
        n_bytes as usize,
    )
}

// compression_debug
// fn process_block_zstd_huffman_header<F: Field>(
//     src: &[u8],
//     byte_offset: usize,
//     last_row: &ZstdWitnessRow<F>,
//     randomness: Value<F>,
// ) -> (usize, Vec<ZstdWitnessRow<F>>) {
//     // A single byte (header_byte) is read.
//     // - if header_byte < 128: canonical weights are represented by FSE table.
//     // - if header_byte >= 128: canonical weights are given by direct representation.

//     let header_byte = src
//         .get(byte_offset)
//         .expect("ZBHuffmanHeader byte should exist");

//     assert!(
//         *header_byte < 128,
//         "we expect canonical huffman weights to be encoded using FSE"
//     );

//     let value_rlc =
//         last_row.encoded_data.value_rlc * randomness + Value::known(F::from(*header_byte as u64));

//     (
//         byte_offset + 1,
//         vec![ZstdWitnessRow {
//             state: ZstdState {
//                 tag: ZstdTag::ZstdBlockHuffmanHeader,
//                 tag_next: ZstdTag::ZstdBlockFseCode,
//                 tag_len: 1,
//                 tag_idx: 1,
//                 tag_value: Value::known(F::from(*header_byte as u64)),
//                 tag_value_acc: Value::known(F::from(*header_byte as u64)),
//             },
//             encoded_data: EncodedData {
//                 byte_idx: (byte_offset + 1) as u64,
//                 encoded_len: last_row.encoded_data.encoded_len,
//                 value_byte: *header_byte,
//                 value_rlc,
//                 ..Default::default()
//             },
//             decoded_data: last_row.decoded_data.clone(),
//             fse_data: FseTableRow::default(),
//             huffman_data: HuffmanData::default(),
//         }],
//     )
// }

fn process_block_zstd_huffman_code_direct<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    n_bytes: usize,
) -> (usize, Vec<ZstdWitnessRow<F>>, HuffmanCodesData) {
    // For direct representation of huffman weights, each byte (8 bits) represents two weights. 
    // weight[0] = (Byte[0] >> 4)
    // weight[1] = (Byte[0] & 0xf).

    let value_rlc_iter = src.iter().skip(byte_offset).take(n_bytes).scan(
        last_row.encoded_data.value_rlc,
        |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(byte as u64));
            Some(*acc)
        },
    )
    .into_iter()
    .flat_map(|v| vec![v, v]);

    let decoded_value_rlc_iter = src
        .iter()
        .skip(byte_offset)
        .take(n_bytes)
        .into_iter()
        .flat_map(|v| vec![v, v])
        .zip((0..).cycle().take(n_bytes * 2))
        .scan(
        last_row.decoded_data.decoded_value_rlc,
        |acc, (&byte, b_flag)| {
            let v = if b_flag > 0 { byte & 0xf } else { byte >> 4 };
            *acc = *acc * randomness + Value::known(F::from(v as u64));
            Some(*acc)
        },
    );

    let tag_value_iter = src
        .iter()
        .skip(byte_offset)
        .take(n_bytes)
        .into_iter()
        .flat_map(|v| vec![v, v])
        .zip((0..).cycle().take(n_bytes * 2))
        .scan(
        Value::known(F::zero()),
        |acc, (&byte, b_flag)| {
            let v = if b_flag > 0 { byte & 0xf } else { byte >> 4 };
            *acc = *acc * randomness + Value::known(F::from(v as u64));
            Some(*acc)
        },
    );

    let tag_value = tag_value_iter
        .clone()
        .last()
        .expect("Raw bytes must be of non-zero length");

    (
        byte_offset + n_bytes,
        src.iter()
            .skip(byte_offset)
            .take(n_bytes)
            .into_iter()
            .flat_map(|v| vec![v, v])
            .zip(tag_value_iter)
            .zip(value_rlc_iter)
            .zip(decoded_value_rlc_iter)
            .zip((0..).cycle().take(n_bytes * 2))
            .enumerate()
            .map(
                |(i, ((((&value_byte, tag_value_acc), value_rlc), decoded_value_rlc), b_flag))| {
                    ZstdWitnessRow {
                        state: ZstdState {
                            tag: ZstdTag::ZstdBlockHuffmanCode,
                            tag_next: ZstdTag::ZstdBlockSequenceHeader,
                            tag_len: (n_bytes * 2) as u64,
                            tag_idx: (i + 1) as u64,
                            tag_value,
                            tag_value_acc,
                        },
                        encoded_data: EncodedData {
                            byte_idx: (byte_offset + i / 2 + 1) as u64,
                            encoded_len: last_row.encoded_data.encoded_len,
                            value_byte: if b_flag > 0 { value_byte >> 4 } else { value_byte & 0xf },
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
                        huffman_data: HuffmanData::default(),
                        fse_data: FseTableRow::default(),
                    }
                },
            )
            .collect::<Vec<_>>(),
            HuffmanCodesData { byte_offset: 0, weights: vec![] }
    )
}

fn process_block_zstd_huffman_code_fse<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    n_bytes: usize,
) -> (usize, Vec<ZstdWitnessRow<F>>, HuffmanCodesData) {
    // Preserve this value for later construction of HuffmanCodesDataTable
    let huffman_code_byte_offset = byte_offset;

    // First, recover the FSE table for generating Huffman weights
    let (n_fse_bytes, table) = FseAuxiliaryTableData::reconstruct(&src, byte_offset).expect("Reconstructing FSE table should not fail.");

     // Exclude the FSE table representation bytes, then we're left with a bitstream for recovering Huffman weights
    let byte_offset = byte_offset + n_fse_bytes;
    let n_bytes = n_bytes - n_fse_bytes;

    // Construct the Huffman bitstream
    let mut huffman_bitstream = 
        src
            .iter()
            .skip(byte_offset)
            .take(n_bytes)
            .rev()
            .clone()
            .flat_map(|v|{
                let mut bits = value_bits_le(*v);
                bits.reverse();
                bits
            })
            .collect::<Vec<u8>>();

    // Deliminators vector stores the positions where the bitstream is deliminated (a different value is decoded)
    // The pair (usize, usize) indicates (byte_idx, bit_idx) where a delimination occurs (think of adding an underscore at the position)
    // The range between two positions is where a new symbol is decoded or a new segment is recognized (i.e. leading zero section, a single sentinel 1-bit)
    let mut deliminators: Vec<(usize, usize)> = vec![];

    // Add a virtual deliminator in the front
    deliminators.push((0, 0));

    // Bitstream processing state values
    let mut current_byte_idx: usize = 1; // byte_idx is 1-indexed
    let mut current_bit_idx: usize = 0;

    // Recognize the leading zero section
    while huffman_bitstream[current_bit_idx] == 0 {
        increment_idx(current_byte_idx, current_bit_idx);
    }
    deliminators.push((current_byte_idx, current_bit_idx)); // indicates the end of leading zeros

    // The next bit is the sentinel bit
    increment_idx(current_byte_idx, current_bit_idx);
    deliminators.push((current_byte_idx, current_bit_idx));

    // Now the actual weight-bearing bitstream starts
    // The Huffman bitstream is decoded by two interleaved states reading the stream in alternating order.
    // The FSE table for the two independent decoding strands are the same.
    let mut color: usize = 0; // use 0, 1 (colors) to denote two alternating decoding strands. 
    let mut prev_baseline: [u64; 2] = [0, 0];
    let mut next_nb_to_read: [usize; 2] = [table.accuracy_log as usize, table.accuracy_log as usize];
    let mut decoded_weights: Vec<u8> = vec![];

    // Convert FSE auxiliary data into a state-indexed representation
    let fse_state_table = table.parse_state_table();

    while current_bit_idx + next_nb_to_read[color] < n_bytes * N_BITS_PER_BYTE {
        let nb = next_nb_to_read[color];
        let next_state = prev_baseline[color] + le_bits_to_value(&huffman_bitstream[current_bit_idx..(current_bit_idx + nb)]);

        // Lookup the FSE table row for the state
        let fse_row = fse_state_table.get(&(next_state as u64)).expect("next state should be in fse table");

        // Decode the symbol
        decoded_weights.push(fse_row.0 as u8);

        // Preparing for next state
        prev_baseline[color] = fse_row.1;
        next_nb_to_read[color] = fse_row.2 as usize;

        for _ in 0..nb {
            increment_idx(current_byte_idx, current_bit_idx);
            deliminators.push((current_byte_idx, current_bit_idx));
        }

        color = !color;
    }

    // Construct HuffmanCodesTable
    let huffman_codes = HuffmanCodesData {
        byte_offset: huffman_code_byte_offset as u64,
        weights: decoded_weights.into_iter().map(|w| FseSymbol::from(w as usize) ).collect()
    };

    // compression_debug
    // need to organize the witness rows
    (0, vec![], huffman_codes)
}

fn process_block_zstd_huffman_jump_table<F: Field>(
    src: &[u8],
    byte_offset: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
) -> (usize, Vec<ZstdWitnessRow<F>>, [u64; 3]) {
    // Note: The decompressed size of each stream is equal to (regen_size + 3) / 4
    // but the compressed bitstream length will be different. 
    // Jump table provides information on the length of first 3 bitstreams. 

    // Jump table's lengths are all plain bytes

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

    let (bytes_offset, rows) = 
        process_raw_bytes(
            src, 
            byte_offset, 
            last_row, 
            randomness, 
            N_JUMP_TABLE_BYTES, 
            ZstdTag::ZstdBlockJumpTable, 
            ZstdTag::ZstdBlockHuffmanCode,
        );

    (bytes_offset, rows, [l1, l2, l3])
}
fn process_block_zstd_lstream<F: Field>(
    src: &[u8],
    byte_offset: usize,
    len: usize,
    last_row: &ZstdWitnessRow<F>,
    randomness: Value<F>,
    stream_idx: usize,
    huffman_code: &HuffmanCodesData,
) -> (usize, Vec<ZstdWitnessRow<F>>) {
    let mut lstream_bits = 
        src
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

    // Deliminators vector stores the positions where the bitstream is deliminated (a different value is decoded)
    // The pair (usize, usize) indicates (byte_idx, bit_idx) where a delimination occurs (think of adding an underscore at the position)
    // The range between two positions is where a new symbol is decoded or a new segment is recognized (i.e. leading zero section, a single sentinel 1-bit)
    let mut deliminators: Vec<(usize, usize)> = vec![];

    // Add a virtual deliminator in the front
    deliminators.push((0, 0));

    // Bitstream processing state values
    let mut current_byte_idx: usize = 1; // byte_idx is 1-indexed
    let mut current_bit_idx: usize = 0;

    // Recognize the leading zero section
    while lstream_bits[current_bit_idx] == 0 {
        increment_idx(current_byte_idx, current_bit_idx);
    }
    deliminators.push((current_byte_idx, current_bit_idx)); // indicates the end of leading zeros

    // The next bit is the sentinel bit
    increment_idx(current_byte_idx, current_bit_idx);
    deliminators.push((current_byte_idx, current_bit_idx));

    // Now the actual symbol-bearing bitstream starts
    let huffman_bit_value_map = huffman_code.parse_canonical_bit_value_map();
    let mut bit_value_acc: u64 = 0;
    let mut cur_bitstring_len: usize = 0;
    let mut decoded_symbols: Vec<u64> = vec![];

    while current_bit_idx < len * N_BITS_PER_BYTE {
        if huffman_bit_value_map.1.contains_key(&bit_value_acc) {
            decoded_symbols.push(huffman_bit_value_map.1.get(&bit_value_acc).unwrap().clone());
            
            // Mark the new deliminator
            for _ in 0..cur_bitstring_len {
                increment_idx(current_byte_idx, current_bit_idx);
            }
            deliminators.push((current_byte_idx, current_bit_idx));

            // Reset decoding state
            bit_value_acc = 0;
            cur_bitstring_len = 0;
        } else {
            bit_value_acc += (src[current_bit_idx + cur_bitstring_len] as u64) * 2u64.pow(cur_bitstring_len as u32);
            cur_bitstring_len += 1;

            if cur_bitstring_len > huffman_bit_value_map.0 as usize {
                unreachable!("read bit len greater than max bitstring len");
            }
        }
    }
    
    // Now construct the witness rows
    let tag_next = if stream_idx == 3 {
        ZstdTag::ZstdBlockSequenceHeader
    } else {
        match stream_idx {
            0 | 1 | 2 => ZstdTag::Lstream,
            _ => unreachable!("stream_idx value out of range")
        }
    };

    // Add the leading zero and sentinel 1-bit.
    if deliminators[1] == (1, 0) {
        // there're no leading zeros
        decoded_symbols.insert(0, 1);
    } else {
        decoded_symbols.insert(0, 0);
        decoded_symbols.insert(1, 1);
    }

    // Witness rows
    let mut value_rlc = last_row.encoded_data.value_rlc;

    let decoded_value_rlc = last_row.decoded_data.decoded_value_rlc;
    let decoded_value_rlc_iter = decoded_symbols.iter().scan(
        last_row.decoded_data.decoded_value_rlc,
        |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(symbol as u64));
            Some(*acc)
        },
    );

    let tag_value_iter = decoded_symbols.iter().scan(
        Value::known(F::zero()),
        |acc, &byte| {
            *acc = *acc * randomness + Value::known(F::from(symbol as u64));
            Some(*acc)
        },
    );

    let tag_value = tag_value_iter
        .clone()
        .last()
        .expect("Tag value exists");

    let mut witness_rows: Vec<ZstdWitnessRow> = vec![];
    
    let mut last_pos = deliminators[0];
    for (idx, curr_pos) in deliminators.into_iter().skip(1).enumerate() {
        if curr_pos.0 > last_pos.0 {
            value_rlc = value_rlc * randomness + Value::known(F::from)
        }
        
        witness_rows.push(ZstdWitnessRow {
            state: ZstdState {
                tag: ZstdTag::Lstream,
                tag_next,
                tag_len: len as u64,
                tag_idx: idx as u64,
                tag_value: tag_value,
                tag_value_acc: tag_value_iter.next(),
            },
            encoded_data: EncodedData {
                byte_idx: (byte_offset + last_pos.0) as u64,
                encoded_len: last_row.encoded_data.encoded_len,
                value_byte: src[byte_offset + last_pos.0],
                value_rlc,
                reverse: true,
                ..Default::default()
            },
            decoded_data: DecodedData {
                decoded_len: last_row.decoded_data.decoded_len,
                decoded_len_acc: last_row.decoded_data.decoded_len + curr_pos.0 as u64 + 1,
                total_decoded_len: last_row.decoded_data.total_decoded_len,
                decoded_byte: decoded_symbols[idx],
                decoded_value_rlc,
            },
            huffman_data: HuffmanData::default(),
            fse_data: FseTableRow::default(),
        });

        last_pos = curr_pos;
    }

    (byte_offset + len, witness_rows)
}

pub fn process<F: Field>(src: &[u8], randomness: Value<F>) -> Vec<ZstdWitnessRow<F>> {
    let mut witness_rows = vec![];
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
        let (byte_offset, rows, last_block) = process_block::<F>(
            src,
            byte_offset,
            rows.last().expect("last row expected to exist"),
            randomness,
        );
        witness_rows.extend_from_slice(&rows);

        if last_block {
            assert!(byte_offset >= src.len());
            break;
        }
    }

    #[cfg(test)]
    let _ = draw_rows(&witness_rows);

    witness_rows
}

#[cfg(test)]
mod tests {
    use ff::BitViewSized;
    use halo2_proofs::halo2curves::bn256::Fr;
    use hex::FromHex;
    use std::io::Write;

    use super::*;

    #[test]
    fn batch_compression() -> Result<(), std::io::Error> {
        let raw = <Vec<u8>>::from_hex(r#"0100000000000231fb0000000064e588f7000000000000000000000000000000000000000000000000000000000000000000000000007a12000006000000000219f90216038510229a150083039bd49417afd0263d6909ba1f9a8eac697f76532365fb95880234e1a857498000b901a45ae401dc0000000000000000000000000000000000000000000000000000000064e58a1400000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e404e45aaf0000000000000000000000005300000000000000000000000000000000000004000000000000000000000000d9692f1748afee00face2da35242417dd05a86150000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000c3100d07a5997a7f9f9cdde967d396f9a2aed6a60000000000000000000000000000000000000000000000000234e1a8574980000000000000000000000000000000000000000000000000049032ac61d5dce9e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000083104ec1a053077484b4d7a88434c2d03c30c3c55bd3a82b259f339f1c0e1e1244189009c5a01c915dd14aed1b824bf610a95560e380ea3213f0bf345df3bddff1acaf7da84d000002d8f902d5068510229a1500830992fd94bbad0e891922a8a4a7e9c39d4cc0559117016fec87082b6be7f5b757b90264ac9650d800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000164883164560000000000000000000000005300000000000000000000000000000000000004000000000000000000000000ffd2ece82f7959ae184d10fe17865d27b4f0fb9400000000000000000000000000000000000000000000000000000000000001f4fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffce9f6fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcea0a00000000000000000000000000000000000000000000000000082b6be7f5b75700000000000000000000000000000000000000000000000000000000004c4b40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006aea61ea08dd6e4834cd43a257ed52d9a31dd3b90000000000000000000000000000000000000000000000000000000064e58a1400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000412210e8a0000000000000000000000000000000000000000000000000000000083104ec2a0bc501c59bceb707d958423bad14c0d0daec84ad067f7e42209ad2cb8d904a55da00a04de4c79ed24b7a82d523b5de63c7ff68a3b7bb519546b3fe4ba8bc90a396600000137f9013480850f7eb06980830317329446ce46951d12710d85bc4fe10bb29c6ea501207787019945ca262000b8c4b2dd898a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000065e4e8d7bd50191abfee6e5bcdc4d16ddfe9975e000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000083104ec2a037979a5225dd156f51abf9a8601e9156e1b1308c0474d69af98c55627886232ea048ac197295187e7ad48aa34cc37c2625434fa812449337732d8522014f4eacfc00000137f9013480850f7eb06980830317329446ce46951d12710d85bc4fe10bb29c6ea501207787019945ca262000b8c4b2dd898a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000065e4e8d7bd50191abfee6e5bcdc4d16ddfe9975e000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000083104ec1a087269dbb9e987e5d58ecd3bcb724cbc4e6c843eb9095de16a25263aebfe06f5aa07f3ac49b6847ba51c5319174e51e088117742240f8555c5c1d77108cf0df90d700000137f9013480850f7eb06980830317329446ce46951d12710d85bc4fe10bb29c6ea501207787019945ca262000b8c4b2dd898a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000065e4e8d7bd50191abfee6e5bcdc4d16ddfe9975e000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000083104ec1a04abdb8572dcabf1996825de6f753124eed41c1292fcfdc4d9a90cb4f8a0f8ff1a06ef25857e2cc9d0fa8b6ecc03b4ba6ef6f3ec1515d570fcc9102e2aa653f347a00000137f9013480850f7eb06980830317329446ce46951d12710d85bc4fe10bb29c6ea501207787019945ca262000b8c4b2dd898a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000065e4e8d7bd50191abfee6e5bcdc4d16ddfe9975e000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000083104ec2a0882202163cbb9a299709b443b663fbab459440deabfbe183e999c98c00ea80c2a010ecb1e5196f0b1ee3d067d9a158b47b1376706e42ce2e769cf8e986935781dd"#)
            .expect("FromHex failure");
        let compressed = {
            let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0)?;
            encoder.set_pledged_src_size(Some(raw.len() as u64))?;
            encoder.include_checksum(false)?;
            encoder.include_magicbytes(false)?;
            encoder.include_contentsize(true)?;
            encoder.write_all(&raw)?;
            encoder.finish()?
        };

        let _witness_rows = process::<Fr>(&compressed, Value::known(Fr::from(123456789)));

        Ok(())
    }

    #[test]
    fn check_witness_generation() -> Result<(), std::io::Error> {
        let compressed: [u8; 559] = [
            0x28, 0xb5, 0x2f, 0xfd, 0x64, 0xae, 0x02, 0x0d, 0x11, 0x00, 0x76, 0x62, 0x5e, 0x23, 0x30, 0x6f,
            0x9b, 0x03, 0x7d, 0xc7, 0x16, 0x0b, 0xbe, 0xc8, 0xf2, 0xd0, 0x22, 0x4b, 0x6b, 0xbc, 0x54, 0x5d,
            0xa9, 0xd4, 0x93, 0xef, 0xc4, 0x54, 0x96, 0xb2, 0xe2, 0xa8, 0xa8, 0x24, 0x1c, 0x54, 0x40, 0x29,
            0x01, 0x55, 0x00, 0x57, 0x00, 0x51, 0x00, 0xcc, 0x51, 0x73, 0x3a, 0x85, 0x9e, 0xf7, 0x59, 0xfc,
            0xc5, 0xca, 0x6a, 0x7a, 0xd9, 0x82, 0x9c, 0x65, 0xc5, 0x45, 0x92, 0xe3, 0x0d, 0xf3, 0xef, 0x71,
            0xee, 0xdc, 0xd5, 0xa2, 0xe3, 0x48, 0xad, 0xa3, 0xbc, 0x41, 0x7a, 0x3c, 0xaa, 0xd6, 0xeb, 0xd0,
            0x77, 0xea, 0xdc, 0x5d, 0x41, 0x06, 0x50, 0x1c, 0x49, 0x0f, 0x07, 0x10, 0x05, 0x88, 0x84, 0x94,
            0x02, 0xfc, 0x3c, 0xe3, 0x60, 0x25, 0xc0, 0xcb, 0x0c, 0xb8, 0xa9, 0x73, 0xbc, 0x13, 0x77, 0xc6,
            0xe2, 0x20, 0xed, 0x17, 0x7b, 0x12, 0xdc, 0x24, 0x5a, 0xdf, 0xb4, 0x21, 0x9a, 0xcb, 0x8f, 0xc7,
            0x58, 0x54, 0x11, 0xa9, 0xf1, 0x47, 0x82, 0x9b, 0xba, 0x60, 0xb4, 0x92, 0x28, 0x0e, 0xfb, 0x8b,
            0x1e, 0x92, 0x23, 0x6a, 0xcf, 0xbf, 0xe5, 0x45, 0xb5, 0x7e, 0xeb, 0x81, 0xf1, 0x78, 0x4b, 0xad,
            0x17, 0x4d, 0x81, 0x9f, 0xbc, 0x67, 0xa7, 0x56, 0xee, 0xb4, 0xd9, 0xe1, 0x95, 0x21, 0x66, 0x0c,
            0x95, 0x83, 0x27, 0xde, 0xac, 0x37, 0x20, 0x91, 0x22, 0x07, 0x0b, 0x91, 0x86, 0x94, 0x1a, 0x7b,
            0xf6, 0x4c, 0xb0, 0xc0, 0xe8, 0x2e, 0x49, 0x65, 0xd6, 0x34, 0x63, 0x0c, 0x88, 0x9b, 0x1c, 0x48,
            0xca, 0x2b, 0x34, 0xa9, 0x6b, 0x99, 0x3b, 0xee, 0x13, 0x3b, 0x7c, 0x93, 0x0b, 0xf7, 0x0d, 0x49,
            0x69, 0x18, 0x57, 0xbe, 0x3b, 0x64, 0x45, 0x1d, 0x92, 0x63, 0x7f, 0xe8, 0xf9, 0xa1, 0x19, 0x7b,
            0x7b, 0x6e, 0xd8, 0xa3, 0x90, 0x23, 0x82, 0xf4, 0xa7, 0xce, 0xc8, 0xf8, 0x90, 0x15, 0xb3, 0x14,
            0xf4, 0x40, 0xe7, 0x02, 0x78, 0xd3, 0x17, 0x71, 0x23, 0xb1, 0x19, 0xad, 0x6b, 0x49, 0xae, 0x13,
            0xa4, 0x75, 0x38, 0x51, 0x47, 0x89, 0x67, 0xb0, 0x39, 0xb4, 0x53, 0x86, 0xa4, 0xac, 0xaa, 0xa3,
            0x34, 0x89, 0xca, 0x2e, 0xe9, 0xc1, 0xfe, 0xf2, 0x51, 0xc6, 0x51, 0x73, 0xaa, 0xf7, 0x9d, 0x2d,
            0xed, 0xd9, 0xb7, 0x4a, 0xb2, 0xb2, 0x61, 0xe4, 0xef, 0x98, 0xf7, 0xc5, 0xef, 0x51, 0x9b, 0xd8,
            0xdc, 0x60, 0x6c, 0x41, 0x76, 0xaf, 0x78, 0x1a, 0x62, 0xb5, 0x4c, 0x1e, 0x21, 0x39, 0x9a, 0x5f,
            0xac, 0x9d, 0xe0, 0x62, 0xe8, 0xe9, 0x2f, 0x2f, 0x48, 0x02, 0x8d, 0x53, 0xc8, 0x91, 0xf2, 0x1a,
            0xd2, 0x7c, 0x0a, 0x7c, 0x48, 0xbf, 0xda, 0xa9, 0xe3, 0x38, 0xda, 0x34, 0xce, 0x76, 0xa9, 0xda,
            0x15, 0x91, 0xde, 0x21, 0xf5, 0x55, 0x46, 0xa8, 0x21, 0x9d, 0x51, 0xcc, 0x18, 0x42, 0x44, 0x81,
            0x8c, 0x94, 0xb4, 0x50, 0x1e, 0x20, 0x42, 0x82, 0x98, 0xc2, 0x3b, 0x10, 0x48, 0xec, 0xa6, 0x39,
            0x63, 0x13, 0xa7, 0x01, 0x94, 0x40, 0xff, 0x88, 0x0f, 0x98, 0x07, 0x4a, 0x46, 0x38, 0x05, 0xa9,
            0xcb, 0xf6, 0xc8, 0x21, 0x59, 0xaa, 0x38, 0x45, 0xbf, 0x5c, 0xf8, 0x55, 0x9e, 0x9f, 0x04, 0xed,
            0xc8, 0x03, 0x42, 0x2a, 0x4b, 0xf6, 0x78, 0x7e, 0x23, 0x67, 0x15, 0xa2, 0x79, 0x29, 0xf4, 0x9b,
            0x7e, 0x00, 0xbc, 0x2f, 0x46, 0x96, 0x99, 0xea, 0xf1, 0xee, 0x1c, 0x6e, 0x06, 0x9c, 0xdb, 0xe4,
            0x8c, 0xc2, 0x05, 0xf7, 0x54, 0x51, 0x84, 0xc0, 0x33, 0x02, 0x01, 0xb1, 0x8c, 0x80, 0xdc, 0x99,
            0x8f, 0xcb, 0x46, 0xff, 0xd1, 0x25, 0xb5, 0xb6, 0x3a, 0xf3, 0x25, 0xbe, 0x85, 0x50, 0x84, 0xf5,
            0x86, 0x5a, 0x71, 0xf7, 0xbd, 0xa1, 0x4c, 0x52, 0x4f, 0x20, 0xa3, 0x61, 0x23, 0x77, 0x12, 0xd3,
            0xb1, 0x58, 0x75, 0x22, 0x01, 0x12, 0x70, 0xec, 0x14, 0x91, 0xf9, 0x85, 0x61, 0xd5, 0x7e, 0x98,
            0x84, 0xc9, 0x76, 0x84, 0xbc, 0xb8, 0xfe, 0x4e, 0x53, 0xa5, 0x06, 0x82, 0x14, 0x95, 0x51,
        ];

        let _witness_rows = process::<Fr>(compressed.as_raw_slice(), Value::known(Fr::from(123456789)));

        Ok(())
    }
}
