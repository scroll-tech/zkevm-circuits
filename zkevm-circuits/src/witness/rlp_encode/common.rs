use crate::witness::RlpTxTag;
use eth_types::{Address, U256, U64};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Value;
use num::Zero;

use super::witness_gen::{RlpDataType, RlpWitnessRow};

pub fn handle_prefix<F: FieldExt>(
    id: usize,
    rlp_data: &[u8],
    rows: &mut Vec<RlpWitnessRow<Value<F>>>,
    data_type: RlpDataType,
    tag: RlpTxTag,
    mut idx: usize,
) -> usize {
    if rlp_data[idx] > 0xf7 {
        // length of length
        let length_of_length = (rlp_data[idx] - 0xf7) as usize;
        let tag_length = length_of_length + 1;
        rows.push(RlpWitnessRow {
            tx_id: id,
            index: idx + 1,
            data_type,
            value: rlp_data[idx],
            value_acc: Value::known(F::zero()),
            value_rlc_acc: Value::known(F::zero()),
            tag,
            tag_length,
            tag_rindex: tag_length,
            length_acc: 0,
        });
        idx += 1;
        let mut length_acc = 0;
        for (k, rlp_byte) in rlp_data[idx..].iter().take(length_of_length).enumerate() {
            length_acc = (length_acc * 256) + (*rlp_byte as u64);
            rows.push(RlpWitnessRow {
                tx_id: id,
                index: idx + 1,
                data_type,
                value: *rlp_byte,
                value_acc: Value::known(F::from(length_acc as u64)),
                value_rlc_acc: Value::known(F::zero()),
                tag,
                tag_length,
                tag_rindex: tag_length - (1 + k),
                length_acc,
            });
            idx += 1;
        }
    } else {
        // length
        assert!(
            rlp_data[idx] >= 0xc0 && rlp_data[idx] < 0xf8,
            "RLP data mismatch({:?}): 0xc0 <= value < 0xf8, got: {:?} at idx: {:?}",
            tag,
            rlp_data[idx],
            idx,
        );
        rows.push(RlpWitnessRow {
            tx_id: id,
            index: idx + 1,
            data_type,
            value: rlp_data[idx],
            value_acc: Value::known(F::from(rlp_data[idx] as u64)),
            value_rlc_acc: Value::known(F::zero()),
            tag,
            tag_length: 1,
            tag_rindex: 1,
            length_acc: (rlp_data[idx] - 192) as u64,
        });
        idx += 1;
    }
    idx
}

pub fn handle_u8<F: FieldExt>(
    tx_id: usize,
    rlp_data: &[u8],
    rows: &mut Vec<RlpWitnessRow<Value<F>>>,
    data_type: RlpDataType,
    tag: RlpTxTag,
    value: u8,
    mut idx: usize,
) -> usize {
    if value == 0 {
        assert_eq!(rlp_data[idx], 0x80);
        rows.push(RlpWitnessRow {
            tx_id,
            index: idx + 1,
            data_type,
            value: rlp_data[idx],
            value_acc: Value::known(F::zero()),
            value_rlc_acc: Value::known(F::zero()),
            tag,
            tag_length: 1,
            tag_rindex: 1,
            length_acc: 0,
        });
        idx += 1;
    } else {
        // TODO: handle this case
        panic!("should never happen");
    }

    idx
}

#[allow(clippy::too_many_arguments)]
pub fn handle_u64<F: FieldExt>(
    tx_id: usize,
    rlp_data: &[u8],
    rows: &mut Vec<RlpWitnessRow<Value<F>>>,
    data_type: RlpDataType,
    tag: RlpTxTag,
    value: U64,
    mut idx: usize,
) -> usize {
    let mut value_bytes = vec![0u8; 8];
    value.to_big_endian(&mut value_bytes);
    let value_bytes = value_bytes
        .iter()
        .skip_while(|b| b.is_zero())
        .cloned()
        .collect::<Vec<u8>>();

    if value_bytes.len() == 1 && value_bytes[0] < 0x80 {
        assert_eq!(
            rlp_data[idx], value_bytes[0],
            "RLP data mismatch({:?}): value < 0x80",
            tag
        );
        rows.push(RlpWitnessRow {
            tx_id,
            index: idx + 1,
            data_type,
            value: value_bytes[0],
            value_acc: Value::known(F::from(value_bytes[0] as u64)),
            value_rlc_acc: Value::known(F::zero()),
            tag,
            tag_length: 1,
            tag_rindex: 1,
            length_acc: 0,
        });
        idx += 1;
    } else {
        assert_eq!(
            rlp_data[idx] as usize,
            0x80 + value_bytes.len(),
            "RLP data mismatch({:?}): len(value)",
            tag
        );
        let tag_length = 1 + value_bytes.len();
        rows.push(RlpWitnessRow {
            tx_id,
            index: idx + 1,
            data_type,
            value: rlp_data[idx],
            value_acc: Value::known(F::zero()),
            value_rlc_acc: Value::known(F::zero()),
            tag,
            tag_length,
            tag_rindex: tag_length,
            length_acc: tag_length as u64 - 1,
        });
        idx += 1;

        let mut value_acc = F::zero();
        for (i, value_byte) in value_bytes.iter().enumerate() {
            assert_eq!(
                rlp_data[idx], *value_byte,
                "RLP data mismatch({:?}): value[{}]",
                tag, i
            );
            value_acc = value_acc * F::from(256) + F::from(*value_byte as u64);
            rows.push(RlpWitnessRow {
                tx_id,
                index: idx + 1,
                data_type,
                value: *value_byte,
                value_acc: Value::known(value_acc),
                value_rlc_acc: Value::known(F::zero()),
                tag,
                tag_length,
                tag_rindex: tag_length - (1 + i),
                length_acc: 0,
            });
            idx += 1;
        }
    }

    idx
}

#[allow(clippy::too_many_arguments)]
pub fn handle_u256<F: FieldExt>(
    randomness: Value<F>,
    id: usize,
    rlp_data: &[u8],
    rows: &mut Vec<RlpWitnessRow<Value<F>>>,
    data_type: RlpDataType,
    tag: RlpTxTag,
    value: U256,
    mut idx: usize,
) -> usize {
    let mut value_bytes = vec![0u8; 32];
    value.to_big_endian(&mut value_bytes);
    let value_bytes = value_bytes
        .iter()
        .skip_while(|b| b.is_zero())
        .cloned()
        .collect::<Vec<u8>>();

    if value_bytes.len() == 1 && value_bytes[0] < 0x80 {
        assert_eq!(
            rlp_data[idx], value_bytes[0],
            "RLP data mismatch({:?}): value < 0x80",
            tag
        );
        rows.push(RlpWitnessRow {
            tx_id: id,
            index: idx + 1,
            data_type,
            value: value_bytes[0],
            value_acc: Value::known(F::from(value_bytes[0] as u64)),
            value_rlc_acc: Value::known(F::zero()),
            tag,
            tag_length: 1,
            tag_rindex: 1,
            length_acc: 0,
        });
        idx += 1;
    } else {
        assert_eq!(
            rlp_data[idx] as usize,
            0x80 + value_bytes.len(),
            "RLP data mismatch({:?}): len(value)",
            tag
        );
        let tag_length = 1 + value_bytes.len();
        rows.push(RlpWitnessRow {
            tx_id: id,
            index: idx + 1,
            data_type,
            value: rlp_data[idx],
            value_acc: Value::known(F::zero()),
            value_rlc_acc: Value::known(F::zero()),
            tag,
            tag_length,
            tag_rindex: tag_length,
            length_acc: value_bytes.len() as u64,
        });
        idx += 1;

        let mut value_acc = Value::known(F::zero());
        for (i, value_byte) in value_bytes.iter().enumerate() {
            assert_eq!(
                rlp_data[idx], *value_byte,
                "RLP data mismatch({:?}): value[{}]",
                tag, i
            );
            value_acc = value_acc
                .zip(randomness)
                .map(|(value_acc, rand)| value_acc * rand + F::from(*value_byte as u64));
            rows.push(RlpWitnessRow {
                tx_id: id,
                index: idx + 1,
                data_type,
                value: *value_byte,
                value_acc,
                value_rlc_acc: Value::known(F::zero()),
                tag,
                tag_length,
                tag_rindex: tag_length - (1 + i),
                length_acc: 0,
            });
            idx += 1;
        }
    }

    idx
}

#[allow(clippy::too_many_arguments)]
pub fn handle_address<F: FieldExt>(
    tx_id: usize,
    rlp_data: &[u8],
    rows: &mut Vec<RlpWitnessRow<Value<F>>>,
    data_type: RlpDataType,
    tag: RlpTxTag,
    value: Address,
    mut idx: usize,
) -> usize {
    let value_bytes = value.as_fixed_bytes();

    if value == Address::zero() {
        assert_eq!(
            rlp_data[idx], 0x80,
            "RLP data mismatch({:?}): value = {}",
            tag, rlp_data[idx]
        );
        rows.push(RlpWitnessRow {
            tx_id,
            index: idx + 1,
            data_type,
            value: rlp_data[idx],
            value_acc: Value::known(F::zero()),
            value_rlc_acc: Value::known(F::zero()),
            tag,
            tag_length: 1,
            tag_rindex: 1,
            length_acc: 0,
        });
    } else {
        assert_eq!(
            rlp_data[idx], 0x94,
            "RLP data mismatch({:?}): value = {}",
            tag, rlp_data[idx]
        );
        rows.push(RlpWitnessRow {
            tx_id,
            index: idx + 1,
            data_type,
            value: rlp_data[idx],
            value_acc: Value::known(F::zero()),
            value_rlc_acc: Value::known(F::zero()),
            tag,
            tag_length: 21,
            tag_rindex: 21,
            length_acc: 20,
        });
        idx += 1;
        let mut value_acc = F::zero();
        assert_eq!(value_bytes.len(), 20);
        for (i, value_byte) in value_bytes.iter().enumerate() {
            assert_eq!(
                rlp_data[idx], *value_byte,
                "RLP data mismatch({:?}): value[{}]",
                tag, i
            );
            value_acc = value_acc * F::from(256) + F::from(*value_byte as u64);
            rows.push(RlpWitnessRow {
                tx_id,
                index: idx + 1,
                data_type,
                value: *value_byte,
                value_acc: Value::known(value_acc),
                value_rlc_acc: Value::known(F::zero()),
                tag,
                tag_length: 21,
                tag_rindex: 21 - (i + 1),
                length_acc: 0,
            });
            idx += 1;
        }
    }

    idx
}

#[allow(clippy::too_many_arguments)]
pub fn handle_bytes<F: FieldExt>(
    randomness: Value<F>,
    tx_id: usize,
    rlp_data: &[u8],
    rows: &mut Vec<RlpWitnessRow<Value<F>>>,
    data_type: RlpDataType,
    prefix_tag: RlpTxTag,
    tag: RlpTxTag,
    call_data: &[u8],
    mut idx: usize,
) -> usize {
    let length = call_data.len();

    if length == 1 && call_data[0] < 0x80 {
        assert_eq!(rlp_data[idx], call_data[0]);
        // add a placeholder row for this case
        rows.push(RlpWitnessRow {
            tx_id,
            index: idx + 1,
            data_type,
            value: call_data[0],
            value_acc: Value::known(F::from(1)),
            value_rlc_acc: Value::known(F::zero()),
            tag: prefix_tag,
            tag_length: 1,
            tag_rindex: 1,
            length_acc: 1,
        });
        rows.push(RlpWitnessRow {
            tx_id,
            index: idx + 1,
            data_type,
            value: call_data[0],
            value_acc: Value::known(F::from(call_data[0] as u64)),
            value_rlc_acc: Value::known(F::from(call_data[0] as u64)),
            tag,
            tag_length: 1,
            tag_rindex: 1,
            length_acc: 0,
        });
        idx += 1;
    } else if length < 56 {
        assert_eq!(
            rlp_data[idx] as usize,
            0x80 + length,
            "RLP data mismatch({:?}): len(call_data) + 128",
            prefix_tag
        );
        rows.push(RlpWitnessRow {
            tx_id,
            index: idx + 1,
            data_type,
            value: (0x80 + length) as u8,
            value_acc: Value::known(F::from((length) as u64)),
            value_rlc_acc: Value::known(F::zero()),
            tag: prefix_tag,
            tag_length: 1,
            tag_rindex: 1,
            length_acc: length as u64,
        });
        idx += 1;

        let mut value_acc_rlc = Value::known(F::zero());
        for (i, data_byte) in call_data.iter().enumerate() {
            assert_eq!(
                rlp_data[idx], *data_byte,
                "RLP data mismatch({:?}): value[{}]",
                tag, i
            );
            value_acc_rlc = value_acc_rlc
                .zip(randomness)
                .map(|(acc, rand)| acc * rand + F::from(*data_byte as u64));
            rows.push(RlpWitnessRow {
                tx_id,
                index: idx + 1,
                data_type,
                value: *data_byte,
                value_acc: Value::known(F::from(*data_byte as u64)),
                value_rlc_acc: value_acc_rlc,
                tag,
                tag_length: length,
                tag_rindex: length - i,
                length_acc: 0,
            });
            idx += 1;
        }
    } else {
        // length > 55.
        let length_of_length = 8 - length.leading_zeros() as usize / 8;
        assert_eq!(
            rlp_data[idx] as usize,
            0xb7 + length_of_length,
            "RLP data mismatch({:?}): len_of_len(call_data) + 0xb7",
            prefix_tag
        );
        let tag_length = 1 + length_of_length;
        rows.push(RlpWitnessRow {
            tx_id,
            index: idx + 1,
            data_type,
            value: rlp_data[idx],
            value_acc: Value::known(F::zero()),
            value_rlc_acc: Value::known(F::zero()),
            tag: prefix_tag,
            tag_length,
            tag_rindex: tag_length,
            length_acc: 0,
        });
        idx += 1;

        let length_bytes = length.to_be_bytes();
        let length_bytes = length_bytes
            .iter()
            .skip_while(|b| b.is_zero())
            .cloned()
            .collect::<Vec<u8>>();
        assert_eq!(length_bytes.len(), length_of_length);

        let mut length_acc = 0;
        for (i, length_byte) in length_bytes.iter().enumerate() {
            assert_eq!(
                rlp_data[idx], *length_byte,
                "RLP data mismatch({:?}): length[{}]",
                prefix_tag, i
            );
            length_acc = length_acc * 256 + (*length_byte as u64);
            rows.push(RlpWitnessRow {
                tx_id,
                index: idx + 1,
                data_type,
                value: *length_byte,
                value_acc: Value::known(F::from(length_acc as u64)),
                value_rlc_acc: Value::known(F::zero()),
                tag: prefix_tag,
                tag_length,
                tag_rindex: tag_length - (1 + i),
                length_acc,
            });
            idx += 1;
        }
        assert_eq!(length_acc as usize, length);

        let tag_length = call_data.len();
        let mut value_rlc_acc = Value::known(F::zero());
        for (i, data_byte) in call_data.iter().enumerate() {
            assert_eq!(
                rlp_data[idx], *data_byte,
                "RLP data mismatch({:?}): data[{}]",
                tag, i
            );
            value_rlc_acc = value_rlc_acc
                .zip(randomness)
                .map(|(acc, rand)| acc * rand + F::from(*data_byte as u64));
            rows.push(RlpWitnessRow {
                tx_id,
                index: idx + 1,
                data_type,
                value: *data_byte,
                value_acc: Value::known(F::from(*data_byte as u64)),
                value_rlc_acc,
                tag,
                tag_length,
                tag_rindex: tag_length - i,
                length_acc: 0,
            });
            idx += 1;
        }
    }

    idx
}
