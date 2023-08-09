use crate::{table::BytecodeFieldTag, util::get_push_size};
use bus_mapping::state_db::CodeDB;
use eth_types::{Field, ToWord, Word, U256};
use std::vec;

/// Public data for the bytecode
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BytecodeRow<F: Field> {
    pub(crate) code_hash: Word,
    pub(crate) tag: F,
    pub(crate) index: F,
    pub(crate) is_code: F,
    pub(crate) value: F,
}

/// Unrolled bytecode
#[derive(Clone, Debug, PartialEq, Default)]
pub struct UnrolledBytecode<F: Field> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) rows: Vec<BytecodeRow<F>>,
}

/// Get unrolled bytecode from raw bytes
pub fn unroll<F: Field>(bytes: Vec<u8>) -> UnrolledBytecode<F> {
    let code_hash = CodeDB::hash(&bytes[..]);
    unroll_with_codehash(code_hash.to_word(), bytes)
}

/// Get unrolled bytecode from raw bytes and codehash
pub fn unroll_with_codehash<F: Field>(code_hash: U256, bytes: Vec<u8>) -> UnrolledBytecode<F> {
    let mut rows = vec![BytecodeRow::<F> {
        code_hash,
        tag: F::from(BytecodeFieldTag::Header as u64),
        index: F::zero(),
        is_code: F::zero(),
        value: F::from(bytes.len() as u64),
    }];
    // Run over all the bytes
    let mut push_rindex = 0;
    for (index, byte) in bytes.iter().enumerate() {
        // Track which byte is an opcode and which is push data
        let is_code = push_rindex == 0;
        push_rindex = if is_code {
            get_push_size(*byte)
        } else {
            push_rindex - 1
        };

        rows.push(BytecodeRow::<F> {
            code_hash,
            tag: F::from(BytecodeFieldTag::Byte as u64),
            index: F::from(index as u64),
            is_code: F::from(is_code as u64),
            value: F::from(*byte as u64),
        });
    }
    UnrolledBytecode { bytes, rows }
}

use crate::table::PoseidonTable;
/// re-export bytes wrapped in hash field
/// specify byte in field for encoding bytecode
pub use bus_mapping::util::POSEIDON_HASH_BYTES_IN_FIELD as HASHBLOCK_BYTES_IN_FIELD;

/// Get unrolled hash inputs as inputs to hash circuit
pub fn unroll_to_hash_input<F: Field, const BYTES_IN_FIELD: usize, const INPUT_LEN: usize>(
    code: impl ExactSizeIterator<Item = u8>,
) -> Vec<[F; INPUT_LEN]> {
    let fl_cnt = code.len() / BYTES_IN_FIELD;
    let fl_cnt = if code.len() % BYTES_IN_FIELD != 0 {
        fl_cnt + 1
    } else {
        fl_cnt
    };

    let (msgs, _) = code
        .chain(std::iter::repeat(0))
        .take(fl_cnt * BYTES_IN_FIELD)
        .fold((Vec::new(), Vec::new()), |(mut msgs, mut cache), bt| {
            cache.push(bt);
            if cache.len() == BYTES_IN_FIELD {
                let mut buf: [u8; 64] = [0; 64];
                U256::from_big_endian(&cache).to_little_endian(&mut buf[0..32]);
                msgs.push(F::from_bytes_wide(&buf));
                cache.clear();
            }
            (msgs, cache)
        });

    let input_cnt = msgs.len() / INPUT_LEN;
    let input_cnt = if msgs.len() % INPUT_LEN != 0 {
        input_cnt + 1
    } else {
        input_cnt
    };
    if input_cnt == 0 {
        return Vec::new();
    }

    let (mut inputs, last) = msgs
        .into_iter()
        .chain(std::iter::repeat(F::zero()))
        .take(input_cnt * INPUT_LEN)
        .fold(
            (Vec::new(), [None; INPUT_LEN]),
            |(mut msgs, mut v_arr), f| {
                if let Some(v) = v_arr.iter_mut().find(|v| v.is_none()) {
                    v.replace(f);
                    (msgs, v_arr)
                } else {
                    msgs.push(v_arr.map(|v| v.unwrap()));
                    let mut v_arr = [None; INPUT_LEN];
                    v_arr[0].replace(f);
                    (msgs, v_arr)
                }
            },
        );

    inputs.push(last.map(|v| v.unwrap()));
    inputs
}

/// Apply default constants in mod
pub fn unroll_to_hash_input_default<F: Field>(
    code: impl ExactSizeIterator<Item = u8>,
) -> Vec<[F; PoseidonTable::INPUT_WIDTH]> {
    unroll_to_hash_input::<F, HASHBLOCK_BYTES_IN_FIELD, { PoseidonTable::INPUT_WIDTH }>(code)
}
