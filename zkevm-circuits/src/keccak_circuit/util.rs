//! Utility traits, functions used in the crate.

use eth_types::{Field, ToScalar, Word};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Error, TableColumn},
};
use itertools::Itertools;
use std::env::var;

pub(crate) const NUM_BITS_PER_BYTE: usize = 8;
pub(crate) const NUM_BYTES_PER_WORD: usize = 8;
pub(crate) const NUM_BITS_PER_WORD: usize = NUM_BYTES_PER_WORD * NUM_BITS_PER_BYTE;
pub(crate) const KECCAK_WIDTH: usize = 5 * 5;
pub(crate) const KECCAK_WIDTH_IN_BITS: usize = KECCAK_WIDTH * NUM_BITS_PER_WORD;
pub(crate) const NUM_ROUNDS: usize = 24;
pub(crate) const NUM_WORDS_TO_ABSORB: usize = 17;
pub(crate) const NUM_WORDS_TO_SQUEEZE: usize = 4;
pub(crate) const ABSORB_WIDTH_PER_ROW: usize = NUM_BITS_PER_WORD;
pub(crate) const ABSORB_WIDTH_PER_ROW_BYTES: usize = ABSORB_WIDTH_PER_ROW / NUM_BITS_PER_BYTE;
pub(crate) const RATE: usize = NUM_WORDS_TO_ABSORB * NUM_BYTES_PER_WORD;
pub(crate) const RATE_IN_BITS: usize = RATE * NUM_BITS_PER_BYTE;
pub(crate) const THETA_C_WIDTH: usize = 5 * NUM_BITS_PER_WORD;
pub(crate) const RHO_MATRIX: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];
pub(crate) const ROUND_CST: [u64; NUM_ROUNDS + 1] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
    0x0000000000000000, // absorb round
];
// Bit positions that have a non-zero value in `IOTA_ROUND_CST`.
pub(crate) const ROUND_CST_BIT_POS: [usize; 7] = [0, 1, 3, 7, 15, 31, 63];

// The number of bits used in the sparse word representation per bit
pub(crate) const BIT_COUNT: usize = 3;
// The base of the bit in the sparse word representation
pub(crate) const BIT_SIZE: usize = 2usize.pow(BIT_COUNT as u32);

// `a ^ ((~b) & c)` is calculated by doing `lookup[3 - 2*a + b - c]`
pub(crate) const CHI_BASE_LOOKUP_TABLE: [u8; 5] = [0, 1, 1, 0, 0];
// `a ^ ((~b) & c) ^ d` is calculated by doing `lookup[5 - 2*a - b + c - 2*d]`
pub(crate) const CHI_EXT_LOOKUP_TABLE: [u8; 7] = [0, 0, 1, 1, 0, 0, 1];

/// Description of which bits (positions) a part contains
#[derive(Clone, Debug)]
pub struct PartInfo {
    /// The bit positions of the part
    pub bits: Vec<usize>,
}

/// Description of how a word is split into parts
#[derive(Clone, Debug)]
pub struct WordParts {
    /// The parts of the word
    pub parts: Vec<PartInfo>,
}

/// Packs bits into bytes
pub mod to_bytes {
    use eth_types::Field;
    use gadgets::util::Expr;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(bits: &[Expression<F>]) -> Vec<Expression<F>> {
        debug_assert!(bits.len() % 8 == 0, "bits not a multiple of 8");
        let mut bytes = Vec::new();
        for byte_bits in bits.chunks(8) {
            let mut value = 0.expr();
            let mut multiplier = F::one();
            for byte in byte_bits.iter() {
                value = value + byte.expr() * multiplier;
                multiplier *= F::from(2);
            }
            bytes.push(value);
        }
        bytes
    }

    pub(crate) fn value(bits: &[u8]) -> Vec<u8> {
        debug_assert!(bits.len() % 8 == 0, "bits not a multiple of 8");
        let mut bytes = Vec::new();
        for byte_bits in bits.chunks(8) {
            let mut value = 0u8;
            for (idx, bit) in byte_bits.iter().enumerate() {
                value += *bit << idx;
            }
            bytes.push(value);
        }
        bytes
    }
}

/// Rotates a word that was split into parts to the right
pub fn rotate<T>(parts: Vec<T>, count: usize, part_size: usize) -> Vec<T> {
    let mut rotated_parts = parts;
    rotated_parts.rotate_right(get_rotate_count(count, part_size));
    rotated_parts
}

/// Rotates a word that was split into parts to the left
pub fn rotate_rev<T>(parts: Vec<T>, count: usize, part_size: usize) -> Vec<T> {
    let mut rotated_parts = parts;
    rotated_parts.rotate_left(get_rotate_count(count, part_size));
    rotated_parts
}

/// Rotates bits left
pub fn rotate_left(bits: &[u8], count: usize) -> [u8; NUM_BITS_PER_WORD] {
    let mut rotated = bits.to_vec();
    rotated.rotate_left(count);
    rotated.try_into().unwrap()
}

/// Encodes the data using rlc
pub mod compose_rlc {
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(expressions: &[Expression<F>], r: Expression<F>) -> Expression<F> {
        let mut rlc = expressions[0].clone();
        let mut multiplier = r.clone();
        for expression in expressions[1..].iter() {
            rlc = rlc + expression.clone() * multiplier.clone();
            multiplier = multiplier * r.clone();
        }
        rlc
    }
}

/// Scatters a value into a packed word constant
pub mod scatter {
    use super::pack;
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(value: u8, count: usize) -> Expression<F> {
        Expression::Constant(pack(&vec![value; count]))
    }
}

/// The words that absorb data
pub fn get_absorb_positions() -> Vec<(usize, usize)> {
    let mut absorb_positions = Vec::new();
    for j in 0..5 {
        for i in 0..5 {
            if i + j * 5 < 17 {
                absorb_positions.push((i, j));
            }
        }
    }
    absorb_positions
}

/// Converts bytes into bits
pub fn into_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits: Vec<u8> = vec![0; bytes.len() * 8];
    for (byte_idx, byte) in bytes.iter().enumerate() {
        for idx in 0u64..8 {
            bits[byte_idx * 8 + (idx as usize)] = (*byte >> idx) & 1;
        }
    }
    bits
}

/// Pack bits in the range [0,BIT_SIZE[ into a sparse keccak word
pub fn pack<F: Field>(bits: &[u8]) -> F {
    pack_with_base(bits, BIT_SIZE)
}

/// Pack bits in the range [0,BIT_SIZE[ into a sparse keccak word with the
/// specified bit base
pub fn pack_with_base<F: Field>(bits: &[u8], base: usize) -> F {
    let base = F::from(base as u64);
    bits.iter()
        .rev()
        .fold(F::zero(), |acc, &bit| acc * base + F::from(bit as u64))
}

/// Decodes the bits using the position data found in the part info
pub fn pack_part(bits: &[u8], info: &PartInfo) -> u64 {
    info.bits.iter().rev().fold(0u64, |acc, &bit_pos| {
        acc * (BIT_SIZE as u64) + (bits[bit_pos] as u64)
    })
}

/// Unpack a sparse keccak word into bits in the range [0,BIT_SIZE[
pub fn unpack<F: Field>(packed: F) -> [u8; NUM_BITS_PER_WORD] {
    let mut bits = [0; NUM_BITS_PER_WORD];
    let packed = Word::from_little_endian(packed.to_repr().as_ref());
    let mask = Word::from(BIT_SIZE - 1);
    for (idx, bit) in bits.iter_mut().enumerate() {
        *bit = ((packed >> (idx * BIT_COUNT)) & mask).as_u32() as u8;
    }
    debug_assert_eq!(pack::<F>(&bits), packed.to_scalar().unwrap());
    bits
}

/// Pack bits stored in a u64 value into a sparse keccak word
pub fn pack_u64<F: Field>(value: u64) -> F {
    pack(
        &((0..NUM_BITS_PER_WORD)
            .map(|i| ((value >> i) & 1) as u8)
            .collect::<Vec<_>>()),
    )
}

/// Calculates a ^ b with a and b field elements
pub fn field_xor<F: Field>(a: F, b: F) -> F {
    let mut bytes = [0u8; 32];
    for (idx, (a, b)) in a
        .to_repr()
        .as_ref()
        .iter()
        .zip(b.to_repr().as_ref().iter())
        .enumerate()
    {
        bytes[idx] = *a ^ *b;
    }
    F::from_repr(bytes).unwrap()
}

/// Returns the size (in bits) of each part size when splitting up a keccak word
/// in parts of `part_size`
pub fn target_part_sizes(part_size: usize) -> Vec<usize> {
    let num_full_chunks = NUM_BITS_PER_WORD / part_size;
    let partial_chunk_size = NUM_BITS_PER_WORD % part_size;
    let mut part_sizes = vec![part_size; num_full_chunks];
    if partial_chunk_size > 0 {
        part_sizes.push(partial_chunk_size);
    }
    part_sizes
}

/// Gets the rotation count in parts
pub fn get_rotate_count(count: usize, part_size: usize) -> usize {
    (count + part_size - 1) / part_size
}

impl WordParts {
    /// Returns a description of how a word will be split into parts
    pub fn new(part_size: usize, rot: usize, normalize: bool) -> Self {
        let mut bits = (0usize..64).collect::<Vec<_>>();
        bits.rotate_right(rot);

        let mut parts = Vec::new();
        let mut rot_idx = 0;

        let mut idx = 0;
        let target_sizes = if normalize {
            // After the rotation we want the parts of all the words to be at the same
            // positions
            target_part_sizes(part_size)
        } else {
            // Here we only care about minimizing the number of parts
            let num_parts_a = rot / part_size;
            let partial_part_a = rot % part_size;

            let num_parts_b = (64 - rot) / part_size;
            let partial_part_b = (64 - rot) % part_size;

            let mut part_sizes = vec![part_size; num_parts_a];
            if partial_part_a > 0 {
                part_sizes.push(partial_part_a);
            }

            part_sizes.extend(vec![part_size; num_parts_b]);
            if partial_part_b > 0 {
                part_sizes.push(partial_part_b);
            }

            part_sizes
        };
        // Split into parts bit by bit
        for part_size in target_sizes {
            let mut num_consumed = 0;
            while num_consumed < part_size {
                let mut part_bits: Vec<usize> = Vec::new();
                while num_consumed < part_size {
                    if !part_bits.is_empty() && bits[idx] == 0 {
                        break;
                    }
                    if bits[idx] == 0 {
                        rot_idx = parts.len();
                    }
                    part_bits.push(bits[idx]);
                    idx += 1;
                    num_consumed += 1;
                }
                parts.push(PartInfo { bits: part_bits });
            }
        }

        debug_assert_eq!(get_rotate_count(rot, part_size), rot_idx);

        parts.rotate_left(rot_idx);
        debug_assert_eq!(parts[0].bits[0], 0);

        Self { parts }
    }
}

/// Get the degree of the circuit from the KECCAK_DEGREE env variable
pub fn get_degree() -> usize {
    var("KECCAK_DEGREE")
        .unwrap_or_else(|_| "8".to_string())
        .parse()
        .expect("Cannot parse KECCAK_DEGREE env var as usize")
}

/// Returns how many bits we can process in a single lookup given the range of
/// values the bit can have and the height of the circuit.
pub fn get_num_bits_per_lookup(range: usize) -> usize {
    let num_unusable_rows = 31;
    let degree = get_degree() as u32;
    let mut num_bits = 1;
    while range.pow(num_bits + 1) + num_unusable_rows <= 2usize.pow(degree) {
        num_bits += 1;
    }
    num_bits as usize
}

/// Loads a normalization table with the given parameters
pub fn load_normalize_table<F: Field>(
    layouter: &mut impl Layouter<F>,
    name: &str,
    tables: &[TableColumn; 2],
    range: u64,
) -> Result<(), Error> {
    let part_size = get_num_bits_per_lookup(range as usize);
    layouter.assign_table(
        || format!("{} table", name),
        |mut table| {
            for (offset, perm) in (0..part_size)
                .map(|_| 0u64..range)
                .multi_cartesian_product()
                .enumerate()
            {
                let mut input = 0u64;
                let mut output = 0u64;
                let mut factor = 1u64;
                for input_part in perm.iter() {
                    input += input_part * factor;
                    output += (input_part & 1) * factor;
                    factor *= BIT_SIZE as u64;
                }
                table.assign_cell(
                    || format!("{} input", name),
                    tables[0],
                    offset,
                    || Value::known(F::from(input)),
                )?;
                table.assign_cell(
                    || format!("{} output", name),
                    tables[1],
                    offset,
                    || Value::known(F::from(output)),
                )?;
            }
            Ok(())
        },
    )
}

/// Loads the byte packing table
pub fn load_pack_table<F: Field>(
    layouter: &mut impl Layouter<F>,
    tables: &[TableColumn; 2],
) -> Result<(), Error> {
    layouter.assign_table(
        || "pack table",
        |mut table| {
            for (offset, idx) in (0u64..256).enumerate() {
                table.assign_cell(
                    || "unpacked",
                    tables[0],
                    offset,
                    || Value::known(F::from(idx)),
                )?;
                let packed: F = pack(&into_bits(&[idx as u8]));
                table.assign_cell(|| "packed", tables[1], offset, || Value::known(packed))?;
            }
            Ok(())
        },
    )
}

/// Loads a lookup table
pub fn load_lookup_table<F: Field>(
    layouter: &mut impl Layouter<F>,
    name: &str,
    tables: &[TableColumn; 2],
    part_size: usize,
    lookup_table: &[u8],
) -> Result<(), Error> {
    layouter.assign_table(
        || format!("{} table", name),
        |mut table| {
            for (offset, perm) in (0..part_size)
                .map(|_| 0..lookup_table.len() as u64)
                .multi_cartesian_product()
                .enumerate()
            {
                let mut input = 0u64;
                let mut output = 0u64;
                let mut factor = 1u64;
                for input_part in perm.iter() {
                    input += input_part * factor;
                    output += (lookup_table[*input_part as usize] as u64) * factor;
                    factor *= BIT_SIZE as u64;
                }
                table.assign_cell(
                    || format!("{} input", name),
                    tables[0],
                    offset,
                    || Value::known(F::from(input)),
                )?;
                table.assign_cell(
                    || format!("{} output", name),
                    tables[1],
                    offset,
                    || Value::known(F::from(output)),
                )?;
            }
            Ok(())
        },
    )
}
