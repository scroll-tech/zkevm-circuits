//! Utility traits, functions used in the crate.

use super::param::*;
use eth_types::{Field, ToScalar, Word};
use halo2_proofs::{circuit::Value, halo2curves::FieldExt};
use std::env::var;

/// Description of which bits (positions) a part contains
#[derive(Clone, Debug)]
pub(crate) struct PartInfo {
    /// The bit positions of the part
    pub(crate) bits: Vec<usize>,
}

/// Description of how a word is split into parts
#[derive(Clone, Debug)]
pub(crate) struct WordParts {
    /// The parts of the word
    pub(crate) parts: Vec<PartInfo>,
}

impl WordParts {
    /// Returns a description of how a word will be split into parts
    pub(crate) fn new(part_size: usize, rot: usize, normalize: bool) -> Self {
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

/// Rotates a word that was split into parts to the right
pub(crate) fn rotate<T>(parts: Vec<T>, count: usize, part_size: usize) -> Vec<T> {
    let mut rotated_parts = parts;
    rotated_parts.rotate_right(get_rotate_count(count, part_size));
    rotated_parts
}

/// Rotates a word that was split into parts to the left
pub(crate) fn rotate_rev<T>(parts: Vec<T>, count: usize, part_size: usize) -> Vec<T> {
    let mut rotated_parts = parts;
    rotated_parts.rotate_left(get_rotate_count(count, part_size));
    rotated_parts
}

/// Rotates bits left
pub(crate) fn rotate_left(bits: &[u8], count: usize) -> [u8; NUM_BITS_PER_WORD] {
    let mut rotated = bits.to_vec();
    rotated.rotate_left(count);
    rotated.try_into().unwrap()
}

/// The words that absorb data
pub(crate) fn get_absorb_positions() -> Vec<(usize, usize)> {
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
pub(crate) fn into_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits: Vec<u8> = vec![0; bytes.len() * 8];
    for (byte_idx, byte) in bytes.iter().enumerate() {
        for idx in 0u64..8 {
            bits[byte_idx * 8 + (idx as usize)] = (*byte >> idx) & 1;
        }
    }
    bits
}

/// Pack bits in the range [0,BIT_SIZE[ into a sparse keccak word
pub(crate) fn pack<F: Field>(bits: &[u8]) -> F {
    pack_with_base(bits, BIT_SIZE)
}

/// Pack bits in the range [0,BIT_SIZE[ into a sparse keccak word with the
/// specified bit base
pub(crate) fn pack_with_base<F: Field>(bits: &[u8], base: usize) -> F {
    let base = F::from(base as u64);
    bits.iter()
        .rev()
        .fold(F::zero(), |acc, &bit| acc * base + F::from(bit as u64))
}

/// Decodes the bits using the position data found in the part info
pub(crate) fn pack_part(bits: &[u8], info: &PartInfo) -> u64 {
    info.bits.iter().rev().fold(0u64, |acc, &bit_pos| {
        acc * (BIT_SIZE as u64) + (bits[bit_pos] as u64)
    })
}

/// Unpack a sparse keccak word into bits in the range [0,BIT_SIZE[
pub(crate) fn unpack<F: Field>(packed: F) -> [u8; NUM_BITS_PER_WORD] {
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
pub(crate) fn pack_u64<F: Field>(value: u64) -> F {
    pack(
        &((0..NUM_BITS_PER_WORD)
            .map(|i| ((value >> i) & 1) as u8)
            .collect::<Vec<_>>()),
    )
}

/// Calculates a ^ b with a and b field elements
pub(crate) fn field_xor<F: Field>(a: F, b: F) -> F {
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
pub(crate) fn target_part_sizes(part_size: usize) -> Vec<usize> {
    let num_full_chunks = NUM_BITS_PER_WORD / part_size;
    let partial_chunk_size = NUM_BITS_PER_WORD % part_size;
    let mut part_sizes = vec![part_size; num_full_chunks];
    if partial_chunk_size > 0 {
        part_sizes.push(partial_chunk_size);
    }
    part_sizes
}

/// Gets the rotation count in parts
pub(crate) fn get_rotate_count(count: usize, part_size: usize) -> usize {
    (count + part_size - 1) / part_size
}

/// Get the degree of the circuit from the KECCAK_DEGREE env variable
pub(crate) fn get_degree() -> usize {
    var("KECCAK_DEGREE")
        .unwrap_or_else(|_| "8".to_string())
        .parse()
        .expect("Cannot parse KECCAK_DEGREE env var as usize")
}

/// Returns how many bits we can process in a single lookup given the range of
/// values the bit can have and the height of the circuit (via KECCAK_DEGREE).
pub fn get_num_bits_per_lookup(range: usize) -> usize {
    let log_height = get_degree();
    get_num_bits_per_lookup_impl(range, log_height)
}

// Implementation of the above without environment dependency.
fn get_num_bits_per_lookup_impl(range: usize, log_height: usize) -> usize {
    let num_unusable_rows = 31;
    let height = 2usize.pow(log_height as u32);
    let mut num_bits = 1;
    while range.pow(num_bits + 1) + num_unusable_rows <= height {
        num_bits += 1;
    }
    num_bits as usize
}

pub(crate) fn extract_field<F: FieldExt>(value: Value<F>) -> F {
    let mut field = F::zero();
    let _ = value.map(|f| {
        field = f;
        f
    });
    field
}

/// Encodes the data using rlc
pub(crate) mod compose_rlc {
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
pub(crate) mod scatter {
    use super::pack;
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(value: u8, count: usize) -> Expression<F> {
        Expression::Constant(pack(&vec![value; count]))
    }
}

/// Packs bits into bytes
pub(crate) mod to_bytes {
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

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::{CellValue, MockProver};
    use halo2_proofs::halo2curves::bn256::Fr as F;
    use halo2_proofs::plonk::{Circuit, ConstraintSystem};
    use itertools::Itertools;
    use std::iter::zip;

    #[test]
    fn pack_table() {
        let msb = 1 << (7 * 3);
        for (idx, expected) in [(0, 0), (1, 1), (128, msb), (129, msb | 1)] {
            let packed: F = pack(&into_bits(&[idx as u8]));
            assert_eq!(packed, F::from(expected));
        }
    }

    #[test]
    fn num_bits_per_lookup() {
        // Typical values.
        assert_eq!(get_num_bits_per_lookup_impl(3, 19), 11);
        assert_eq!(get_num_bits_per_lookup_impl(4, 19), 9);
        assert_eq!(get_num_bits_per_lookup_impl(5, 19), 8);
        assert_eq!(get_num_bits_per_lookup_impl(6, 19), 7);
        // The largest imaginable value does not overflow u64.
        assert_eq!(get_num_bits_per_lookup_impl(3, 32) * BIT_COUNT, 60);
    }

    #[test]
    fn normalize_table() {
        normalize_table_impl(3, 10);
        normalize_table_impl(4, 10);
        normalize_table_impl(6, 10);
        normalize_table_impl(6, 19);
    }

    fn normalize_table_impl(range: usize, log_height: usize) {
        let table = build_table(&TableTestCircuit {
            range,
            log_height,
            normalize_else_chi: true,
        });

        // On all rows, all inputs/outputs are correct, i.e. they have the same low bit.
        assert_eq!(BIT_COUNT, 3);
        for (inp, out) in table.iter() {
            for pos in (0..64).step_by(BIT_COUNT) {
                assert_eq!((inp >> pos) & 1, (out >> pos) & (4 + 2 + 1));
            }
        }
    }

    #[test]
    fn chi_table() {
        // Check the base pattern for all combinations of bits.
        for i in 0..16_usize {
            let (a, b, c, d) = (i & 1, (i >> 1) & 1, (i >> 2) & 1, (i >> 3) & 1);
            assert_eq!(
                CHI_BASE_LOOKUP_TABLE[3 - 2 * a + b - c],
                (a ^ ((!b) & c)) as u8
            );
            assert_eq!(
                CHI_EXT_LOOKUP_TABLE[5 - 2 * a - b + c - 2 * d],
                (a ^ ((!b) & c) ^ d) as u8
            );
        }

        // Check the table with multiple parts per row.
        chi_table_impl(10);
        chi_table_impl(19);
    }

    fn chi_table_impl(log_height: usize) {
        let range = 5; // CHI_BASE_LOOKUP_RANGE
        let table = build_table(&TableTestCircuit {
            range,
            log_height,
            normalize_else_chi: false,
        });

        // On all rows, all input/output pairs match the base table.
        for (inp, out) in table.iter() {
            for pos in (0..64).step_by(BIT_COUNT) {
                let inp = ((inp >> pos) & 7) as usize;
                let out = ((out >> pos) & 7) as u8;
                assert_eq!(out, CHI_BASE_LOOKUP_TABLE[inp]);
            }
        }
    }

    // ---- Helpers ----

    fn build_table(circuit: &TableTestCircuit) -> Vec<(u64, u64)> {
        let prover = MockProver::<F>::run(circuit.log_height as u32, circuit, vec![]).unwrap();

        let columns = prover.fixed();
        assert_eq!(columns.len(), 2);
        let unused_rows = 6; // What MockProver uses on this test circuit.
        let used_rows = (1 << circuit.log_height) - unused_rows;

        // Check the unused rows.
        for io in zip(&columns[0], &columns[1]).skip(used_rows) {
            assert_eq!(io, (&CellValue::Unassigned, &CellValue::Unassigned));
        }

        // Get the generated lookup table with the form: table[row] = (input, output).
        let table = zip(&columns[0], &columns[1])
            .take(used_rows)
            .map(|(inp, out)| (unwrap_u64(inp), unwrap_u64(out)))
            .collect::<Vec<_>>();

        // All possible combinations of inputs are there.
        let unique_rows = table.iter().unique().count();
        assert_eq!(unique_rows, circuit.expected_num_entries());

        table
    }

    #[derive(Clone)]
    struct TableTestCircuit {
        range: usize,
        log_height: usize,
        normalize_else_chi: bool,
    }

    impl TableTestCircuit {
        fn expected_num_entries(&self) -> usize {
            let num_bits = get_num_bits_per_lookup_impl(self.range, self.log_height);
            self.range.pow(num_bits as u32)
        }
    }

    impl Circuit<F> for TableTestCircuit {
        type Config = [TableColumn; 2];
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            array_init::array_init(|_| meta.lookup_table_column())
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            if self.normalize_else_chi {
                load_normalize_table_impl(
                    &mut layouter,
                    "normalize",
                    &config,
                    self.range as u64,
                    self.log_height,
                )?;
            } else {
                let num_bits = get_num_bits_per_lookup_impl(self.range, self.log_height);
                load_lookup_table(
                    &mut layouter,
                    "chi base",
                    &config,
                    num_bits,
                    &CHI_BASE_LOOKUP_TABLE,
                )?;
            }
            Ok(())
        }
    }

    fn unwrap_u64<F: Field>(cv: &CellValue<F>) -> u64 {
        match *cv {
            CellValue::Assigned(f) => {
                let f = f.get_lower_128();
                assert_eq!(f >> 64, 0);
                f as u64
            }
            _ => panic!("the cell should be assigned"),
        }
    }
}
