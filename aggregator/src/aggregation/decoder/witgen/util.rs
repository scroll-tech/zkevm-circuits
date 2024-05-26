use bitstream_io::{
    read::{BitRead, BitReader},
    LittleEndian,
};
use std::io::{Cursor, Result};

use super::N_BITS_PER_BYTE;

/// Given a bitstream and a range 0..=r for the value to be read from an offset, this function reads
/// a variable number of bits from the bitstream as per "FSE Table Description" in [RFC
/// 8478][doclink].
///
/// It returns the tuple (n, v) for:
/// - n: number of bits read from bitstream
/// - v: the read value that is in the range 0..=r
///
/// [doclink]: https://www.rfc-editor.org/rfc/rfc8478.txt
pub fn read_variable_bit_packing(src: &[u8], offset: u32, r: u64) -> Result<(u32, u64, u64)> {
    // construct a bit-reader.
    let mut reader = BitReader::endian(Cursor::new(&src), LittleEndian);

    // number of bits required to fit a value in the range 0..=r.
    let size = bit_length(r) as u32;
    let max = 1 << size;

    // if there is no need for variable bit-packing, i.e. if the range is 0..=(2^k - 1)
    if r + 1 == max {
        reader.skip(offset)?;
        let value = reader.read::<u64>(size)?;
        return Ok((size, value, value));
    }

    // lo_pin denotes the pin where if the value read is below the pin, its considered a low value
    // and we can pack it in size-1 number of bits.
    //
    // since there are 0..=r, effectively r+1 different values possible to be read, an obvious size
    // bits encoding would waste lo_pin number of possible 8-bit bitstrings.
    //
    // | Value Read              | Value Decoded         | Bits Used |
    // |-------------------------|-----------------------|-----------|
    // | 0 .. lo_pin             | lo_value_read         | size - 1  |
    // | lo_pin .. hi_pin_1      | value_read            | size      |
    // | hi_pin_1 .. hi_pin_2    | value_read - hi_pin_1 | size - 1  |
    // | hi_pin_2 .. (1 << size) | value_read - lo_pin   | size      |
    let n_total = r + 1;
    let lo_pin = max - n_total;
    let n_remaining = n_total - lo_pin;
    let hi_pin_1 = lo_pin + (n_remaining / 2);
    let hi_pin_2 = max - (n_remaining / 2);

    // refer: https://nigeltao.github.io/blog/2022/zstandard-part-5-fse.html#variable-length-bit-packing
    //
    // - value    : the value denoted by size-bits.
    // - lo_value : the value denoted by the low (size-1)-bits.
    reader.skip(offset)?;
    let value = reader.read::<u64>(size)?;
    let lo_value = value & ((1 << (size - 1)) - 1);

    Ok(if (0..lo_pin).contains(&lo_value) {
        (size - 1, lo_value, lo_value)
    } else if (lo_pin..hi_pin_1).contains(&value) {
        (size, value, value)
    } else if (hi_pin_1..hi_pin_2).contains(&value) {
        (size - 1, lo_value, value - hi_pin_1)
    } else {
        assert!((hi_pin_2..(1 << size)).contains(&value));
        (size, value, value - lo_pin)
    })
}

/// Given the sum of even powers of two, return the exponents such that they are as even as
/// possible, with the larger powers followed by smaller.
///
/// For instance: if sum == 0x20 and n == 6
/// 0x20 <- 0x08 + 0x08 + 0x04 + 0x04 + 0x04 + 0x04
///
/// We would return vec![3, 3, 2, 2, 2, 2] as the corresponding exponents. The function also
/// returns the index at which the first smallest SPoT occurs.
pub fn smaller_powers_of_two(sum: u64, n: u64) -> (usize, Vec<u64>) {
    assert!(sum != 0, "SPoTs sum cannot be 0");
    assert!(sum & (sum - 1) == 0, "SPoTs sum is not a power of 2");

    if n == 1 {
        return (0, vec![(sum as f64).log2() as u64]);
    }

    let next_pow2 = 1 << bit_length(n);
    let mut diff = (next_pow2 - n) as usize;
    let smallest_spot = sum / next_pow2;
    let smallest_exponent = (smallest_spot as f64).log2() as u64;

    let pows: Vec<u64> = std::iter::repeat(smallest_exponent + 1)
        .take(diff as usize)
        .chain(std::iter::repeat(smallest_exponent))
        .take(n as usize)
        .collect();

    if diff >= pows.len() {
        diff = 0;
    }

    (diff, pows)
}

// Returns the number of bits needed to represent a u32 value in binary form.
pub fn bit_length(value: u64) -> u64 {
    if value == 0 {
        0
    } else {
        64 - value.leading_zeros() as u64
    }
}

/// Returns the bits in little-endianness.
pub fn value_bits_le(value_byte: u8) -> [u8; N_BITS_PER_BYTE] {
    (0..N_BITS_PER_BYTE)
        .map(|i| (value_byte >> i) & 1u8)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("expected N_BITS_PER_BYTE elements")
}

pub fn le_bits_to_value(bits: &[u8]) -> u64 {
    assert!(bits.len() <= 32);
    let mut m: u64 = 1;

    bits.iter().fold(0, |mut acc, b| {
        acc += (*b as u64) * m;
        m *= 2;
        acc
    })
}

pub fn be_bits_to_value(bits: &[u8]) -> u64 {
    assert!(bits.len() <= 32);

    bits.iter().fold(0, |mut acc, b| {
        acc = acc * 2 + *b as u64;
        acc
    })
}

// helper utility for helping manage bitstream delimitation
pub fn increment_idx(current_byte_idx: usize, current_bit_idx: usize) -> (usize, usize) {
    let current_bit_idx = current_bit_idx + 1;
    let mut current_byte_idx = current_byte_idx;

    if current_bit_idx >= current_byte_idx * N_BITS_PER_BYTE {
        current_byte_idx += 1;
    }

    (current_byte_idx, current_bit_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_bit_packing() -> std::io::Result<()> {
        // case 1:
        // read in little-endian order:
        //
        //                          <--- start
        // 00000011 10011011 01101111 00110000
        //
        // skip 4 bits and read a value between 0..=32.
        let src = vec![0x30, 0x6f, 0x9b, 0x03];
        let offset = 4;
        let range = 32;
        let (n_bits, _value_read, value_decoded) = read_variable_bit_packing(&src, offset, range)?;
        assert_eq!(n_bits, 5);
        assert_eq!(value_decoded, 19);

        // case 2:
        // read in little-endian order:
        //
        //
        // 10000000
        // skip 6 bits to read in range 0..=3, i.e. a range which does not require variable
        // bit-packing.
        let src = vec![0b10000000];
        let offset = 6;
        let range = 3;
        let (n_bits, _value_read, value_decoded) = read_variable_bit_packing(&src, offset, range)?;
        assert_eq!(n_bits, 2);
        assert_eq!(value_decoded, 2);

        // case 3:
        let src = vec![0b11000000];
        let offset = 6;
        let range = 2;
        let (n_bits, _value_read, value_decoded) = read_variable_bit_packing(&src, offset, range)?;
        assert_eq!(n_bits, 2);
        assert_eq!(value_decoded, 2);

        Ok(())
    }

    #[test]
    fn test_spots() {
        assert_eq!(smaller_powers_of_two(0x20, 6), (2, vec![3, 3, 2, 2, 2, 2]),);

        assert_eq!(smaller_powers_of_two(0x80, 5), (3, vec![5, 5, 5, 4, 4]),);

        assert_eq!(smaller_powers_of_two(0x40, 1), (0, vec![6]));
    }
}
