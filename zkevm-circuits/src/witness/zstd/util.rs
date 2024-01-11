use super::N_BITS_PER_BYTE;

pub fn value_bits_le(value_byte: u8) -> [u8; N_BITS_PER_BYTE] {
    (0..N_BITS_PER_BYTE)
        .map(|i| (value_byte >> i) & 1u8)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("expected N_BITS_PER_BYTE elements")
}

// compression_debug
pub fn le_bits_to_value(bits: &[u8]) -> u64 {
    assert!(bits.len() <= 64);

    bits.into_iter().enumerate().fold(0, |mut acc, (p, b)| {
        acc += (2u64).pow(p as u32) * (*b as u64);
        acc
    })
}
