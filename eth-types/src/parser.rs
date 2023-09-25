//! Constant functions to parse hex strings
//! into [`H64`], [`H160`], [`H256`], [`U256`].
//!
//! Exported macros:
//! - [`h64!`](crate::h64!)
//! - [`h160!`](crate::h160!)
//! - [`h256!`](crate::h256!)
//! - [`u256!`](crate::u256!)

use crate::{H160, H256, H64, U256};

/// Invalid hex string.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidHex;

/// Create an [`H64`] from a hex string.  Panics on invalid input.
#[macro_export]
macro_rules! h64 {
    ($s:expr) => {
        match $crate::parser::try_parse_h64(&$s) {
            Ok(v) => v,
            Err(_) => panic!("invalid H64 hex string"),
        }
    };
}

/// Create an [`H160`] from a hex string.  Panics on invalid input.
#[macro_export]
macro_rules! h160 {
    ($s:expr) => {
        match $crate::parser::try_parse_h160(&$s) {
            Ok(v) => v,
            Err(_) => panic!("invalid H160 hex string"),
        }
    };
}

/// Create an [`H256`] from a hex string.  Panics on invalid input.
#[macro_export]
macro_rules! h256 {
    ($s:expr) => {
        match $crate::parser::try_parse_h256(&$s) {
            Ok(v) => v,
            Err(_) => panic!("invalid H256 hex string"),
        }
    };
}

/// Create an [`U256`] from a hex string.  Panics on invalid input.
#[macro_export]
macro_rules! u256 {
    ($s:expr) => {
        match $crate::parser::try_parse_u256(&$s) {
            Ok(v) => v,
            Err(_) => panic!("invalid U256 hex string"),
        }
    };
}

#[macro_export]
/// Create an [`Address`](crate::Address) from a hex string.  Panics on invalid input.
macro_rules! address {
    ($s:expr) => {
        $crate::h160!($s)
    };
}

#[macro_export]
/// Create a [`Word`](crate::Word) from a hex string.  Panics on invalid input.
macro_rules! word {
    ($word_hex:expr) => {
        $crate::u256!($word_hex)
    };
}

macro_rules! define_parser_function {
    (
        $(#[$doc:meta])*
        $fn_name:ident,
        $return_type:ident,
        $prefixed_len:expr,
        $len:expr,
    ) => {
        $(#[$doc])*
        pub const fn $fn_name(s: &str) -> Result<$return_type, InvalidHex> {
            let bytes = match (s.len(), s.as_bytes()) {
                ($prefixed_len, [b'0', b'x', s @ ..]) => s,
                ($len, s) => s,
                _ => return Err(InvalidHex),
            };
            match try_parse_hex_ascii(bytes) {
                Ok(buf) => Ok($return_type(buf)),
                Err(_) => Err(InvalidHex),
            }
        }
    };
}

define_parser_function! {
    /// Parse a hex string into a H64.
    ///
    /// Valid Inputs:
    /// - starts with 0x, length is 18 (0x + 16 hex chars)
    /// - does not start with 0x, length is 16 (16 hex chars)
    try_parse_h64,
    H64,
    18,
    16,
}

define_parser_function! {
    /// Parse a hex string into a H160.
    ///
    /// Valid Inputs:
    /// - starts with 0x, length is 42 (0x + 40 hex chars)
    /// - does not start with 0x, length is 40 (40 hex chars)
    try_parse_h160,
    H160,
    42,
    40,
}

define_parser_function! {
    /// Parse a hex string into a H256.
    ///
    /// Valid Inputs:
    /// - starts with 0x, length is 66 (0x + 64 hex chars)
    /// - does not start with 0x, length is 64 (64 hex chars)
    try_parse_h256,
    H256,
    66,
    64,
}

/// Parse a var-length hex string into a U256.
///
/// Valid Inputs:
/// - starting with 0x, length less than 66 (0x + 64 hex chars)
/// - not starting with 0x, length less than 64 (64 hex chars)
pub const fn try_parse_u256(s: &str) -> Result<U256, InvalidHex> {
    let bytes = match (s.len(), s.as_bytes()) {
        (len, [b'0', b'x', s @ ..]) if len <= 66 => s,
        (len, s) if len <= 64 => s,
        _ => return Err(InvalidHex),
    };
    let length = bytes.len();
    // copy bytes and reverse it since it is little endian
    // eg. b"123" -> [b'2', b'3', b'0', b'1']
    let mut padded_bytes = [b'0'; 64];
    let mut i = 0;
    // start from lowest byte
    while i < length {
        if i + 1 < length {
            padded_bytes[i] = bytes[length - i - 2];
            padded_bytes[i + 1] = bytes[length - i - 1];
            i += 2;
        } else {
            padded_bytes[i + 1] = bytes[length - i - 1];
            i += 1;
        }
    }
    let mut limbs = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        // a bit hack to make it const
        let mut buf = [0u8; 16];
        let mut j = 0;
        while j < 16 {
            buf[j] = padded_bytes[i * 16 + j];
            j += 1;
        }
        limbs[i] = match try_parse_hex_ascii(&buf) {
            Ok(buf) => u64::from_le_bytes(buf),
            Err(_) => return Err(InvalidHex),
        };
        i += 1;
    }

    Ok(U256(limbs))
}

// copy from https://github.com/uuid-rs/uuid/blob/main/src/parser.rs
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
const HEX_TABLE: &[u8; 256] = &{
    let mut buf = [0; 256];
    let mut i: u8 = 0;

    loop {
        buf[i as usize] = match i {
            b'0'..=b'9' => i - b'0',
            b'a'..=b'f' => i - b'a' + 10,
            b'A'..=b'F' => i - b'A' + 10,
            _ => 0xff,
        };

        if i == 255 {
            break buf;
        }

        i += 1
    }
};

const SHL4_TABLE: &[u8; 256] = &{
    let mut buf = [0; 256];
    let mut i: u8 = 0;

    loop {
        buf[i as usize] = i.wrapping_shl(4);

        if i == 255 {
            break buf;
        }

        i += 1;
    }
};

const fn try_parse_hex_ascii<const N_BYTES: usize>(s: &[u8]) -> Result<[u8; N_BYTES], ()> {
    if s.len() != N_BYTES * 2 {
        return Err(());
    }

    let mut buf = [0u8; N_BYTES];
    let mut i = 0;

    while i < N_BYTES {
        // Convert a two-char hex value (like `A8`)
        // into a byte (like `10101000`)
        let h1 = HEX_TABLE[s[i * 2] as usize];
        let h2 = HEX_TABLE[s[i * 2 + 1] as usize];

        // We use `0xff` as a sentinel value to indicate
        // an invalid hex character sequence (like the letter `G`)
        if h1 | h2 == 0xff {
            return Err(());
        }

        // The upper nibble needs to be shifted into position
        // to produce the final byte value
        buf[i] = SHL4_TABLE[h1 as usize] | h2;
        i += 1;
    }

    Ok(buf)
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{distributions::Standard, prelude::*};
    use rayon::prelude::*;
    use std::str::FromStr;

    #[test]
    fn test_try_parse_hex_ascii() {
        assert_eq!(
            try_parse_hex_ascii::<20>("000000000000000000000000000000000000cafe".as_bytes()),
            Ok([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xca, 0xfe,])
        );
        assert_eq!(
            try_parse_hex_ascii::<20>("0000000000000000000000000000000000cafe".as_bytes()),
            Err(())
        );
    }

    #[test]
    fn test_try_parse_u256() {
        assert_eq!(
            try_parse_u256("0x00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"),
            Ok(U256::from_str(
                "0x00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
            )
            .unwrap())
        );
        assert_eq!(
            try_parse_u256("0x00112233445566778899AABBCCDDEEFF"),
            Ok(U256::from_str("0x00112233445566778899AABBCCDDEEFF").unwrap())
        );
        assert_eq!(
            try_parse_u256("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"),
            Ok(U256::from_str(
                "0x00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
            )
            .unwrap())
        );
        assert_eq!(
            try_parse_u256("00112233445566778899AABBCCDDEEFF"),
            Ok(U256::from_str("0x00112233445566778899AABBCCDDEEFF").unwrap())
        );
    }

    #[test]
    fn test_marcos() {
        assert_eq!(word!("0"), U256::from_str("0").unwrap());
        assert_eq!(word!("0x3"), U256::from_str("0x3").unwrap());
        assert_eq!(word!("0xB"), U256::from_str("0xB").unwrap());
        assert_eq!(word!("0x15"), U256::from_str("0x15").unwrap());
        assert_eq!(word!("0x20"), U256::from_str("0x20").unwrap());
        assert_eq!(word!("0xFFFF"), U256::from_str("0xFFFF").unwrap());
        assert_eq!(
            word!("7156526fbd7a3c72969b54f64e42c10fbb768c8a"),
            U256::from_str("7156526fbd7a3c72969b54f64e42c10fbb768c8a").unwrap()
        );
        assert_eq!(
            word!("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3"),
            U256::from_str("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3")
                .unwrap()
        );
        assert_eq!(
            word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"),
            U256::from_str("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3")
                .unwrap()
        )
    }

    #[test]
    fn test_const() {
        const _: H64 = h64!("1234567890abcdef");
        const _: H64 = h64!("0x1234567890abcdef");
        const _: H160 = h160!("1234567890abcdef1234567890abcdef12345678");
        const _: H160 = h160!("0x1234567890abcdef1234567890abcdef12345678");
        const _: H256 = h256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        const _: H256 = h256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        const _: U256 = u256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        const _: U256 = u256!("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    }

    const HEX_ALPHABET: [u8; 22] = *b"0123456789abcdefABCDEF";

    #[ignore]
    #[test]
    fn fuzzy_test_valid() {
        // generate word hex string
        (0..1000000).into_par_iter().for_each(|_| {
            let mut rng = thread_rng();
            // h64 test
            let h64_hex = (0..16)
                .map(|_| HEX_ALPHABET[rng.gen_range(0..22)] as char)
                .collect::<String>();
            assert_eq!(
                H64::from_str(&h64_hex).unwrap(),
                try_parse_h64(&h64_hex).unwrap()
            );
            let prefixed = format!("0x{}", h64_hex);
            assert_eq!(
                H64::from_str(&prefixed).unwrap(),
                try_parse_h64(&prefixed).unwrap()
            );

            // h160 test
            let h160_hex = (0..40)
                .map(|_| HEX_ALPHABET[rng.gen_range(0..22)] as char)
                .collect::<String>();
            assert_eq!(
                H160::from_str(&h160_hex).unwrap(),
                try_parse_h160(&h160_hex).unwrap()
            );
            let prefixed = format!("0x{}", h160_hex);
            assert_eq!(
                H160::from_str(&prefixed).unwrap(),
                try_parse_h160(&prefixed).unwrap()
            );

            // h256 test
            let h256_hex = (0..64)
                .map(|_| HEX_ALPHABET[rng.gen_range(0..22)] as char)
                .collect::<String>();
            assert_eq!(
                H256::from_str(&h256_hex).unwrap(),
                try_parse_h256(&h256_hex).unwrap()
            );
            let prefixed = format!("0x{}", h256_hex);
            assert_eq!(
                H256::from_str(&prefixed).unwrap(),
                try_parse_h256(&prefixed).unwrap()
            );

            // word test
            // may generate empty string
            let length = rng.gen_range(0..65);
            let mut word_hex = String::with_capacity(length);
            for _ in 0..length {
                word_hex.push(HEX_ALPHABET[rng.gen_range(0..22)] as char);
            }
            assert_eq!(
                U256::from_str(&word_hex).unwrap(),
                try_parse_u256(&word_hex).unwrap()
            );
            let prefixed = format!("0x{}", word_hex);
            assert_eq!(
                U256::from_str(&prefixed).unwrap(),
                try_parse_u256(&prefixed).unwrap()
            );
        })
    }

    #[ignore]
    #[test]
    fn fuzzy_test_word_invalid() {
        (0..100000).into_par_iter().for_each(|_| {
            let mut rng = thread_rng();
            let length = rng.gen_range(1..128);
            let word_hex = rng
                .sample_iter::<char, _>(Standard)
                .take(length)
                .collect::<String>();
            match U256::from_str(&word_hex) {
                Ok(v) => {
                    assert_eq!(try_parse_u256(&word_hex).unwrap(), v);
                }
                Err(_) => {
                    assert!(try_parse_u256(&word_hex).is_err());
                }
            }
        })
    }
}
