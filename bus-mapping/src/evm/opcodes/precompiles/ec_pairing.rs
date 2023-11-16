use eth_types::U256;
use itertools::Itertools;

use crate::{
    circuit_input_builder::{
        EcPairingOp, EcPairingPair, PrecompileEvent, N_BYTES_PER_PAIR, N_PAIRING_PER_OP,
    },
    precompile::{EcPairingAuxData, EcPairingError, PrecompileAuxData},
};

pub(crate) fn opt_data(
    input_bytes: &[u8],
    output_bytes: &[u8],
    return_bytes: &[u8],
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    // assertions.
    let pairing_check = if output_bytes.is_empty() {
        U256::zero()
    } else {
        debug_assert_eq!(
            output_bytes.len(),
            32,
            "len(output)={:?}, expected={:?}",
            output_bytes.len(),
            32
        );
        U256::from_big_endian(output_bytes)
    };
    debug_assert!(
        pairing_check.eq(&U256::one()) || pairing_check.is_zero(),
        "ecPairing returns 1 or 0"
    );
    if input_bytes.is_empty() {
        debug_assert!(
            pairing_check.eq(&U256::one()),
            "for zero inputs, pairing check == 1"
        );
    }

    let op = if !input_bytes.is_empty() {
        if (input_bytes.len() > N_PAIRING_PER_OP * N_BYTES_PER_PAIR)
            || (input_bytes.len() % N_BYTES_PER_PAIR != 0)
        {
            return (
                None,
                Some(PrecompileAuxData::EcPairing(Box::new(Err(
                    EcPairingError::InvalidInputLen(input_bytes.to_vec()),
                )))),
            );
        }
        debug_assert!(
            input_bytes.len() % N_BYTES_PER_PAIR == 0
                && input_bytes.len() <= N_PAIRING_PER_OP * N_BYTES_PER_PAIR
        );
        // process input bytes.
        let mut pairs = input_bytes
            .chunks_exact(N_BYTES_PER_PAIR)
            .map(|chunk| {
                // process <= 192 bytes chunk at a time.
                EcPairingPair {
                    g1_point: (
                        U256::from_big_endian(&chunk[0x00..0x20]),
                        U256::from_big_endian(&chunk[0x20..0x40]),
                    ),
                    g2_point: (
                        U256::from_big_endian(&chunk[0x40..0x60]),
                        U256::from_big_endian(&chunk[0x60..0x80]),
                        U256::from_big_endian(&chunk[0x80..0xA0]),
                        U256::from_big_endian(&chunk[0xA0..0xC0]),
                    ),
                }
            })
            .collect_vec();
        // pad the pairs to make them of fixed size: N_PAIRING_PER_OP.
        pairs.resize(N_PAIRING_PER_OP, EcPairingPair::padding_pair());
        EcPairingOp {
            pairs: <[_; N_PAIRING_PER_OP]>::try_from(pairs).unwrap(),
            output: pairing_check,
            input_bytes: input_bytes.to_vec(),
            output_bytes: output_bytes.to_vec(),
            return_bytes: return_bytes.to_vec(),
        }
    } else {
        let pairs = [EcPairingPair::padding_pair(); N_PAIRING_PER_OP];
        EcPairingOp {
            pairs,
            output: pairing_check,
            input_bytes: vec![],
            output_bytes: output_bytes.to_vec(),
            return_bytes: return_bytes.to_vec(),
        }
    };

    (
        Some(PrecompileEvent::EcPairing(Box::new(op.clone()))),
        Some(PrecompileAuxData::EcPairing(Box::new(Ok(
            EcPairingAuxData(op),
        )))),
    )
}
