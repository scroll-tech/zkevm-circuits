use eth_types::U256;
use itertools::Itertools;

use crate::{
    circuit_input_builder::{
        EcPairingOp, EcPairingPair, PrecompileEvent, N_BYTES_PER_PAIR, N_PAIRING_PER_OP,
    },
    precompile::{EcPairingAuxData, EcPairingError, PrecompileAuxData},
};

pub(crate) fn opt_data(
    input_bytes: Option<Vec<u8>>,
    output_bytes: Option<Vec<u8>>,
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    // assertions.
    let pairing_check = output_bytes.map_or(U256::zero(), |output| {
        debug_assert_eq!(
            output.len(),
            32,
            "len(output)={:?}, expected={:?}",
            output.len(),
            32
        );
        U256::from(output[31])
    });
    debug_assert!(
        pairing_check.eq(&U256::one()) || pairing_check.is_zero(),
        "ecPairing returns 1 or 0"
    );
    if input_bytes.is_none() {
        debug_assert!(
            pairing_check.eq(&U256::one()),
            "for zero inputs, pairing check == 1"
        );
    }

    let op = if let Some(input) = input_bytes {
        if (input.len() > N_PAIRING_PER_OP * N_BYTES_PER_PAIR)
            || (input.len() % N_BYTES_PER_PAIR != 0)
        {
            return (
                None,
                Some(PrecompileAuxData::EcPairing(Box::new(Err(
                    EcPairingError::InvalidInputLen(input),
                )))),
            );
        }
        debug_assert!(
            input.len() % N_BYTES_PER_PAIR == 0
                && input.len() <= N_PAIRING_PER_OP * N_BYTES_PER_PAIR
        );
        // process input bytes.
        let mut pairs = input
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
        }
    } else {
        let pairs = [EcPairingPair::padding_pair(); N_PAIRING_PER_OP];
        EcPairingOp {
            pairs,
            output: pairing_check,
        }
    };

    (
        Some(PrecompileEvent::EcPairing(Box::new(op.clone()))),
        Some(PrecompileAuxData::EcPairing(Box::new(Ok(
            EcPairingAuxData(op),
        )))),
    )
}
