use eth_types::U256;

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

    let (op, aux_data) = if let Some(input) = input_bytes {
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
        let (mut ecc_pairs, mut evm_pairs): (Vec<EcPairingPair>, Vec<EcPairingPair>) = input
            .chunks_exact(N_BYTES_PER_PAIR)
            .map(|chunk| {
                // process <= 192 bytes chunk at a time.
                let evm_circuit_pair = EcPairingPair {
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
                };
                // if EVM inputs were 0s.
                let ecc_circuit_pair = if evm_circuit_pair.swap() {
                    EcPairingPair::ecc_padding()
                } else {
                    evm_circuit_pair
                };
                (ecc_circuit_pair, evm_circuit_pair)
            })
            .unzip();
        // pad the pairs to make them of fixed size: N_PAIRING_PER_OP.
        ecc_pairs.resize(N_PAIRING_PER_OP, EcPairingPair::ecc_padding());
        evm_pairs.resize(N_PAIRING_PER_OP, EcPairingPair::evm_padding());
        (
            EcPairingOp {
                pairs: <[_; N_PAIRING_PER_OP]>::try_from(ecc_pairs).unwrap(),
                output: pairing_check,
            },
            EcPairingAuxData(EcPairingOp {
                pairs: <[_; N_PAIRING_PER_OP]>::try_from(evm_pairs).unwrap(),
                output: pairing_check,
            }),
        )
    } else {
        // if no input bytes.
        let ecc_pairs = [EcPairingPair::ecc_padding(); N_PAIRING_PER_OP];
        let evm_pairs = [EcPairingPair::evm_padding(); N_PAIRING_PER_OP];
        (
            EcPairingOp {
                pairs: ecc_pairs,
                output: pairing_check,
            },
            EcPairingAuxData(EcPairingOp {
                pairs: evm_pairs,
                output: pairing_check,
            }),
        )
    };

    (
        Some(PrecompileEvent::EcPairing(Box::new(op))),
        Some(PrecompileAuxData::EcPairing(Box::new(Ok(aux_data)))),
    )
}
