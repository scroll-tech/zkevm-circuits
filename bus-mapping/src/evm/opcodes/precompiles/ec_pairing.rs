use eth_types::{ToLittleEndian, U256};
use halo2_proofs::halo2curves::{
    bn256::{multi_miller_loop, Fq, Fq2, G1Affine, G2Affine, Gt},
    group::cofactor::CofactorCurveAffine,
    pairing::MillerLoopResult,
};

use crate::{
    circuit_input_builder::{
        EcPairingOp, EcPairingPair, PrecompileEvent, N_BYTES_PER_PAIR, N_PAIRING_PER_OP,
    },
    precompile::{EcPairingAuxData, PrecompileAuxData},
};

pub(crate) fn opt_data(
    input_bytes: Option<Vec<u8>>,
    output_bytes: Option<Vec<u8>>,
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    // assertions.
    let output_bytes = output_bytes.expect("precompile should return at least 0 on failure");
    debug_assert_eq!(output_bytes.len(), 32, "ecPairing returns EVM word: 1 or 0");
    let pairing_check = output_bytes[31];
    debug_assert!(
        pairing_check == 1 || pairing_check == 0,
        "ecPairing returns 1 or 0"
    );
    debug_assert_eq!(output_bytes.iter().take(31).sum::<u8>(), 0);
    if input_bytes.is_none() {
        debug_assert_eq!(pairing_check, 1);
    }

    let (op, aux_data) = if let Some(input) = input_bytes {
        debug_assert!(
            input.len() % N_BYTES_PER_PAIR == 0
                && input.len() <= N_PAIRING_PER_OP * N_BYTES_PER_PAIR
        );
        // process input bytes.
        let (mut ecc_pairs, mut evm_pairs): (Vec<EcPairingPair>, Vec<EcPairingPair>) = input
            .chunks_exact(N_BYTES_PER_PAIR)
            .map(|chunk| {
                // process 192 bytes chunk at a time.
                // process g1.
                let g1_point = {
                    let g1_x =
                        Fq::from_bytes(&U256::from_big_endian(&chunk[0x00..0x20]).to_le_bytes())
                            .unwrap();
                    let g1_y =
                        Fq::from_bytes(&U256::from_big_endian(&chunk[0x20..0x40]).to_le_bytes())
                            .unwrap();
                    G1Affine { x: g1_x, y: g1_y }
                };
                // process g2.
                let g2_point = {
                    let g2_x1 =
                        Fq::from_bytes(&U256::from_big_endian(&chunk[0x40..0x60]).to_le_bytes())
                            .unwrap();
                    let g2_x2 =
                        Fq::from_bytes(&U256::from_big_endian(&chunk[0x60..0x80]).to_le_bytes())
                            .unwrap();
                    let g2_y1 =
                        Fq::from_bytes(&U256::from_big_endian(&chunk[0x80..0xA0]).to_le_bytes())
                            .unwrap();
                    let g2_y2 =
                        Fq::from_bytes(&U256::from_big_endian(&chunk[0xA0..0xC0]).to_le_bytes())
                            .unwrap();
                    G2Affine {
                        x: Fq2 {
                            c0: g2_x2,
                            c1: g2_x1,
                        },
                        y: Fq2 {
                            c0: g2_y2,
                            c1: g2_y1,
                        },
                    }
                };

                let evm_circuit_pair = EcPairingPair { g1_point, g2_point };
                let ecc_circuit_pair =
                    if g1_point.is_identity().into() || g2_point.is_identity().into() {
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
                output: pairing_check.into(),
            },
            EcPairingAuxData(EcPairingOp {
                pairs: <[_; N_PAIRING_PER_OP]>::try_from(evm_pairs).unwrap(),
                output: pairing_check.into(),
            }),
        )
    } else {
        // if no input bytes.
        let ecc_pairs = [EcPairingPair::ecc_padding(); N_PAIRING_PER_OP];
        let evm_pairs = [EcPairingPair::evm_padding(); N_PAIRING_PER_OP];
        (
            EcPairingOp {
                pairs: ecc_pairs,
                output: pairing_check.into(),
            },
            EcPairingAuxData(EcPairingOp {
                pairs: evm_pairs,
                output: pairing_check.into(),
            }),
        )
    };

    debug_assert_eq!(
        {
            let gt = multi_miller_loop(&[
                (&op.pairs[0].g1_point, &op.pairs[0].g2_point.into()),
                (&op.pairs[1].g1_point, &op.pairs[1].g2_point.into()),
                (&op.pairs[2].g1_point, &op.pairs[2].g2_point.into()),
                (&op.pairs[3].g1_point, &op.pairs[3].g2_point.into()),
            ]);
            let gt = gt.final_exponentiation();
            gt.eq(&Gt::identity()) as u8
        },
        pairing_check
    );

    (
        Some(PrecompileEvent::EcPairing(Box::new(op))),
        Some(PrecompileAuxData::EcPairing(Box::new(aux_data))),
    )
}
