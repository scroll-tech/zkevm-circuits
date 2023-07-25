use eth_types::{ToLittleEndian, U256};
use halo2_proofs::halo2curves::{
    bn256::{Fq, Fq2, G1Affine, G2Affine},
    group::cofactor::CofactorCurveAffine,
};

use crate::{
    circuit_input_builder::{EcPairingOp, PrecompileEvent, N_BYTES_PER_PAIR, N_PAIRING_PER_OP},
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

    let aux_data = if let Some(input) = input_bytes {
        debug_assert!(
            input.len() % N_BYTES_PER_PAIR == 0
                && input.len() <= N_PAIRING_PER_OP * N_BYTES_PER_PAIR
        );
        // process input bytes.
        let mut pairs = input
            .chunks_exact(N_BYTES_PER_PAIR)
            .map(|chunk| {
                // process 192 bytes chunk at a time.
                // process g1.
                let g1 = {
                    let g1_x =
                        Fq::from_bytes(&U256::from_big_endian(&chunk[0x00..0x20]).to_le_bytes())
                            .unwrap();
                    let g1_y =
                        Fq::from_bytes(&U256::from_big_endian(&chunk[0x20..0x40]).to_le_bytes())
                            .unwrap();
                    G1Affine { x: g1_x, y: g1_y }
                };
                // process g2.
                let g2 = {
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
                            c0: g2_x1,
                            c1: g2_x2,
                        },
                        y: Fq2 {
                            c0: g2_y1,
                            c1: g2_y2,
                        },
                    }
                };
                if g1.is_identity().into() && g2.is_identity().into() {
                    (g1, G2Affine::generator(), true)
                } else {
                    (g1, g2, true)
                }
            })
            .collect::<Vec<(G1Affine, G2Affine, bool)>>();
        // pad with placeholder pairs.
        pairs.resize(
            N_PAIRING_PER_OP,
            (G1Affine::identity(), G2Affine::generator(), false),
        );
        EcPairingAuxData(EcPairingOp {
            inputs: <[_; N_PAIRING_PER_OP]>::try_from(pairs)
                .expect("pairs.len() <= N_PAIRING_PER_OP"),
            output: pairing_check.into(),
        })
    } else {
        // if no input bytes.
        let ec_pairing_op = EcPairingOp {
            inputs: [
                (G1Affine::identity(), G2Affine::generator(), false),
                (G1Affine::identity(), G2Affine::generator(), false),
                (G1Affine::identity(), G2Affine::generator(), false),
                (G1Affine::identity(), G2Affine::generator(), false),
            ],
            output: pairing_check.into(),
        };
        EcPairingAuxData(ec_pairing_op)
    };

    (
        Some(PrecompileEvent::EcPairing(Box::new(aux_data.0.clone()))),
        Some(PrecompileAuxData::EcPairing(Box::new(aux_data))),
    )
}
