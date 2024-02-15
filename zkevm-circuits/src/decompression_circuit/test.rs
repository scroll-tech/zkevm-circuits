#[test]
fn test_basic() {
    use crate::decompression_circuit::DecompressionCircuit;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    let circuit = DecompressionCircuit::<Fr>::default();
    let mock_prover = MockProver::run(17, &circuit, vec![]);
    assert!(mock_prover.is_ok());
    let mock_prover = mock_prover.unwrap();
    if let Err(errors) = mock_prover.verify_par() {
        log::debug!("errors.len() = {}", errors.len());
    }

    mock_prover.assert_satisfied_par();
}

#[test]
fn test_work_example_decompression() {
    use crate::decompression_circuit::DecompressionCircuit;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    let compressed: Vec<u8> = vec![
        // 0x28, 0xb5, 0x2f, 0xfd, // magic numbers are removed
        0x60, // Originally 0x64. unset the checksum bit.
        0xae, 0x02, // FrameContentSize
        0x0d, 0x11, 0x00, // BlockHeader
        0x76, 0x62, 0x5e, // ZstdBlockLiteralsHeader
        0x23, 0x30, 0x6f, 0x9b, 0x03, // ZstdBlockFseCode
        // ZstdBlockHuffmanCode
        0x7d, 0xc7, 0x16, 0x0b, 0xbe, 0xc8, 0xf2, 0xd0, 0x22, 0x4b, 0x6b, 0xbc, 0x54, 0x5d, 0xa9,
        0xd4, 0x93, 0xef, 0xc4, 0x54, 0x96, 0xb2, 0xe2, 0xa8, 0xa8, 0x24, 0x1c, 0x54, 0x40, 0x29,
        0x01, // ZstdBlockJumpTable
        0x55, 0x00, 0x57, 0x00, 0x51, 0x00, // LStream1
        0xcc, 0x51, 0x73, 0x3a, 0x85, 0x9e, 0xf7, 0x59, 0xfc, 0xc5, 0xca, 0x6a, 0x7a, 0xd9, 0x82,
        0x9c, 0x65, 0xc5, 0x45, 0x92, 0xe3, 0x0d, 0xf3, 0xef, 0x71, 0xee, 0xdc, 0xd5, 0xa2, 0xe3,
        0x48, 0xad, 0xa3, 0xbc, 0x41, 0x7a, 0x3c, 0xaa, 0xd6, 0xeb, 0xd0, 0x77, 0xea, 0xdc, 0x5d,
        0x41, 0x06, 0x50, 0x1c, 0x49, 0x0f, 0x07, 0x10, 0x05, 0x88, 0x84, 0x94, 0x02, 0xfc, 0x3c,
        0xe3, 0x60, 0x25, 0xc0, 0xcb, 0x0c, 0xb8, 0xa9, 0x73, 0xbc, 0x13, 0x77, 0xc6, 0xe2, 0x20,
        0xed, 0x17, 0x7b, 0x12, 0xdc, 0x24, 0x5a, 0xdf, 0xb4, 0x21, // LStream2
        0x9a, 0xcb, 0x8f, 0xc7, 0x58, 0x54, 0x11, 0xa9, 0xf1, 0x47, 0x82, 0x9b, 0xba, 0x60, 0xb4,
        0x92, 0x28, 0x0e, 0xfb, 0x8b, 0x1e, 0x92, 0x23, 0x6a, 0xcf, 0xbf, 0xe5, 0x45, 0xb5, 0x7e,
        0xeb, 0x81, 0xf1, 0x78, 0x4b, 0xad, 0x17, 0x4d, 0x81, 0x9f, 0xbc, 0x67, 0xa7, 0x56, 0xee,
        0xb4, 0xd9, 0xe1, 0x95, 0x21, 0x66, 0x0c, 0x95, 0x83, 0x27, 0xde, 0xac, 0x37, 0x20, 0x91,
        0x22, 0x07, 0x0b, 0x91, 0x86, 0x94, 0x1a, 0x7b, 0xf6, 0x4c, 0xb0, 0xc0, 0xe8, 0x2e, 0x49,
        0x65, 0xd6, 0x34, 0x63, 0x0c, 0x88, 0x9b, 0x1c, 0x48, 0xca, 0x2b, 0x34,
        // LStream3
        0xa9, 0x6b, 0x99, 0x3b, 0xee, 0x13, 0x3b, 0x7c, 0x93, 0x0b, 0xf7, 0x0d, 0x49, 0x69, 0x18,
        0x57, 0xbe, 0x3b, 0x64, 0x45, 0x1d, 0x92, 0x63, 0x7f, 0xe8, 0xf9, 0xa1, 0x19, 0x7b, 0x7b,
        0x6e, 0xd8, 0xa3, 0x90, 0x23, 0x82, 0xf4, 0xa7, 0xce, 0xc8, 0xf8, 0x90, 0x15, 0xb3, 0x14,
        0xf4, 0x40, 0xe7, 0x02, 0x78, 0xd3, 0x17, 0x71, 0x23, 0xb1, 0x19, 0xad, 0x6b, 0x49, 0xae,
        0x13, 0xa4, 0x75, 0x38, 0x51, 0x47, 0x89, 0x67, 0xb0, 0x39, 0xb4, 0x53, 0x86, 0xa4, 0xac,
        0xaa, 0xa3, 0x34, 0x89, 0xca, 0x2e, // LStream4
        0xe9, 0xc1, 0xfe, 0xf2, 0x51, 0xc6, 0x51, 0x73, 0xaa, 0xf7, 0x9d, 0x2d, 0xed, 0xd9, 0xb7,
        0x4a, 0xb2, 0xb2, 0x61, 0xe4, 0xef, 0x98, 0xf7, 0xc5, 0xef, 0x51, 0x9b, 0xd8, 0xdc, 0x60,
        0x6c, 0x41, 0x76, 0xaf, 0x78, 0x1a, 0x62, 0xb5, 0x4c, 0x1e, 0x21, 0x39, 0x9a, 0x5f, 0xac,
        0x9d, 0xe0, 0x62, 0xe8, 0xe9, 0x2f, 0x2f, 0x48, 0x02, 0x8d, 0x53, 0xc8, 0x91, 0xf2, 0x1a,
        0xd2, 0x7c, 0x0a, 0x7c, 0x48, 0xbf, 0xda, 0xa9, 0xe3, 0x38, 0xda, 0x34, 0xce, 0x76, 0xa9,
        0xda, 0x15, 0x91, 0xde, 0x21, 0xf5, 0x55, // Sequence Section
        0x46, 0xa8, 0x21, 0x9d, 0x51, 0xcc, 0x18, 0x42, 0x44, 0x81, 0x8c, 0x94, 0xb4, 0x50, 0x1e,
        0x20, 0x42, 0x82, 0x98, 0xc2, 0x3b, 0x10, 0x48, 0xec, 0xa6, 0x39, 0x63, 0x13, 0xa7, 0x01,
        0x94, 0x40, 0xff, 0x88, 0x0f, 0x98, 0x07, 0x4a, 0x46, 0x38, 0x05, 0xa9, 0xcb, 0xf6, 0xc8,
        0x21, 0x59, 0xaa, 0x38, 0x45, 0xbf, 0x5c, 0xf8, 0x55, 0x9e, 0x9f, 0x04, 0xed, 0xc8, 0x03,
        0x42, 0x2a, 0x4b, 0xf6, 0x78, 0x7e, 0x23, 0x67, 0x15, 0xa2, 0x79, 0x29, 0xf4, 0x9b, 0x7e,
        0x00, 0xbc, 0x2f, 0x46, 0x96, 0x99, 0xea, 0xf1, 0xee, 0x1c, 0x6e, 0x06, 0x9c, 0xdb, 0xe4,
        0x8c, 0xc2, 0x05, 0xf7, 0x54, 0x51, 0x84, 0xc0, 0x33, 0x02, 0x01, 0xb1, 0x8c, 0x80, 0xdc,
        0x99, 0x8f, 0xcb, 0x46, 0xff, 0xd1, 0x25, 0xb5, 0xb6, 0x3a, 0xf3, 0x25, 0xbe, 0x85, 0x50,
        0x84, 0xf5, 0x86, 0x5a, 0x71, 0xf7, 0xbd, 0xa1, 0x4c, 0x52, 0x4f, 0x20, 0xa3, 0x61, 0x23,
        0x77, 0x12, 0xd3, 0xb1, 0x58, 0x75, 0x22, 0x01, 0x12, 0x70, 0xec, 0x14, 0x91, 0xf9, 0x85,
        0x61, 0xd5, 0x7e, 0x98, 0x84, 0xc9, 0x76, 0x84, 0xbc, 0xb8, 0xfe, 0x4e, 0x53, 0xa5, 0x06,
        0x82, 0x14, 0x95, 0x51,
    ];

    let decompression_circuit = DecompressionCircuit::<Fr> {
        compressed_frames: vec![compressed],
        _data: Default::default(),
    };

    let mock_prover = MockProver::run(18, &decompression_circuit, vec![]);

    let mock_prover = mock_prover.unwrap();
    if let Err(errors) = mock_prover.verify_par() {
        log::debug!("errors.len() = {}", errors.len());
    }

    mock_prover.assert_satisfied_par();
}
