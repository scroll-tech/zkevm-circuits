use bus_mapping::{evm::PrecompileCallArgs, precompile::PrecompileCalls};
use eth_types::{bytecode, evm_types::OpcodeId, word, ToWord, Word};
use halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use once_cell::sync::Lazy;

pub static TEST_VECTOR: Lazy<Vec<PrecompileCallArgs>> = Lazy::new(|| {
    let mut rng = rand::thread_rng();
    vec![
        PrecompileCallArgs {
            name: "ecPairing (valid): empty calldata",
            setup_code: bytecode! {},
            call_data_offset: 0x00.into(),
            call_data_length: 0x00.into(),
            ret_offset: 0x00.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Bn128Pairing.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecPairing (valid): zero bytes",
            setup_code: bytecode! {},
            call_data_offset: 0x00.into(),
            call_data_length: 0xC0.into(),
            ret_offset: 0xC0.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Bn128Pairing.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecPairing (pairing true): 2 pairs",
            setup_code: bytecode! {
                // G1_x1
                PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"))
                PUSH1(0x00)
                MSTORE
                // G1_y1
                PUSH32(word!("0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
                PUSH1(0x20)
                MSTORE
                // G2_x11
                PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
                PUSH1(0x40)
                MSTORE
                // G2_x12
                PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                PUSH1(0x60)
                MSTORE
                // G2_y11
                PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                PUSH1(0x80)
                MSTORE
                // G2_y12
                PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                PUSH1(0xA0)
                MSTORE
                // G1_x2
                PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                PUSH1(0xC0)
                MSTORE
                // G1_y2
                PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                PUSH1(0xE0)
                MSTORE
                // G2_x21
                PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                PUSH2(0x100)
                MSTORE
                // G2_x22
                PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                PUSH2(0x120)
                MSTORE
                // G2_y21
                PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                PUSH2(0x140)
                MSTORE
                // G2_y22
                PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                PUSH2(0x160)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x180.into(),
            ret_offset: 0x180.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Bn128Pairing.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecPairing (pairing true): 4 pairs with random G1s",
            setup_code: {
                let mut setup_code = bytecode! {
                    // G1_x1
                    PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"))
                    PUSH1(0x00)
                    MSTORE
                    // G1_y1
                    PUSH32(word!("0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
                    PUSH1(0x20)
                    MSTORE
                    // G2_x11
                    PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
                    PUSH1(0x40)
                    MSTORE
                    // G2_x12
                    PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                    PUSH1(0x60)
                    MSTORE
                    // G2_y11
                    PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                    PUSH1(0x80)
                    MSTORE
                    // G2_y12
                    PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                    PUSH1(0xA0)
                    MSTORE
                    // G1_x2
                    PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                    PUSH1(0xC0)
                    MSTORE
                    // G1_y2
                    PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                    PUSH1(0xE0)
                    MSTORE
                    // G2_x21
                    PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                    PUSH2(0x100)
                    MSTORE
                    // G2_x22
                    PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                    PUSH2(0x120)
                    MSTORE
                    // G2_y21
                    PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                    PUSH2(0x140)
                    MSTORE
                    // G2_y22
                    PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                    PUSH2(0x160)
                    MSTORE
                };
                let mut memory_addr = 0x180;
                for _ in 0..2 {
                    // G1::random
                    let g1 = G1Affine::random(&mut rng);
                    setup_code.push(32, Word::from_little_endian(&g1.x.to_bytes()));
                    setup_code.push(2, memory_addr);
                    memory_addr += 0x20;
                    setup_code.write_op(OpcodeId::MSTORE);
                    setup_code.push(32, Word::from_little_endian(&g1.y.to_bytes()));
                    setup_code.push(2, memory_addr);
                    memory_addr += 0x20;
                    setup_code.write_op(OpcodeId::MSTORE);
                    // G2::identity
                    for _ in 0..4 {
                        setup_code.push(1, 0x00);
                        setup_code.push(2, memory_addr);
                        memory_addr += 0x20;
                        setup_code.write_op(OpcodeId::MSTORE);
                    }
                }
                setup_code
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x300.into(),
            ret_offset: 0x300.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Bn128Pairing.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecPairing (pairing true): 4 pairs with random G2s",
            setup_code: {
                let mut setup_code = bytecode! {
                    // G1_x1
                    PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"))
                    PUSH1(0x00)
                    MSTORE
                    // G1_y1
                    PUSH32(word!("0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
                    PUSH1(0x20)
                    MSTORE
                    // G2_x11
                    PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
                    PUSH1(0x40)
                    MSTORE
                    // G2_x12
                    PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                    PUSH1(0x60)
                    MSTORE
                    // G2_y11
                    PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                    PUSH1(0x80)
                    MSTORE
                    // G2_y12
                    PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                    PUSH1(0xA0)
                    MSTORE
                    // G1_x2
                    PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                    PUSH1(0xC0)
                    MSTORE
                    // G1_y2
                    PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                    PUSH1(0xE0)
                    MSTORE
                    // G2_x21
                    PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                    PUSH2(0x100)
                    MSTORE
                    // G2_x22
                    PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                    PUSH2(0x120)
                    MSTORE
                    // G2_y21
                    PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                    PUSH2(0x140)
                    MSTORE
                    // G2_y22
                    PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                    PUSH2(0x160)
                    MSTORE
                };
                let mut memory_addr = 0x180;
                for _ in 0..2 {
                    // G1::identity
                    for _ in 0..2 {
                        setup_code.push(1, 0x00);
                        setup_code.push(2, memory_addr);
                        memory_addr += 0x20;
                        setup_code.write_op(OpcodeId::MSTORE);
                    }
                    // G2::random
                    let g2 = G2Affine::random(&mut rng);
                    for fq in [g2.x.c0, g2.x.c1, g2.y.c0, g2.y.c1].iter() {
                        setup_code.push(32, Word::from_little_endian(&fq.to_bytes()));
                        setup_code.push(2, memory_addr);
                        memory_addr += 0x20;
                        setup_code.write_op(OpcodeId::MSTORE);
                    }
                }
                setup_code
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x300.into(),
            ret_offset: 0x300.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Bn128Pairing.address().to_word(),
            ..Default::default()
        },
    ]
});
