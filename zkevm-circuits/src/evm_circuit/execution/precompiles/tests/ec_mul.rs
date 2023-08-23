use bus_mapping::{evm::PrecompileCallArgs, precompile::PrecompileCalls};
use eth_types::{bytecode, word, ToWord};
use once_cell::sync::Lazy;

pub static TEST_VECTOR: Lazy<Vec<PrecompileCallArgs>> = Lazy::new(|| {
    vec![
        PrecompileCallArgs {
            name: "ecMul (valid input)",
            // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)
            // s = 7
            setup_code: bytecode! {
                // p_x
                PUSH1(0x02)
                PUSH1(0x00)
                MSTORE

                // p_y
                PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                PUSH1(0x20)
                MSTORE

                // s
                PUSH1(0x07)
                PUSH1(0x40)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x60.into(),
            ret_offset: 0x60.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Mul.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecMul (invalid input: point not on curve)",
            // P = (2, 3)
            // s = 7
            setup_code: bytecode! {
                // p_x
                PUSH1(0x02)
                PUSH1(0x00)
                MSTORE

                // p_y
                PUSH1(0x03)
                PUSH1(0x20)
                MSTORE

                // s
                PUSH1(0x07)
                PUSH1(0x40)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x60.into(),
            ret_offset: 0x60.into(),
            ret_size: 0x00.into(),
            address: PrecompileCalls::Bn128Mul.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecMul (valid input < 96 bytes)",
            // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)
            // s = blank
            setup_code: bytecode! {
                // p_x
                PUSH1(0x02)
                PUSH1(0x00)
                MSTORE

                // p_y
                PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                PUSH1(0x20)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x40.into(),
            ret_offset: 0x40.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Mul.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecMul (should succeed on empty inputs)",
            setup_code: bytecode! {},
            call_data_offset: 0x00.into(),
            call_data_length: 0x00.into(),
            ret_offset: 0x00.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Mul.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecMul (valid inputs > 96 bytes)",
            // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)
            // s = 7
            setup_code: bytecode! {
                // p_x
                PUSH1(0x02)
                PUSH1(0x00)
                MSTORE

                // p_y
                PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                PUSH1(0x20)
                MSTORE

                // s
                PUSH1(0x07)
                PUSH1(0x40)
                MSTORE

                // junk bytes, will be truncated
                PUSH32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128)
                PUSH1(0x80)
                SHL
                PUSH32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128)
                ADD
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x80.into(),
            ret_offset: 0x80.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Mul.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecMul (invalid input: must mod p to be valid)",
            // P = (p + 1, p + 2)
            // s = 7
            setup_code: bytecode! {
                // p_x
                PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD48"))
                PUSH1(0x00)
                MSTORE

                // p_y
                PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD49"))
                PUSH1(0x20)
                MSTORE

                // s = 7
                PUSH1(0x07)
                PUSH1(0x40)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x60.into(),
            ret_offset: 0x60.into(),
            ret_size: 0x00.into(),
            address: PrecompileCalls::Bn128Mul.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name:
                "ecMul (valid: scalar larger than scalar field order n but less than base field p)",
            // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)

            // For bn256 (alt_bn128) scalar field:
            // n = 21888242871839275222246405745257275088548364400416034343698204186575808495617

            // Choose scalar s such that n < s < p
            // s = 21888242871839275222246405745257275088548364400416034343698204186575808500000
            setup_code: bytecode! {
                // p_x
                PUSH1(0x02)
                PUSH1(0x00)
                MSTORE

                // p_y
                PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                PUSH1(0x20)
                MSTORE
                // s
                PUSH32(word!("0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0001120"))
                PUSH1(0x40)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x60.into(),
            ret_offset: 0x60.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Mul.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecMul (valid: scalar larger than base field order)",
            // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)
            // s = 2^256 - 1
            setup_code: bytecode! {
                // p_x
                PUSH1(0x02)
                PUSH1(0x00)
                MSTORE

                // p_y
                PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                PUSH1(0x20)
                MSTORE

                // s
                PUSH32(word!("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))
                PUSH1(0x40)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x60.into(),
            ret_offset: 0x60.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Mul.address().to_word(),
            ..Default::default()
        },
    ]
});
