use bus_mapping::{evm::PrecompileCallArgs, precompile::PrecompileCalls};
use eth_types::{bytecode, word, ToWord};
use once_cell::sync::Lazy;

pub static TEST_VECTOR: Lazy<Vec<PrecompileCallArgs>> = Lazy::new(|| {
    vec![
        PrecompileCallArgs {
            name: "ecAdd (valid inputs)",
            // P = (1, 2)
            // Q = (1, 2)
            setup_code: bytecode! {
                // p_x = 1
                PUSH1(0x01)
                PUSH1(0x00)
                MSTORE
                // p_y = 2
                PUSH1(0x02)
                PUSH1(0x20)
                MSTORE
                // q_x = 1
                PUSH1(0x01)
                PUSH1(0x40)
                MSTORE
                // q_y = 2
                PUSH1(0x02)
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x80.into(),
            ret_offset: 0x80.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecAdd (invalid input: point not on curve)",
            // P = (2, 3)
            // Q = (1, 2)
            setup_code: bytecode! {
                // p_x = 2
                PUSH1(0x02)
                PUSH1(0x00)
                MSTORE
                // p_y = 3
                PUSH1(0x03)
                PUSH1(0x20)
                MSTORE
                // q_x = 1
                PUSH1(0x01)
                PUSH1(0x40)
                MSTORE
                // q_y = 2
                PUSH1(0x02)
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x80.into(),
            ret_offset: 0x80.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecAdd (valid inputs: truncated byte, input resulting in valid curve point)",
            // P = (1, 2)
            // Q = (q_x, q_y)
            setup_code: bytecode! {
                // p_x = 1
                PUSH1(0x01)
                PUSH1(0x00)
                MSTORE
                // p_y = 2
                PUSH1(0x02)
                PUSH1(0x20)
                MSTORE
                // q_x = 0x0878b7f04b21d2b67978160da1f2740ff4ab143c6193ef0a8ca0f757c0a2c7ad
                PUSH32(word!("0x0878b7f04b21d2b67978160da1f2740ff4ab143c6193ef0a8ca0f757c0a2c7ad"))
                PUSH1(0x40)
                MSTORE
                // q_y = 0x00a5ad7b42f91a99b266c8a657b5c237b95831904a448e9ae8f5b6ce6a2a1b00
                PUSH32(word!("0x00a5ad7b42f91a99b266c8a657b5c237b95831904a448e9ae8f5b6ce6a2a1b00"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x7f.into(), // the last byte is 0x00 so should be valid.
            ret_offset: 0x80.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecAdd (invalid inputs: truncated bytes, input resulting in invalid curve point)",
            // P = (1, 2)
            // Q = (q_x, q_y)
            setup_code: bytecode! {
                // p_x = 1
                PUSH1(0x01)
                PUSH1(0x00)
                MSTORE
                // p_y = 2
                PUSH1(0x02)
                PUSH1(0x20)
                MSTORE
                // q_x = 0x0878b7f04b21d2b67978160da1f2740ff4ab143c6193ef0a8ca0f757c0a2c7ad
                PUSH32(word!("0x0878b7f04b21d2b67978160da1f2740ff4ab143c6193ef0a8ca0f757c0a2c7ad"))
                PUSH1(0x40)
                MSTORE
                // q_y = 0x00a5ad7b42f91a99b266c8a657b5c237b95831904a448e9ae8f5b6ce6a2a1b00
                PUSH32(word!("0x00a5ad7b42f91a99b266c8a657b5c237b95831904a448e9ae8f5b6ce6a2a1b00"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            // only the last byte is 0x00, so ignoring 2 bytes does not give us point on curve.
            call_data_length: 0x7e.into(),
            ret_offset: 0x80.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecAdd (valid inputs: truncated bytes, input resulting in valid curve point)",
            // P = (1, 2)
            // Q = (0, 0) truncated
            setup_code: bytecode! {
                // p_x = 1
                PUSH1(0x01)
                PUSH1(0x00)
                MSTORE
                // p_y = 2
                PUSH1(0x02)
                PUSH1(0x20)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x40.into(), // q is (0, 0)
            ret_offset: 0x40.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecAdd (should succeed on empty inputs)",
            setup_code: bytecode! {},
            call_data_offset: 0x00.into(),
            call_data_length: 0x00.into(),
            ret_offset: 0x00.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecAdd (valid inputs > 128 bytes)",
            // P = (1, 2)
            // Q = (1, 2)
            setup_code: bytecode! {
                // p_x = 1
                PUSH1(0x01)
                PUSH1(0x00)
                MSTORE
                // p_y = 2
                PUSH1(0x02)
                PUSH1(0x20)
                MSTORE
                // q_x = 1
                PUSH1(0x01)
                PUSH1(0x40)
                MSTORE
                // q_y = 2
                PUSH1(0x02)
                PUSH1(0x60)
                MSTORE
                // junk bytes, will be truncated
                PUSH32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128)
                PUSH1(0x80)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x80.into(),
            ret_offset: 0x80.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecAdd (invalid input: must mod p to be valid)",
            // P = (p + 1, p + 2)
            // Q = (1, 2)
            setup_code: bytecode! {
                // p_x
                PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD48"))
                PUSH1(0x00)
                MSTORE
                // p_y
                PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD49"))
                PUSH1(0x20)
                MSTORE
                // q_x = 1
                PUSH1(0x01)
                PUSH1(0x40)
                MSTORE
                // q_y = 2
                PUSH1(0x02)
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x80.into(),
            ret_offset: 0x80.into(),
            ret_size: 0x00.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecAdd (valid inputs: P == -Q)",
            // P = (1, 2)
            // Q = -P
            setup_code: bytecode! {
                // p_x
                PUSH1(0x01)
                PUSH1(0x00)
                MSTORE
                // p_y
                PUSH1(0x02)
                PUSH1(0x20)
                MSTORE
                // q_x = 1
                PUSH1(0x01)
                PUSH1(0x40)
                MSTORE
                // q_y = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
                PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x80.into(),
            ret_offset: 0x80.into(),
            ret_size: 0x40.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecAdd (valid inputs: P == -Q), return size == 0",
            // P = (1, 2)
            // Q = -P
            setup_code: bytecode! {
                // p_x
                PUSH1(0x01)
                PUSH1(0x00)
                MSTORE
                // p_y
                PUSH1(0x02)
                PUSH1(0x20)
                MSTORE
                // q_x = 1
                PUSH1(0x01)
                PUSH1(0x40)
                MSTORE
                // q_y = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
                PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x80.into(),
            ret_offset: 0x80.into(),
            ret_size: 0x00.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            ..Default::default()
        },
    ]
});
