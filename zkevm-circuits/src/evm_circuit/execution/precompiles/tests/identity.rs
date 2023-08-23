use bus_mapping::{evm::PrecompileCallArgs, precompile::PrecompileCalls};
use eth_types::{bytecode, word, ToWord};
use once_cell::sync::Lazy;

pub static TEST_VECTOR: Lazy<Vec<PrecompileCallArgs>> = Lazy::new(|| {
    vec![
        PrecompileCallArgs {
            name: "single-byte success",
            setup_code: bytecode! {
                // place params in memory
                PUSH1(0xff)
                PUSH1(0x00)
                MSTORE
            },
            call_data_offset: 0x1f.into(),
            call_data_length: 0x01.into(),
            ret_offset: 0x3f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Identity.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "multi-bytes success (less than 32 bytes)",
            setup_code: bytecode! {
                // place params in memory
                PUSH16(word!("0x0123456789abcdef0f1e2d3c4b5a6978"))
                PUSH1(0x00)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x10.into(),
            ret_offset: 0x20.into(),
            ret_size: 0x10.into(),
            address: PrecompileCalls::Identity.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "multi-bytes success (more than 32 bytes)",
            setup_code: bytecode! {
                // place params in memory
                PUSH30(word!("0x0123456789abcdef0f1e2d3c4b5a6978"))
                PUSH1(0x00) // place from 0x00 in memory
                MSTORE
                PUSH30(word!("0xaabbccdd001122331039abcdefefef84"))
                PUSH1(0x20) // place from 0x20 in memory
                MSTORE
            },
            // copy 63 bytes from memory addr 0
            call_data_offset: 0x00.into(),
            call_data_length: 0x3f.into(),
            // return only 35 bytes and write from memory addr 72
            ret_offset: 0x48.into(),
            ret_size: 0x23.into(),
            address: PrecompileCalls::Identity.address().to_word(),
            ..Default::default()
        },
    ]
});
