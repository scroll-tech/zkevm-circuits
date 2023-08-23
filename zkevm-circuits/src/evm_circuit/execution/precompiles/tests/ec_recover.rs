use bus_mapping::{evm::PrecompileCallArgs, precompile::PrecompileCalls};
use eth_types::{bytecode, word, ToWord};
use once_cell::sync::Lazy;

pub static TEST_VECTOR: Lazy<Vec<PrecompileCallArgs>> = Lazy::new(|| {
    vec![
        PrecompileCallArgs {
            name: "ecrecover (invalid sig, addr not recovered)",
            setup_code: bytecode! {
                // msg hash from 0x00
                PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                PUSH1(0x00)
                MSTORE
                // signature v from 0x20
                PUSH1(28)
                PUSH1(0x20)
                MSTORE
                // signature r from 0x40
                PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                PUSH1(0x40)
                MSTORE
                // signature s from 0x60
                PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                PUSH1(0x60)
                MSTORE
            },
            // copy 96 bytes from memory addr 0. This is insufficient to recover an
            // address, and so the return data length from the precompile call will be 0.
            call_data_offset: 0x00.into(),
            call_data_length: 0x60.into(),
            // return 32 bytes and write from memory addr 128
            ret_offset: 0x80.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Ecrecover.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecrecover (invalid sig, addr recovered)",
            setup_code: bytecode! {
                // msg hash from 0x00
                PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                PUSH1(0x00)
                MSTORE
                // signature v from 0x20
                PUSH1(28)
                PUSH1(0x20)
                MSTORE
                // signature r from 0x40
                PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                PUSH1(0x40)
                MSTORE
                // signature s from 0x60
                PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                PUSH1(0x60)
                MSTORE
            },
            // copy 101 bytes from memory addr 0. This should be sufficient to recover an
            // address, but the signature is invalid (ecrecover does not care about this
            // though)
            call_data_offset: 0x00.into(),
            call_data_length: 0x65.into(),
            // return 32 bytes and write from memory addr 128
            ret_offset: 0x80.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Ecrecover.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecrecover (valid sig, addr recovered)",
            setup_code: bytecode! {
                // msg hash from 0x00
                PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                PUSH1(0x00)
                MSTORE
                // signature v from 0x20
                PUSH1(28)
                PUSH1(0x20)
                MSTORE
                // signature r from 0x40
                PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                PUSH1(0x40)
                MSTORE
                // signature s from 0x60
                PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                PUSH1(0x60)
                MSTORE
            },
            // copy 128 bytes from memory addr 0. Address is recovered and the signature is
            // valid.
            call_data_offset: 0x00.into(),
            call_data_length: 0x80.into(),
            // return 32 bytes and write from memory addr 128
            ret_offset: 0x80.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Ecrecover.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "ecrecover (valid sig, addr recovered, extra input bytes)",
            setup_code: bytecode! {
                // msg hash from 0x00
                PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                PUSH1(0x00)
                MSTORE
                // signature v from 0x20
                PUSH1(28)
                PUSH1(0x20)
                MSTORE
                // signature r from 0x40
                PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                PUSH1(0x40)
                MSTORE
                // signature s from 0x60
                PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                PUSH1(0x60)
                MSTORE
            },
            // copy 133 bytes from memory addr 0. Address is recovered and the signature is
            // valid. The 5 bytes after the first 128 bytes are ignored.
            call_data_offset: 0x00.into(),
            call_data_length: 0x85.into(),
            // return 32 bytes and write from memory addr 128
            ret_offset: 0x80.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Ecrecover.address().to_word(),
            ..Default::default()
        },
    ]
});
