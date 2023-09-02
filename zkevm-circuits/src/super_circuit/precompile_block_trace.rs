#![allow(unused_imports)]
pub use super::*;
use bus_mapping::{
    evm::{OpcodeId, PrecompileCallArgs},
    precompile::PrecompileCalls,
};
use ethers_signers::{LocalWallet, Signer};
use mock::{eth, TestContext, MOCK_CHAIN_ID, MOCK_DIFFICULTY_L2GETH as MOCK_DIFFICULTY};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// use crate::witness::block_apply_mpt_state;
#[cfg(feature = "scroll")]
use eth_types::l2_types::BlockTrace;
use eth_types::{address, bytecode, evm_types::GasCost, word, Bytecode, ToWord, Word};

#[cfg(feature = "scroll")]
pub(crate) fn block_ec_ops() -> BlockTrace {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode_ec_add = PrecompileCallArgs {
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
    }
    .with_call_op(OpcodeId::STATICCALL);
    let bytecode_ec_mul = PrecompileCallArgs {
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
    }
    .with_call_op(OpcodeId::CALL);
    let bytecode_ec_pairing = PrecompileCallArgs {
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
    }
    .with_call_op(OpcodeId::DELEGATECALL);
    let bytecode_modexp_256 = PrecompileCallArgs {
        name: "modexp length in u256",
        setup_code: bytecode! {
            // Base size
            PUSH1(0x20)
            PUSH1(0x00)
            MSTORE
            // Esize
            PUSH1(0x20)
            PUSH1(0x20)
            MSTORE
            // Msize
            PUSH1(0x20)
            PUSH1(0x40)
            MSTORE
            // B, E and M
            PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000008"))
            PUSH1(0x60)
            MSTORE
            PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000009"))
            PUSH1(0x80)
            MSTORE
            PUSH32(word!("0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47"))
            PUSH1(0xA0)
            MSTORE
        },
        call_data_offset: 0x0.into(),
        call_data_length: 0xc0.into(),
        ret_offset: 0xe0.into(),
        ret_size: 0x01.into(),
        address: PrecompileCalls::Modexp.address().to_word(),
        ..Default::default()
    }
    .with_call_op(OpcodeId::STATICCALL);

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");
    let addr_c = address!("0x000000000000000000000000000000000000CCCC");
    let addr_d = address!("0x000000000000000000000000000000000000DDDD");
    let addr_e = address!("0x000000000000000000000000000000000000EEEE");

    // 5 accounts and 4 txs.
    TestContext::<5, 4>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0].address(addr_a).balance(Word::from(1u64 << 24));
            accs[1]
                .address(addr_b)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_add);
            accs[2]
                .address(addr_c)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_mul);
            accs[3]
                .address(addr_d)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_pairing);
            accs[4]
                .address(addr_e)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_modexp_256);
        },
        |mut txs, accs| {
            txs[0]
                .from(wallet_a.clone())
                .to(accs[1].address)
                .gas(Word::from(1_000_000u64));
            txs[1]
                .from(wallet_a.clone())
                .to(accs[2].address)
                .gas(Word::from(1_000_000u64));
            txs[2]
                .from(wallet_a.clone())
                .to(accs[3].address)
                .gas(Word::from(1_000_000u64));
            txs[3]
                .from(wallet_a.clone())
                .to(accs[4].address)
                .gas(Word::from(1_000_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .l2_trace()
    .clone()
}

#[cfg(feature = "scroll")]
pub(crate) fn block_precompile_oog() -> BlockTrace {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode_ec_add = PrecompileCallArgs {
        name: "ecAdd OOG (valid inputs: P == -Q), return size == 0",
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
        gas: 149.into(),
        ..Default::default()
    }
    .with_call_op(OpcodeId::STATICCALL);

    let bytecode_ec_mul = PrecompileCallArgs {
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
        gas: (PrecompileCalls::Bn128Mul.base_gas_cost().as_u64() - 1).to_word(),
        ..Default::default()
    }
    .with_call_op(OpcodeId::CALL);

    let bytecode_ec_pairing = PrecompileCallArgs {
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
        value: 1.into(),
        gas: (PrecompileCalls::Bn128Pairing.base_gas_cost().as_u64()
            + 2 * GasCost::PRECOMPILE_BN256PAIRING_PER_PAIR.as_u64()
            - 1)
        .to_word(),
        ..Default::default()
    }
    .with_call_op(OpcodeId::DELEGATECALL);

    let bytecode_modexp_256 = PrecompileCallArgs {
        name: "modexp length in u256",
        setup_code: bytecode! {},
        address: PrecompileCalls::Modexp.address().to_word(),
        ..Default::default()
    }
    .with_call_op(OpcodeId::STATICCALL);

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");
    let addr_c = address!("0x000000000000000000000000000000000000CCCC");
    let addr_d = address!("0x000000000000000000000000000000000000DDDD");
    let addr_e = address!("0x000000000000000000000000000000000000EEEE");

    // 5 accounts and 4 txs.
    TestContext::<5, 4>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0].address(addr_a).balance(Word::from(1u64 << 24));
            accs[1]
                .address(addr_b)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_add);
            accs[2]
                .address(addr_c)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_mul);
            accs[3]
                .address(addr_d)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_pairing);
            accs[4]
                .address(addr_e)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_modexp_256);
        },
        |mut txs, accs| {
            txs[0]
                .from(wallet_a.clone())
                .to(accs[1].address)
                .gas(Word::from(21_000u64));
            txs[1]
                .from(wallet_a.clone())
                .to(accs[2].address)
                .gas(Word::from(21_000u64));
            txs[2]
                .from(wallet_a.clone())
                .to(accs[3].address)
                .gas(Word::from(21_000u64));
            txs[3]
                .from(wallet_a.clone())
                .to(accs[4].address)
                .gas(Word::from(21_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .l2_trace()
    .clone()
}

#[cfg(feature = "scroll")]
pub(crate) fn block_precompile_invalid_ec_add() -> BlockTrace {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode_ec_add_noc = PrecompileCallArgs {
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
        gas: 1000.into(),
        address: PrecompileCalls::Bn128Add.address().to_word(),
        ..Default::default()
    }
    .with_call_op(OpcodeId::STATICCALL);

    let bytecode_ec_add_oor = PrecompileCallArgs {
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
    }
    .with_call_op(OpcodeId::DELEGATECALL);

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");
    let addr_c = address!("0x000000000000000000000000000000000000CCCC");

    // 3 accounts and 2 txs.
    TestContext::<3, 2>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0].address(addr_a).balance(Word::from(1u64 << 24));
            accs[1]
                .address(addr_b)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_add_noc);
            accs[2]
                .address(addr_c)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_add_oor);
        },
        |mut txs, accs| {
            txs[0]
                .from(wallet_a.clone())
                .to(accs[1].address)
                .gas(Word::from(21_000u64));
            txs[1]
                .from(wallet_a.clone())
                .to(accs[2].address)
                .gas(Word::from(21_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .l2_trace()
    .clone()
}

#[cfg(feature = "scroll")]
pub(crate) fn block_precompile_invalid_ec_mul() -> BlockTrace {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode_ec_mul_oor_p = PrecompileCallArgs {
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
    }
    .with_call_op(OpcodeId::CALL);

    let bytecode_ec_mul_noc_p = PrecompileCallArgs {
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
    }
    .with_call_op(OpcodeId::STATICCALL);

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");
    let addr_c = address!("0x000000000000000000000000000000000000CCCC");

    // 3 accounts and 2 txs.
    TestContext::<3, 2>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0].address(addr_a).balance(Word::from(1u64 << 24));
            accs[1]
                .address(addr_b)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_mul_oor_p);
            accs[2]
                .address(addr_c)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_mul_noc_p);
        },
        |mut txs, accs| {
            txs[0]
                .from(wallet_a.clone())
                .to(accs[1].address)
                .gas(Word::from(1_000_000u64));
            txs[1]
                .from(wallet_a.clone())
                .to(accs[2].address)
                .gas(Word::from(1_000_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .l2_trace()
    .clone()
}

#[cfg(feature = "scroll")]
pub(crate) fn block_precompile_invalid_ec_pairing_batch1() -> BlockTrace {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode_ec_pairing_oor = PrecompileCallArgs {
        name: "ecPairing (invalid): invalid field element, mod p is valid",
        setup_code: bytecode! {
            // G1_x1
            PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD48")) // p + 1
            PUSH1(0x00)
            MSTORE
            // G1_y1
            PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD49")) // p + 2
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
        value: 1.into(),
        address: PrecompileCalls::Bn128Pairing.address().to_word(),
        ..Default::default()
    }
    .with_call_op(OpcodeId::CALL);

    let bytecode_ec_pairing_noc_g1 = PrecompileCallArgs {
        name: "ecPairing (invalid): G1 point not on curve",
        setup_code: bytecode! {
            // G1_x1
            PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18d0"))
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
    }
    .with_call_op(OpcodeId::STATICCALL);

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");
    let addr_c = address!("0x000000000000000000000000000000000000CCCC");

    // 3 accounts and 2 txs.
    TestContext::<3, 2>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0].address(addr_a).balance(Word::from(1u64 << 24));
            accs[1]
                .address(addr_b)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_pairing_oor);
            accs[2]
                .address(addr_c)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_pairing_noc_g1);
        },
        |mut txs, accs| {
            txs[0]
                .from(wallet_a.clone())
                .to(accs[1].address)
                .gas(Word::from(1_000_000u64));
            txs[1]
                .from(wallet_a.clone())
                .to(accs[2].address)
                .gas(Word::from(1_000_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .l2_trace()
    .clone()
}

#[cfg(feature = "scroll")]
pub(crate) fn block_precompile_invalid_ec_pairing_batch2() -> BlockTrace {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode_ec_pairing_noc_g2 = PrecompileCallArgs {
        name: "ecPairing (invalid): G2 point not on curve",
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
            PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebb"))
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
    }
    .with_call_op(OpcodeId::DELEGATECALL);

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");

    // 2 accounts and 1 tx.
    TestContext::<2, 1>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0].address(addr_a).balance(Word::from(1u64 << 24));
            accs[1]
                .address(addr_b)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_ec_pairing_noc_g2);
        },
        |mut txs, accs| {
            txs[0]
                .from(wallet_a.clone())
                .to(accs[1].address)
                .gas(Word::from(1_000_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .l2_trace()
    .clone()
}

#[cfg(feature = "scroll")]
pub(crate) fn block_precompile_invalid_modexp() -> BlockTrace {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode_modexp_oor_1 = PrecompileCallArgs {
        name: "modexp length too large invalid",
        setup_code: bytecode! {
            // Base size
            PUSH1(0x1)
            PUSH1(0x00)
            MSTORE
            // Esize
            PUSH1(0x1)
            PUSH1(0x20)
            MSTORE
            // Msize
            PUSH1(0x21)
            PUSH1(0x40)
            MSTORE
            // B, E and M
            PUSH32(word!("0x08090A0000000000000000000000000000000000000000000000000000000000"))
            PUSH1(0x60)
            MSTORE
        },
        call_data_offset: 0x0.into(),
        call_data_length: 0x63.into(),
        ret_offset: 0x9f.into(),
        ret_size: 0x01.into(),
        address: PrecompileCalls::Modexp.address().to_word(),
        gas: 100000.into(),
        ..Default::default()
    }
    .with_call_op(OpcodeId::STATICCALL);

    let bytecode_modexp_oor_2 = PrecompileCallArgs {
        name: "modexp length too large invalid",
        setup_code: bytecode! {
            // Base size
            PUSH1(0x21)
            PUSH1(0x00)
            MSTORE
            // Esize
            PUSH1(0x21)
            PUSH1(0x20)
            MSTORE
            // Msize
            PUSH1(0x21)
            PUSH1(0x40)
            MSTORE
            // B, E and M
            PUSH32(word!("0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"))
            PUSH1(0x60)
            MSTORE
            PUSH32(word!("0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"))
            PUSH1(0x80)
            MSTORE
            PUSH32(word!("0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"))
            PUSH1(0xa0)
            MSTORE
            PUSH32(word!("0x08090A0000000000000000000000000000000000000000000000000000000000"))
            PUSH1(0xc0)
            MSTORE
        },
        call_data_offset: 0x0.into(),
        call_data_length: 0xc3.into(),
        ret_offset: 0xe0.into(),
        ret_size: 0x21.into(),
        address: PrecompileCalls::Modexp.address().to_word(),
        gas: 1000.into(),
        ..Default::default()
    }
    .with_call_op(OpcodeId::CALL);

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");
    let addr_c = address!("0x000000000000000000000000000000000000CCCC");

    // 3 accounts and 2 txs.
    TestContext::<3, 2>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0].address(addr_a).balance(Word::from(1u64 << 24));
            accs[1]
                .address(addr_b)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_modexp_oor_1);
            accs[2]
                .address(addr_c)
                .balance(Word::from(1u64 << 20))
                .code(bytecode_modexp_oor_2);
        },
        |mut txs, accs| {
            txs[0]
                .from(wallet_a.clone())
                .to(accs[1].address)
                .gas(Word::from(1_000_000u64));
            txs[1]
                .from(wallet_a.clone())
                .to(accs[2].address)
                .gas(Word::from(1_000_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .l2_trace()
    .clone()
}
