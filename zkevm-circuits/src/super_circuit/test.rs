pub use super::*;
use bus_mapping::{
    circuit_input_builder::keccak_inputs,
    evm::{OpcodeId, PrecompileCallArgs},
    precompile::PrecompileCalls,
};
use ethers_signers::{LocalWallet, Signer};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use log::error;
use mock::{eth, TestContext, MOCK_CHAIN_ID, MOCK_DIFFICULTY};
use mpt_zktrie::state::builder::HASH_SCHEME_DONE;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{collections::HashMap, env::set_var};

use eth_types::{address, bytecode, geth_types::GethData, word, Bytecode, ToWord, Word};

#[test]
fn super_circuit_degree() {
    let mut cs = ConstraintSystem::<Fr>::default();
    SuperCircuit::<Fr, 1, 32, 64, 0x100>::configure(&mut cs);
    log::info!("super circuit degree: {}", cs.degree());
    log::info!("super circuit minimum_rows: {}", cs.minimum_rows());
    assert!(cs.degree() <= 9);
}

fn test_super_circuit<
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_INNER_BLOCKS: usize,
    const MOCK_RANDOMNESS: u64,
>(
    geth_data: GethData,
    circuits_params: CircuitsParams,
) {
    set_var("COINBASE", "0x0000000000000000000000000000000000000000");
    set_var("CHAIN_ID", MOCK_CHAIN_ID.to_string());
    let mut difficulty_be_bytes = [0u8; 32];
    MOCK_DIFFICULTY.to_big_endian(&mut difficulty_be_bytes);
    set_var("DIFFICULTY", hex::encode(difficulty_be_bytes));

    let block_data = BlockData::new_from_geth_data_with_params(geth_data, circuits_params);
    let mut builder = block_data.new_circuit_input_builder();
    builder
        .handle_block(&block_data.eth_block, &block_data.geth_traces)
        .expect("could not handle block tx");
    let mut block = block_convert(&builder.block, &builder.code_db).unwrap();
    block.randomness = Fr::from(MOCK_RANDOMNESS);

    // Mock fill state roots
    assert!(*HASH_SCHEME_DONE);
    block.mpt_updates.mock_fill_state_roots();
    block.prev_state_root = block.mpt_updates.old_root();

    // Recompute keccak inputs for updated prev_state_root.
    builder.block.prev_state_root = block.mpt_updates.old_root();
    block.keccak_inputs = keccak_inputs(&builder.block, &builder.code_db).unwrap();

    let active_row_num =SuperCircuit::<
        Fr,
        MAX_TXS,
        MAX_CALLDATA,
        MAX_INNER_BLOCKS,
        MOCK_RANDOMNESS,
    >::min_num_rows_block(&block).0;
    let (k, circuit, instance) = SuperCircuit::<
        Fr,
        MAX_TXS,
        MAX_CALLDATA,
        MAX_INNER_BLOCKS,
        MOCK_RANDOMNESS,
    >::build_from_witness_block(block)
    .unwrap();
    let prover = MockProver::run(k, &circuit, instance).unwrap();

    let res = prover.verify_at_rows_par(0..active_row_num, 0..active_row_num);
    if let Err(errs) = res {
        error!("Verification failures: {:#?}", errs);
        prover.assert_satisfied_par();
        panic!("Failed verification");
    }
}

fn callee_bytecode(is_return: bool, offset: u64, length: u64) -> Bytecode {
    let memory_bytes = [0x60; 10];
    let memory_address = 0;
    let memory_value = Word::from_big_endian(&memory_bytes);
    let mut code = bytecode! {
        PUSH10(memory_value)
        PUSH1(memory_address)
        MSTORE
        PUSH2(length)
        PUSH2(32u64 - u64::try_from(memory_bytes.len()).unwrap() + offset)
    };
    code.write_op(if is_return {
        OpcodeId::RETURN
    } else {
        OpcodeId::REVERT
    });
    code
}

fn block_1tx_deploy() -> GethData {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);
    let addr_a = wallet_a.address();

    let mut wallets = HashMap::new();
    wallets.insert(wallet_a.address(), wallet_a);

    let tx_input = callee_bytecode(true, 300, 20).code();
    let mut block: GethData = TestContext::<2, 1>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0].address(addr_a).balance(eth(10));
        },
        |mut txs, accs| {
            txs[0].from(accs[0].address).input(tx_input.into());
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .into();
    block.sign(&wallets);
    block
}

pub(crate) fn block_1tx() -> GethData {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode = bytecode! {
        GAS
        STOP
    };

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");

    let mut wallets = HashMap::new();
    wallets.insert(wallet_a.address(), wallet_a);

    let mut block: GethData = TestContext::<2, 1>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0]
                .address(addr_b)
                .balance(Word::from(1u64 << 20))
                .code(bytecode);
            accs[1].address(addr_a).balance(Word::from(1u64 << 20));
        },
        |mut txs, accs| {
            txs[0]
                .from(accs[1].address)
                .to(accs[0].address)
                .gas(Word::from(1_000_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .into();
    block.sign(&wallets);
    block
}

pub(crate) fn block_2tx() -> GethData {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode = bytecode! {
        GAS
        STOP
    };

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");

    let mut wallets = HashMap::new();
    wallets.insert(wallet_a.address(), wallet_a);

    let mut block: GethData = TestContext::<2, 2>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0]
                .address(addr_b)
                .balance(Word::from(1u64 << 20))
                .code(bytecode);
            accs[1].address(addr_a).balance(Word::from(1u64 << 20));
        },
        |mut txs, accs| {
            txs[0]
                .from(accs[1].address)
                .to(accs[0].address)
                .gas(Word::from(1_000_000u64));
            txs[1]
                .from(accs[1].address)
                .to(accs[0].address)
                .gas(Word::from(1_000_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .into();
    block.sign(&wallets);
    block
}

pub(crate) fn block_ec_ops() -> GethData {
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

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");
    let addr_c = address!("0x000000000000000000000000000000000000CCCC");
    let addr_d = address!("0x000000000000000000000000000000000000DDDD");

    let mut wallets = HashMap::new();
    wallets.insert(wallet_a.address(), wallet_a);

    // 4 accounts and 3 txs.
    let mut block: GethData = TestContext::<4, 3>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0].address(addr_a).balance(Word::from(1u64 << 20));
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
        },
        |mut txs, accs| {
            txs[0]
                .from(accs[0].address)
                .to(accs[1].address)
                .gas(Word::from(1_000_000u64));
            txs[1]
                .from(accs[0].address)
                .to(accs[2].address)
                .gas(Word::from(1_000_000u64));
            txs[2]
                .from(accs[0].address)
                .to(accs[3].address)
                .gas(Word::from(1_000_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .into();
    block.sign(&wallets);
    block
}

const TEST_MOCK_RANDOMNESS: u64 = 0x100;

// High memory usage test.  Run in serial with:
// `cargo test [...] serial_ -- --ignored --test-threads 1`
#[ignore]
#[cfg(feature = "scroll")]
#[test]
fn serial_test_super_circuit_1tx_1max_tx() {
    let block = block_1tx();
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 256;
    const MAX_INNER_BLOCKS: usize = 1;
    let circuits_params = CircuitsParams {
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_rws: 256,
        max_copy_rows: 256,
        max_exp_steps: 256,
        max_bytecode: 512,
        max_mpt_rows: 512,
        max_poseidon_rows: 512,
        max_evm_rows: 0,
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_rlp_rows: 500,
        ..Default::default()
    };
    test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
        block,
        circuits_params,
    );
}

#[ignore]
#[cfg(feature = "scroll")]
#[test]
fn serial_test_super_circuit_1tx_deploy_2max_tx() {
    let block = block_1tx_deploy();
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 256;
    const MAX_INNER_BLOCKS: usize = 1;
    const MAX_RWS: usize = 256;
    const MAX_COPY_ROWS: usize = 256;
    let circuits_params = CircuitsParams {
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_rws: MAX_RWS,
        max_copy_rows: MAX_COPY_ROWS,
        max_mpt_rows: 1024,
        max_poseidon_rows: 1024,
        max_bytecode: 512,
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_exp_steps: 256,
        max_evm_rows: 0,
        max_rlp_rows: 500,
        ..Default::default()
    };
    test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
        block,
        circuits_params,
    );
}

#[ignore]
#[cfg(feature = "scroll")]
#[test]
fn serial_test_super_circuit_1tx_2max_tx() {
    let block = block_1tx();
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 256;
    const MAX_INNER_BLOCKS: usize = 1;
    let circuits_params = CircuitsParams {
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_rws: 256,
        max_copy_rows: 256,
        max_exp_steps: 256,
        max_bytecode: 512,
        max_mpt_rows: 512,
        max_poseidon_rows: 512,
        max_evm_rows: 0,
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_rlp_rows: 500,
        ..Default::default()
    };
    test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
        block,
        circuits_params,
    );
}

#[ignore]
#[cfg(feature = "scroll")]
#[test]
fn serial_test_super_circuit_2tx_4max_tx() {
    let block = block_2tx();
    const MAX_TXS: usize = 4;
    const MAX_CALLDATA: usize = 320;
    const MAX_INNER_BLOCKS: usize = 1;
    const MAX_RWS: usize = 256;
    const MAX_COPY_ROWS: usize = 256;
    let circuits_params = CircuitsParams {
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_rws: MAX_RWS,
        max_copy_rows: MAX_COPY_ROWS,
        max_bytecode: 512,
        max_mpt_rows: 512,
        max_poseidon_rows: 512,
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_exp_steps: 256,
        max_evm_rows: 0,
        max_rlp_rows: 800,
        ..Default::default()
    };
    test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
        block,
        circuits_params,
    );
}

#[ignore]
#[cfg(feature = "scroll")]
#[test]
fn serial_test_super_circuit_2tx_2max_tx() {
    let block = block_2tx();
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 256;
    const MAX_INNER_BLOCKS: usize = 1;
    let circuits_params = CircuitsParams {
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_rws: 256,
        max_copy_rows: 256,
        max_mpt_rows: 512,
        max_poseidon_rows: 512,
        max_exp_steps: 256,
        max_bytecode: 512,
        max_evm_rows: 0,
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_rlp_rows: 500,
        ..Default::default()
    };
    test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
        block,
        circuits_params,
    );
}

#[cfg(feature = "scroll")]
#[test]
fn test_super_circuit_ec_ops_txs() {
    let block = block_ec_ops();
    const MAX_TXS: usize = 3;
    const MAX_CALLDATA: usize = 320;
    const MAX_INNER_BLOCKS: usize = 1;
    const MAX_RWS: usize = 1024;
    const MAX_COPY_ROWS: usize = 2048;
    let circuits_params = CircuitsParams {
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_rws: MAX_RWS,
        max_copy_rows: MAX_COPY_ROWS,
        max_bytecode: 4096,
        max_mpt_rows: 2048,
        max_poseidon_rows: 2048,
        max_evm_rows: 0,
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_exp_steps: 256,
        max_rlp_rows: 800,
        ..Default::default()
    };
    test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
        block,
        circuits_params,
    );
}
