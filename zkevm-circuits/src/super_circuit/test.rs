pub use super::*;
use bus_mapping::{circuit_input_builder::keccak_inputs, evm::OpcodeId};
use ethers_signers::{LocalWallet, Signer};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use log::error;
use mock::{eth, TestContext, MOCK_CHAIN_ID, MOCK_DIFFICULTY};
use mpt_zktrie::state::builder::HASH_SCHEME_DONE;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{collections::HashMap, env::set_var};

use eth_types::{address, bytecode, geth_types::GethData, Bytecode, Word};

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

    let (k, circuit, instance) = SuperCircuit::<
        Fr,
        MAX_TXS,
        MAX_CALLDATA,
        MAX_INNER_BLOCKS,
        MOCK_RANDOMNESS,
    >::build_from_witness_block(block)
    .unwrap();
    let prover = MockProver::run(k, &circuit, instance).unwrap();
    prover.assert_satisfied_par();
    let res = prover.verify_par();
    if let Err(err) = res {
        error!("Verification failures: {:#?}", err);
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
        max_evm_rows: 0,
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_rlp_rows: 500,
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
        max_bytecode: 512,
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_exp_steps: 256,
        max_evm_rows: 0,
        max_rlp_rows: 500,
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
        max_evm_rows: 0,
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_rlp_rows: 500,
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
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_exp_steps: 256,
        max_evm_rows: 0,
        max_rlp_rows: 800,
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
        max_exp_steps: 256,
        max_bytecode: 512,
        max_evm_rows: 0,
        max_keccak_rows: 0,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_rlp_rows: 500,
    };
    test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
        block,
        circuits_params,
    );
}
