#![allow(unused_imports)]
pub use super::*;
use bus_mapping::{
    circuit_input_builder::CircuitInputBuilder,
    evm::{OpcodeId, PrecompileCallArgs},
    precompile::PrecompileCalls,
};
use ethers_signers::{LocalWallet, Signer};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use log::error;
#[cfg(not(feature = "scroll"))]
use mock::MOCK_DIFFICULTY;
#[cfg(feature = "scroll")]
use mock::MOCK_DIFFICULTY_L2GETH as MOCK_DIFFICULTY;
use mock::{eth, TestContext, MOCK_CHAIN_ID};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::env::set_var;

use crate::witness::block_apply_mpt_state;
#[cfg(feature = "scroll")]
use eth_types::l2_types::BlockTrace;
use eth_types::{address, bytecode, word, Bytecode, ToWord, Word};

#[test]
fn super_circuit_degree() {
    let mut cs = ConstraintSystem::<Fr>::default();
    SuperCircuit::<Fr, 1, 32, 64, 0x100>::configure(&mut cs);
    log::info!("super circuit degree: {}", cs.degree());
    log::info!("super circuit minimum_rows: {}", cs.minimum_rows());
    assert!(cs.degree() <= 9);
}

#[cfg(feature = "scroll")]
fn test_super_circuit<
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_INNER_BLOCKS: usize,
    const MOCK_RANDOMNESS: u64,
>(
    l2_trace: BlockTrace,
    circuits_params: CircuitsParams,
) {
    set_var("COINBASE", "0x0000000000000000000000000000000000000000");
    set_var("CHAIN_ID", MOCK_CHAIN_ID.to_string());
    let mut difficulty_be_bytes = [0u8; 32];
    MOCK_DIFFICULTY.to_big_endian(&mut difficulty_be_bytes);
    set_var("DIFFICULTY", hex::encode(difficulty_be_bytes));

    let mut builder =
        CircuitInputBuilder::new_from_l2_trace(circuits_params, l2_trace, false, false)
            .expect("could not handle block tx");

    builder
        .finalize_building()
        .expect("could not finalize building block");

    let mut block = block_convert(&builder.block, &builder.code_db).unwrap();
    block_apply_mpt_state(
        &mut block,
        &builder.mpt_init_state.expect("used non-light mode"),
    );

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

#[cfg(feature = "scroll")]
fn block_1tx_deploy() -> BlockTrace {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);
    let addr_a = wallet_a.address();

    let tx_input = callee_bytecode(true, 300, 20).code();
    TestContext::<2, 1>::new(
        Some(vec![Word::zero()]),
        |accs| {
            accs[0].address(addr_a).balance(eth(10));
        },
        |mut txs, _accs| {
            txs[0].from(wallet_a).input(tx_input.into());
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .l2_trace()
    .clone()
}

fn block_1tx_ctx() -> TestContext<2, 1> {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode = bytecode! {
        GAS
        STOP
    };

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");

    TestContext::new(
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
                .from(wallet_a)
                .to(accs[0].address)
                .gas(Word::from(1_000_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
}

#[cfg(feature = "scroll")]
fn block_1tx_trace() -> BlockTrace {
    block_1tx_ctx().l2_trace().clone()
}

pub(crate) fn block_1tx() -> GethData {
    block_1tx_ctx().into()
}

fn block_2tx_ctx() -> TestContext<2, 2> {
    let mut rng = ChaCha20Rng::seed_from_u64(2);

    let chain_id = *MOCK_CHAIN_ID;

    let bytecode = bytecode! {
        GAS
        STOP
    };

    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x000000000000000000000000000000000000BBBB");

    TestContext::new(
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
                .from(wallet_a.clone())
                .to(accs[0].address)
                .gas(Word::from(1_000_000u64));
            txs[1]
                .from(wallet_a.clone())
                .to(accs[0].address)
                .gas(Word::from(1_000_000u64));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
}

#[cfg(feature = "scroll")]
fn block_2tx_trace() -> BlockTrace {
    block_2tx_ctx().l2_trace().clone()
}

pub(crate) fn block_2tx() -> GethData {
    block_2tx_ctx().into()
}

const TEST_MOCK_RANDOMNESS: u64 = 0x100;

// High memory usage test.  Run in serial with:
// `cargo test [...] serial_ -- --ignored --test-threads 1`
#[ignore]
#[cfg(feature = "scroll")]
#[test]
fn serial_test_super_circuit_1tx_1max_tx() {
    let block = block_1tx_trace();
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
        max_mpt_rows: 2049,
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
        max_mpt_rows: 2049,
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
    let block = block_1tx_trace();
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
        max_mpt_rows: 2049,
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
    let block = block_2tx_trace();
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
        max_mpt_rows: 2049,
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
    let block = block_2tx_trace();
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 256;
    const MAX_INNER_BLOCKS: usize = 1;
    let circuits_params = CircuitsParams {
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_rws: 256,
        max_copy_rows: 256,
        max_mpt_rows: 2049,
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
fn precomiple_super_circuits_params(max_txs: usize, max_calldata: usize) -> CircuitsParams {
    const MAX_RWS: usize = 4096;
    const MAX_COPY_ROWS: usize = 16384; // precompile require many copies
    CircuitsParams {
        max_txs,
        max_calldata,
        max_rws: MAX_RWS,
        max_copy_rows: MAX_COPY_ROWS,
        max_bytecode: 16384,
        max_mpt_rows: 2049,
        max_poseidon_rows: 8192,
        max_evm_rows: 0,
        // modexp ref this to decide its ability, we
        // need at least one (~25000 rows)
        max_keccak_rows: 40000,
        max_inner_blocks: 1,
        max_exp_steps: 256,
        max_rlp_rows: 3200,
        ..Default::default()
    }
}

#[ignore]
#[cfg(feature = "scroll")]
#[test]
fn serial_test_super_circuit_ec_ops_txs() {
    const MAX_TXS: usize = 4;
    const MAX_CALLDATA: usize = 0x320;

    let block = precompile_block_trace::block_ec_ops();
    let circuits_params = precomiple_super_circuits_params(MAX_TXS, MAX_CALLDATA);

    test_super_circuit::<MAX_TXS, MAX_CALLDATA, 1, TEST_MOCK_RANDOMNESS>(block, circuits_params);
}

#[ignore]
#[cfg(feature = "scroll")]
#[test]
fn serial_test_super_circuit_precompile_oog() {
    const MAX_TXS: usize = 4;
    const MAX_CALLDATA: usize = 0x260;

    let block = precompile_block_trace::block_precompile_oog();
    let circuits_params = precomiple_super_circuits_params(MAX_TXS, MAX_CALLDATA);

    test_super_circuit::<MAX_TXS, MAX_CALLDATA, 1, TEST_MOCK_RANDOMNESS>(block, circuits_params);
}

#[ignore]
#[cfg(feature = "scroll")]
#[test]
fn serial_test_super_circuit_invalid_precompile() {
    const MAX_TXS: usize = 3;
    const MAX_CALLDATA: usize = 0x8a6;

    let block = precompile_block_trace::block_invalid_precompile();
    let circuits_params = precomiple_super_circuits_params(MAX_TXS, MAX_CALLDATA);

    test_super_circuit::<MAX_TXS, MAX_CALLDATA, 1, TEST_MOCK_RANDOMNESS>(block, circuits_params);
}

#[ignore]
#[cfg(feature = "scroll")]
#[test]
fn serial_test_super_circuit_precompile_invalid_ec_pairing_fq_overflow() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 0x180;

    let block = precompile_block_trace::block_precompile_invalid_ec_pairing_fq_overflow();
    let circuits_params = precomiple_super_circuits_params(MAX_TXS, MAX_CALLDATA);

    test_super_circuit::<MAX_TXS, MAX_CALLDATA, 1, TEST_MOCK_RANDOMNESS>(block, circuits_params);
}
