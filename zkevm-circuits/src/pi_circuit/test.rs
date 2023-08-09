#![allow(unused_imports)]
use super::{dev::*, *};
use crate::util::unusable_rows;
use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
};
use mock::{test_ctx::helpers::tx_from_1_to_0, CORRECT_MOCK_TXS, MOCK_CHAIN_ID, MOCK_DIFFICULTY};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::env::set_var;

use crate::{super_circuit::test::block_2tx, witness::block_convert};
use bus_mapping::mock::BlockData;
use eth_types::{bytecode, geth_types::GethData};
use mock::{test_ctx::helpers::account_0_code_account_1_no_code, TestContext};

// #[test]
// fn pi_circuit_unusable_rows() {
//     const MAX_TXS: usize = 2;
//     const MAX_CALLDATA: usize = 8;
//     const MAX_INNER_BLOCKS: usize = 1;
//     assert_eq!(
//         PiCircuit::<Fr>::unusable_rows(),
//         unusable_rows::<Fr, PiTestCircuit::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>>(),
//     )
// }

fn run<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_INNER_BLOCKS: usize>(
    k: u32,
    block: Block<F>,
) -> Result<(), Vec<VerifyFailure>> {
    let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>(PiCircuit::new(
        MAX_TXS,
        MAX_CALLDATA,
        MAX_INNER_BLOCKS,
        &block,
    ));
    let public_inputs = circuit.0.instance();

    let prover = match MockProver::run(k, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };
    prover.assert_satisfied_par();
    prover.verify()
}

fn block_1tx() -> Block<Fr> {
    use crate::super_circuit::test::block_1tx;

    let block = block_1tx();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    block_convert(&builder.block, &builder.code_db).unwrap()
}

fn block_2txs() -> Block<Fr> {
    use crate::super_circuit::test::block_1tx;

    let block = block_2tx();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    block_convert(&builder.block, &builder.code_db).unwrap()
}

fn empty_block() -> Block<Fr> {
    Block::<Fr> {
        txs: vec![],
        sigs: vec![],
        ..Default::default()
    }
}

#[cfg(feature = "scroll")]
#[test]
fn serial_test_simple_pi() {
    const MAX_TXS: usize = 4;
    const MAX_CALLDATA: usize = 20;
    const MAX_INNER_BLOCKS: usize = 4;

    let mut difficulty_be_bytes = [0u8; 32];
    MOCK_DIFFICULTY.to_big_endian(&mut difficulty_be_bytes);
    set_var("DIFFICULTY", hex::encode(difficulty_be_bytes));
    set_var("COINBASE", "0x0000000000000000000000000000000000000000");

    let block = block_1tx();

    let k = 16;
    assert_eq!(
        run::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>(k, block),
        Ok(())
    );
}

fn run_size_check<
    F: Field,
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_INNER_BLOCKS: usize,
>(
    blocks: [Block<F>; 2],
) {
    let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>(PiCircuit::new(
        MAX_TXS,
        MAX_CALLDATA,
        MAX_INNER_BLOCKS,
        &blocks[0],
    ));
    let public_inputs = circuit.0.instance();
    let prover1 = MockProver::run(20, &circuit, public_inputs).unwrap();

    let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>(PiCircuit::new(
        MAX_TXS,
        MAX_CALLDATA,
        MAX_INNER_BLOCKS,
        &blocks[1],
    ));
    let public_inputs = circuit.0.instance();
    let prover2 = MockProver::run(20, &circuit, public_inputs).unwrap();

    assert_eq!(prover1.fixed(), prover2.fixed());
    assert_eq!(prover1.permutation(), prover2.permutation());
}

#[test]
fn variadic_size_check() {
    const MAX_TXS: usize = 8;
    const MAX_CALLDATA: usize = 200;
    const MAX_INNER_BLOCKS: usize = 4;

    let block_0 = empty_block();
    let block_1 = block_1tx();
    let block_2 = block_2txs();

    run_size_check::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>([block_1, block_2.clone()]);
    run_size_check::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>([block_0, block_2]);
}
