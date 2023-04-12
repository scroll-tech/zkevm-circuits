#![allow(unused_imports)]
use crate::{
    evm_circuit::witness::{block_convert, Block},
    exp_circuit::ExpCircuit,
};
use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams},
    evm::OpcodeId,
    mock::BlockData,
};
use eth_types::{bytecode, geth_types::GethData, Bytecode, Field, Word};
use halo2_proofs::{
    circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
};
use mock::TestContext;

/// Test exponentiation circuit with the provided block witness
pub fn test_exp_circuit<F: Field>(k: u32, block: Block<F>) {
    let circuit = ExpCircuit::<F>::new(
        block.exp_events.clone(),
        block.circuits_params.max_exp_steps,
    );
    let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied_par()
}

fn gen_code_single(base: Word, exponent: Word) -> Bytecode {
    bytecode! {
        PUSH32(exponent)
        PUSH32(base)
        EXP
        STOP
    }
}

fn gen_code_multiple(args: Vec<(Word, Word)>) -> Bytecode {
    let mut code = Bytecode::default();
    for (base, exponent) in args.into_iter() {
        code.push(32, exponent);
        code.push(32, base);
        code.write_op(OpcodeId::EXP);
    }
    code.write_op(OpcodeId::STOP);
    code
}

fn gen_data(code: Bytecode) -> CircuitInputBuilder {
    let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    builder
}

fn test_ok(base: Word, exponent: Word, k: Option<u32>) {
    let code = gen_code_single(base, exponent);
    let builder = gen_data(code);
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    test_exp_circuit(k.unwrap_or(18), block);
}

fn test_ok_multiple(args: Vec<(Word, Word)>) {
    let code = gen_code_multiple(args);
    let builder = gen_data(code);
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    test_exp_circuit(20, block);
}

#[test]
fn exp_circuit_single() {
    test_ok(2.into(), 2.into(), None);
    test_ok(3.into(), 7.into(), None);
    test_ok(5.into(), 11.into(), None);
    test_ok(7.into(), 13.into(), None);
    test_ok(11.into(), 17.into(), None);
    test_ok(13.into(), 23.into(), None);
    test_ok(29.into(), 43.into(), None);
    test_ok(41.into(), 259.into(), None);
}

#[test]
fn exp_circuit_big() {
    test_ok(
        2.into(),
        Word::from_str_radix("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE", 16).unwrap(),
        Some(20),
    );
}

#[test]
fn exp_circuit_multiple() {
    test_ok_multiple(vec![
        (3.into(), 7.into()),
        (5.into(), 11.into()),
        (7.into(), 13.into()),
        (11.into(), 17.into()),
        (13.into(), 23.into()),
        (29.into(), 43.into()),
        (41.into(), 259.into()),
    ]);
}

#[test]
fn variadic_size_check() {
    let k = 20;
    // Empty
    let block: GethData = TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b)
        .unwrap()
        .into();
    let mut builder =
        BlockData::new_from_geth_data_with_params(block.clone(), CircuitsParams::default())
            .new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    let circuit = ExpCircuit::<Fr>::new(
        block.exp_events.clone(),
        block.circuits_params.max_exp_steps,
    );
    let prover1 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

    // Non-empty
    let code = bytecode! {
        PUSH32(8)
        PUSH32(10)
        EXP
        PUSH32(3)
        PUSH32(5)
        EXP
        STOP
    };
    let builder = gen_data(code);
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    let circuit = ExpCircuit::<Fr>::new(
        block.exp_events.clone(),
        block.circuits_params.max_exp_steps,
    );
    let prover2 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

    assert_eq!(prover1.fixed(), prover2.fixed());
    assert_eq!(prover1.permutation(), prover2.permutation());
}
