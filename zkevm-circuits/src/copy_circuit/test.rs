#![allow(unused_imports)]

use crate::{
    copy_circuit::*,
    evm_circuit::{test::rand_bytes, witness::block_convert},
    util::unusable_rows,
    witness::Block,
};
use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams},
    evm::{gen_sha3_code, MemoryKind, OpcodeId, PrecompileCallArgs},
    mock::BlockData,
    precompile::PrecompileCalls,
};
use eth_types::{
    address, bytecode, geth_types::GethData, word, AccessList, AccessListItem, ToWord, Word, H256,
};
use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
};
use mock::{
    eth, gwei, test_ctx::helpers::account_0_code_account_1_no_code, MockTransaction, TestContext,
    MOCK_ACCOUNTS,
};

const K: u32 = 20;

#[test]
fn copy_circuit_unusable_rows() {
    assert_eq!(
        CopyCircuit::<Fr>::unusable_rows(),
        unusable_rows::<Fr, CopyCircuit::<Fr>>(),
    )
}

/// Test copy circuit from copy events and test data
pub fn test_copy_circuit<F: Field>(
    copy_events: Vec<CopyEvent>,
    max_copy_rows: usize,
    external_data: ExternalData,
) -> Result<(), Vec<VerifyFailure>> {
    let circuit =
        CopyCircuit::<F>::new_with_external_data(copy_events, max_copy_rows, external_data);

    let prover = MockProver::<F>::run(K, &circuit, vec![]).unwrap();
    prover.verify_par()
}

/// Test copy circuit with the provided block witness
pub fn test_copy_circuit_from_block<F: Field>(block: Block<F>) -> Result<(), Vec<VerifyFailure>> {
    test_copy_circuit::<F>(
        block.copy_events,
        block.circuits_params.max_copy_rows,
        ExternalData {
            max_txs: block.circuits_params.max_txs,
            max_calldata: block.circuits_params.max_calldata,
            txs: block.txs,
            max_rws: block.circuits_params.max_rws,
            rws: block.rws,
            bytecodes: block.bytecodes,
        },
    )
}

fn gen_calldatacopy_data() -> CircuitInputBuilder {
    let length = 512 / 2 - 32;
    let code = bytecode! {
        PUSH32(Word::from(length))
        PUSH32(Word::from(0x00))
        PUSH32(Word::from(0x00))
        CALLDATACOPY
        STOP
    };
    let calldata = rand_bytes(length);
    let test_ctx = TestContext::<2, 1>::new(
        None,
        account_0_code_account_1_no_code(code),
        |mut txs, accs| {
            txs[0]
                .from(accs[1].address)
                .to(accs[0].address)
                .input(calldata.into());
        },
        |block, _txs| block.number(0xcafeu64),
    )
    .unwrap();
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data_with_params(
        block.clone(),
        CircuitsParams {
            max_rws: 512,
            max_copy_rows: 512,
            max_calldata: 512,
            ..Default::default()
        },
    )
    .new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    builder
}

fn gen_codecopy_data() -> CircuitInputBuilder {
    let code = bytecode! {
        PUSH32(Word::from(0x20))
        PUSH32(Word::from(0x00))
        PUSH32(Word::from(0x00))
        CODECOPY
        STOP
    };
    let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    builder
}

fn gen_returndatacopy_data() -> CircuitInputBuilder {
    let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

    let pushdata = (0..32).collect::<Vec<u8>>();
    let code_b = bytecode! {
        PUSH32(Word::from_big_endian(&pushdata))
        PUSH32(0x0)
        MSTORE

        PUSH32(0x10)
        PUSH32(0x0)
        RETURN
        STOP
    };

    let memdata = (0..32).rev().collect::<Vec<u8>>();
    let code_a = bytecode! {
        PUSH32(Word::from_big_endian(&memdata))
        PUSH32(0x20)
        MSTORE

        PUSH32(0x10) // retLength
        PUSH32(0x0) // retOffset
        PUSH1(0x00) // argsLength
        PUSH1(0x00) // argsOffset
        PUSH1(0x00) // value
        PUSH32(addr_b.to_word()) // addr
        PUSH32(0x1_0000) // gas
        CALL
        PUSH32(0x10) // size
        PUSH32(0x0) // offset
        PUSH32(0x20) // dest_offset
        RETURNDATACOPY
        STOP
    };

    let test_ctx = TestContext::<3, 1>::new(
        None,
        |accs| {
            accs[0].address(addr_a).code(code_a);
            accs[1].address(addr_b).code(code_b);
            accs[2]
                .address(mock::MOCK_ACCOUNTS[2])
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
        },
        |block, _tx| block,
    )
    .unwrap();

    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data_with_params(
        block.clone(),
        CircuitsParams {
            max_rws: 512,
            max_copy_rows: 512,
            max_calldata: 512,
            ..Default::default()
        },
    )
    .new_circuit_input_builder();

    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    builder
}

fn gen_extcodecopy_data() -> CircuitInputBuilder {
    let external_address = MOCK_ACCOUNTS[0];
    let code = bytecode! {
        PUSH1(0x30usize)
        PUSH1(0x0usize)
        PUSH1(0x0usize)
        PUSH20(external_address.to_word())
        EXTCODECOPY
        STOP
    };
    let code_ext = rand_bytes(0x0fffusize);
    let test_ctx = TestContext::<3, 1>::new(
        None,
        |accs| {
            accs[0].address(MOCK_ACCOUNTS[1]).code(code.clone());

            accs[1].address(external_address).code(code_ext.clone());

            accs[2]
                .address(MOCK_ACCOUNTS[2])
                .balance(Word::from(1u64 << 20));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap();
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    builder
}

fn gen_sha3_data() -> CircuitInputBuilder {
    let (code, _) = gen_sha3_code(0x20, 512 - 32, MemoryKind::EqualToSize);
    let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data_with_params(
        block.clone(),
        CircuitsParams {
            max_rws: 1024,
            max_copy_rows: 1024,
            ..Default::default()
        },
    )
    .new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    builder
}

fn gen_tx_log_data() -> CircuitInputBuilder {
    let code = bytecode! {
        PUSH32(200)         // value
        PUSH32(0)           // offset
        MSTORE
        PUSH32(Word::MAX)   // topic
        PUSH1(32)           // length
        PUSH1(0x20)         // offset
        LOG0
        STOP
    };
    let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    builder
}

fn gen_access_list_data() -> CircuitInputBuilder {
    let test_access_list = AccessList(vec![
        AccessListItem {
            address: address!("0x0000000000000000000000000000000000001111"),
            storage_keys: [10, 11].map(H256::from_low_u64_be).to_vec(),
        },
        AccessListItem {
            address: address!("0x0000000000000000000000000000000000002222"),
            storage_keys: [20, 22].map(H256::from_low_u64_be).to_vec(),
        },
        AccessListItem {
            address: address!("0x0000000000000000000000000000000000003333"),
            storage_keys: [30, 33].map(H256::from_low_u64_be).to_vec(),
        },
    ]);
    let test_ctx = TestContext::<1, 1>::new(
        None,
        |accs| {
            accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(20));
        },
        |mut txs, _accs| {
            txs[0]
                .from(MOCK_ACCOUNTS[0])
                .to(MOCK_ACCOUNTS[1])
                .gas_price(gwei(2))
                .gas(Word::from(0x10000))
                .value(eth(2))
                .transaction_type(1) // Set tx type to EIP-2930.
                .access_list(test_access_list);
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap();
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();

    builder
}

fn gen_create_data() -> CircuitInputBuilder {
    let code = bytecode! {
        PUSH21(Word::from("6B6020600060003760206000F3600052600C6014F3"))
        PUSH1(0)
        MSTORE

        PUSH1 (0xef) // salt
        PUSH1 (0x15) // size
        PUSH1 (0xB) // offset
        PUSH1 (0)   // value
        CREATE2
        STOP
    };

    let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    builder
}

fn gen_return_data() -> CircuitInputBuilder {
    let code = bytecode! {
        PUSH21(Word::from("6B6020600060003760206000F3600052600C6014F3"))
        PUSH1(0)
        MSTORE
        PUSH2(0x10)
        PUSH1(0)
        RETURN
    };

    let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    builder
}

#[test]
fn copy_circuit_valid_calldatacopy() {
    let builder = gen_calldatacopy_data();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    assert_eq!(test_copy_circuit_from_block(block), Ok(()));
}

#[test]
fn copy_circuit_valid_codecopy() {
    let builder = gen_codecopy_data();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    assert_eq!(test_copy_circuit_from_block(block), Ok(()));
}

#[test]
fn copy_circuit_valid_returndatacopy() {
    let builder = gen_returndatacopy_data();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    assert_eq!(test_copy_circuit_from_block(block), Ok(()));
}

#[test]
fn copy_circuit_valid_extcodecopy() {
    let builder = gen_extcodecopy_data();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    assert_eq!(test_copy_circuit_from_block(block), Ok(()));
}

#[test]
fn copy_circuit_valid_sha3() {
    let builder = gen_sha3_data();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    assert_eq!(test_copy_circuit_from_block(block), Ok(()));
}

#[test]
fn copy_circuit_valid_tx_log() {
    let builder = gen_tx_log_data();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    assert_eq!(test_copy_circuit_from_block(block), Ok(()));
}

#[test]
fn copy_circuit_valid_access_list() {
    let builder = gen_access_list_data();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    assert_eq!(test_copy_circuit_from_block(block), Ok(()));
}

#[test]
fn copy_circuit_valid_create() {
    let builder = gen_create_data();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    assert_eq!(test_copy_circuit_from_block(block), Ok(()));
}

#[test]
fn copy_circuit_valid_return() {
    let builder = gen_return_data();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    assert_eq!(test_copy_circuit_from_block(block), Ok(()));
}

#[test]
fn copy_circuit_invalid_calldatacopy() {
    let mut builder = gen_calldatacopy_data();

    // modify first byte of first copy event
    builder.block.copy_events[0].copy_bytes.bytes[0].0 =
        builder.block.copy_events[0].copy_bytes.bytes[0]
            .0
            .wrapping_add(1);

    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

    assert_error_matches(
        test_copy_circuit_from_block(block),
        vec!["Memory word lookup", "Tx calldata lookup"],
    );
}

#[test]
fn copy_circuit_invalid_codecopy() {
    let mut builder = gen_codecopy_data();

    // modify first byte of first copy event
    builder.block.copy_events[0].copy_bytes.bytes[0].0 =
        builder.block.copy_events[0].copy_bytes.bytes[0]
            .0
            .wrapping_add(1);

    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

    assert_error_matches(
        test_copy_circuit_from_block(block),
        vec!["Memory word lookup", "Bytecode lookup"],
    );
}

#[test]
fn copy_circuit_invalid_extcodecopy() {
    let mut builder = gen_extcodecopy_data();

    // modify first byte of first copy event
    builder.block.copy_events[0].copy_bytes.bytes[0].0 =
        builder.block.copy_events[0].copy_bytes.bytes[0]
            .0
            .wrapping_add(1);

    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

    assert_error_matches(
        test_copy_circuit_from_block(block),
        vec!["Memory word lookup", "Bytecode lookup"],
    );
}

#[test]
fn copy_circuit_invalid_sha3() {
    let mut builder = gen_sha3_data();

    // modify first byte of first copy event
    builder.block.copy_events[0].copy_bytes.bytes[0].0 =
        builder.block.copy_events[0].copy_bytes.bytes[0]
            .0
            .wrapping_add(1);

    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

    assert_error_matches(
        test_copy_circuit_from_block(block),
        vec!["Memory word lookup"],
    );
}

#[test]
fn copy_circuit_invalid_tx_log() {
    let mut builder = gen_tx_log_data();

    // modify first byte of first copy event
    builder.block.copy_events[0].copy_bytes.bytes[0].0 =
        builder.block.copy_events[0].copy_bytes.bytes[0]
            .0
            .wrapping_add(1);

    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    let result = test_copy_circuit_from_block(block);

    let errors = result.expect_err("result is not an error");
    errors
        .iter()
        .find(|err| matches!(err, VerifyFailure::Lookup { .. }))
        .expect("there should be a lookup error");
}

#[test]
fn copy_circuit_precompile_call() {
    // TODO: as we add support for more precompiles, we should populate those here as well.
    let args = PrecompileCallArgs {
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
    };
    let bytecode = args.with_call_op(OpcodeId::STATICCALL);
    let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap();
    let block: GethData = test_ctx.into();
    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    assert_eq!(test_copy_circuit_from_block(block), Ok(()));
}

#[test]
fn variadic_size_check() {
    let builder = gen_tx_log_data();
    let block1 = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

    let block: GethData = TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b)
        .unwrap()
        .into();
    let mut builder =
        BlockData::new_from_geth_data_with_params(block.clone(), CircuitsParams::default())
            .new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    let block2 = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

    let circuit = CopyCircuit::<Fr>::new(block1.copy_events, block1.circuits_params.max_copy_rows);
    let prover1 = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();

    let circuit = CopyCircuit::<Fr>::new(
        block2.copy_events.clone(),
        block2.circuits_params.max_copy_rows,
    );
    let prover2 = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();

    assert_eq!(prover1.fixed(), prover2.fixed());
    assert_eq!(prover1.permutation(), prover2.permutation());
}

fn assert_error_matches(result: Result<(), Vec<VerifyFailure>>, names: Vec<&str>) {
    let errors = result.expect_err("result is not an error");
    assert_eq!(errors.len(), names.len(), "{errors:?}");
    for i in 0..names.len() {
        match &errors[i] {
            VerifyFailure::Lookup {
                name: lookup_name, ..
            } => {
                assert_eq!(lookup_name, &names[i])
            }
            VerifyFailure::ConstraintNotSatisfied { .. } => panic!(),
            VerifyFailure::CellNotAssigned { .. } => panic!(),
            VerifyFailure::ConstraintPoisoned { .. } => panic!(),
            VerifyFailure::Permutation { .. } => panic!(),
            // &VerifyFailure::InstanceCellNotAssigned { .. } | &VerifyFailure::Shuffle { .. } => {
            //     todo!()
            // }
        }
    }
}
