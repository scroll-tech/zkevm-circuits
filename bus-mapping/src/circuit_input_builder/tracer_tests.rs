use super::*;
use crate::circuit_input_builder::access::gen_state_access_trace;
use crate::error::{ExecError, OogError};
use crate::geth_errors::{
    GETH_ERR_GAS_UINT_OVERFLOW, GETH_ERR_OUT_OF_GAS, GETH_ERR_STACK_OVERFLOW,
    GETH_ERR_STACK_UNDERFLOW,
};
use crate::operation::RWCounter;
use crate::state_db::Account;
use eth_types::evm_types::{stack::Stack, Gas, OpcodeId};
use eth_types::{
    address, bytecode, geth_types::GethData, word, Bytecode, Hash, ToAddress, ToWord, Word,
};
use lazy_static::lazy_static;
use mock::test_ctx::{helpers::*, LoggerConfig, TestContext};
use mock::MOCK_COINBASE;
use pretty_assertions::assert_eq;
use std::collections::HashSet;

// Helper struct that contains a CircuitInputBuilder, a particuar tx and a
// particular execution step so that we can easily get a
// CircuitInputStateRef to have a context in order to get the error at a
// given step.
struct CircuitInputBuilderTx {
    builder: CircuitInputBuilder,
    tx: Transaction,
    pub(crate) tx_ctx: TransactionContext,
    step: ExecStep,
}

impl CircuitInputBuilderTx {
    fn new(geth_data: &GethData, geth_step: &GethExecStep) -> Self {
        let block = crate::mock::BlockData::new_from_geth_data(geth_data.clone());
        let mut builder = block.new_circuit_input_builder();
        let tx = builder
            .new_tx(&block.eth_block.transactions[0], true)
            .unwrap();
        let tx_ctx = TransactionContext::new(
            &block.eth_block.transactions[0],
            &GethExecTrace {
                gas: Gas(0),
                failed: false,
                return_value: "".to_owned(),
                struct_logs: vec![geth_step.clone()],
            },
            false,
        )
        .unwrap();

        let prev_log_id = if tx.is_steps_empty() {
            0
        } else {
            tx.last_step().log_id
        };

        let call_ctx = tx_ctx.call_ctx().unwrap();
        let exec_step = ExecStep::new(geth_step, call_ctx, RWCounter::new(), 0, prev_log_id);
        Self {
            builder,
            tx,
            tx_ctx,
            step: exec_step,
        }
    }

    fn state_ref(&mut self) -> CircuitInputStateRef {
        self.builder.state_ref(&mut self.tx, &mut self.tx_ctx)
    }
}

lazy_static! {
    static ref ADDR_A: Address = Address::zero();
    static ref WORD_ADDR_A: Word = ADDR_A.to_word();
    static ref ADDR_B: Address = address!("0x0000000000000000000000000000000000000123");
    static ref WORD_ADDR_B: Word = ADDR_B.to_word();
}

fn mock_internal_create() -> Call {
    Call {
        call_id: 0,
        caller_id: 0,
        last_callee_id: 0,
        kind: CallKind::Create,
        is_static: false,
        is_root: false,
        is_persistent: false,
        is_success: false,
        rw_counter_end_of_reversion: 0,
        caller_address: *ADDR_A,
        address: *ADDR_B,
        code_source: CodeSource::Memory,
        code_hash: Hash::zero(),
        depth: 2,
        value: Word::zero(),
        call_data_offset: 0,
        call_data_length: 0,
        return_data_offset: 0,
        return_data_length: 0,
        last_callee_return_data_offset: 0,
        last_callee_return_data_length: 0,
    }
}

//
// Geth Errors ignored
//
// These errors happen in a CALL, CALLCODE, DELEGATECALL or STATICCALL, and
// are used internally but not propagated in geth to the scope where the
// tracer is used.

fn check_err_depth(step: &GethExecStep, next_step: Option<&GethExecStep>) -> bool {
    matches!(
        step.op,
        OpcodeId::CALL
            | OpcodeId::CALLCODE
            | OpcodeId::DELEGATECALL
            | OpcodeId::STATICCALL
            | OpcodeId::CREATE
            | OpcodeId::CREATE2
    ) && step.error.is_none()
        && result(next_step).is_zero()
        && step.depth == 1025
}

#[test]
fn tracer_err_depth() {
    // Recursive CALL will exaust the call depth
    let code = bytecode! {
             PUSH1(0x0) // retLength
             PUSH1(0x0) // retOffset
             PUSH1(0x0) // argsLength
             PUSH1(0x0) // argsOffset
             PUSH1(0x42) // value
             PUSH32(*WORD_ADDR_A) // addr
             PUSH32(0x8_0000_0000_0000_u64) // gas
             CALL
             PUSH2(0xab)
             STOP
    };

    // Create a custom tx setting Gas to
    let block: GethData = TestContext::<2, 1>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(*ADDR_A)
                .balance(Word::from(1u64 << 20))
                .code(code);
            accs[1]
                .address(address!("0x0000000000000000000000000000000000000010"))
                .balance(Word::from(10u64.pow(19)));
        },
        |mut txs, accs| {
            txs[0]
                .to(accs[0].address)
                .from(accs[1].address)
                .gas(Word::from(10u64.pow(15)));
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let struct_logs = &block.geth_traces[0].struct_logs;

    // get last CALL
    let (index, step) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| s.op == OpcodeId::CALL)
        .unwrap();
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert_eq!(step.op, OpcodeId::CALL);
    assert_eq!(step.depth, 1025u16);
    assert_eq!(step.error, None);
    // Some sanity checks
    assert_eq!(struct_logs[index + 1].op, OpcodeId::PUSH2);
    assert_eq!(struct_logs[index + 1].depth, 1025u16);
    assert_eq!(struct_logs[index + 1].stack, Stack(vec![Word::zero()])); // success = 0
    assert_eq!(struct_logs[index + 2].op, OpcodeId::STOP);
    assert_eq!(struct_logs[index + 2].depth, 1025u16);

    assert!(check_err_depth(step, next_step));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::Depth)
    );
}

#[test]
fn tracer_err_insufficient_balance() {
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH32(Word::from(0x1000)) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };
    let code_b = bytecode! {
        PUSH1(0x01) // value
        PUSH1(0x02) // key
        SSTORE

        PUSH3(0xbb)
    };

    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1]
                .address(address!("0x000000000000000000000000000000000cafe001"))
                .code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    // get last CALL
    let (index, step) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| s.op == OpcodeId::CALL)
        .unwrap();
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert_eq!(step.error, None);
    assert_eq!(next_step.unwrap().op, OpcodeId::PUSH2);
    assert_eq!(next_step.unwrap().stack, Stack(vec![Word::zero()])); // failure = 0

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::InsufficientBalance)
    );
}

#[test]
fn tracer_call_success() {
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH32(Word::from(0x1000)) // value
        PUSH32(Word::from(0x000000000000000000000000000000000cafe001)) // addr
        PUSH32(0x1_0000) // gas
        CALL
        PUSH2(0xaa)
    };
    let code_b = bytecode! {
        STOP
    };

    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 1>::new(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a)
                .balance(Word::from(10000u64));
            accs[1]
                .address(address!("0x000000000000000000000000000000000cafe001"))
                .code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .into();

    // get last CALL
    let (index, step) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| s.op == OpcodeId::CALL)
        .unwrap();
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert_eq!(step.error, None);
    assert_eq!(next_step.unwrap().op, OpcodeId::STOP);
    assert_eq!(next_step.unwrap().stack, Stack(vec![]));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    let error = builder.state_ref().get_step_err(step, next_step);
    // expects no errors detected
    assert_eq!(error.unwrap(), None);
}

#[test]
fn tracer_err_address_collision() {
    // We do CREATE2 twice with the same parameters, with a code_creater
    // that outputs the same, which will lead to the same new
    // contract address.
    let code_creator = bytecode! {
        PUSH1(0x00) // value
        PUSH1(0x00) // offset
        MSTORE
        PUSH1(0x01) // length
        PUSH1(0x00) // offset
        RETURN
    };

    // code_a calls code_b which executes code_creator in CREATE2
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };

    let mut code_b = Bytecode::default();
    // pad code_creator to multiple of 32 bytes
    let len = code_creator.to_vec().len();
    let code_creator: Vec<u8> = code_creator
        .to_vec()
        .iter()
        .cloned()
        .chain(0u8..((32 - len % 32) as u8))
        .collect();
    for (index, word) in code_creator.chunks(32).enumerate() {
        code_b.push(32, Word::from_big_endian(word));
        code_b.push(32, Word::from(index * 32));
        code_b.write_op(OpcodeId::MSTORE);
    }
    let code_b_end = bytecode! {
        PUSH3(0x123456) // salt
        PUSH1(len) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // value
        CREATE2

        PUSH3(0x123456) // salt
        PUSH1(len) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // value
        CREATE2

        PUSH3(0xbb)
    };
    code_b.append(&code_b_end);
    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    // get last CREATE2
    let (index, step) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| s.op == OpcodeId::CREATE2)
        .unwrap();
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    let memory = next_step.unwrap().memory.clone();

    let create2_address: Address = {
        // get first RETURN
        let (index, _) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .find(|(_, s)| s.op == OpcodeId::RETURN)
            .unwrap();
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        let addr_word = next_step.unwrap().stack.last().unwrap();
        addr_word.to_address()
    };

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    // Set up call context at CREATE2
    builder.tx_ctx.call_is_success.push(false);
    builder.state_ref().push_call(mock_internal_create());
    builder.state_ref().call_ctx_mut().unwrap().memory = memory;
    // Set up account and contract that exist during the second CREATE2
    builder.builder.sdb.set_account(
        &ADDR_B,
        Account {
            nonce: Word::zero(),
            balance: Word::from(555u64), /* same value as in
                                          * `mock::new_tracer_account` */
            storage: HashMap::new(),
            code_hash: Hash::zero(),
        },
    );
    builder.builder.sdb.set_account(
        &create2_address,
        Account {
            nonce: Word::zero(),
            balance: Word::zero(),
            storage: HashMap::new(),
            code_hash: Hash::zero(),
        },
    );
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::ContractAddressCollision)
    );
}

fn check_err_code_store_out_of_gas(step: &GethExecStep, next_step: Option<&GethExecStep>) -> bool {
    let length = step.stack.nth_last(1).unwrap();
    step.op == OpcodeId::RETURN
        && step.error.is_none()
        && result(next_step).is_zero()
        && Word::from(200) * length > Word::from(step.gas.0)
}

#[test]
fn tracer_err_code_store_out_of_gas() {
    // code_creator outputs an empty array of length 0x100, which will
    // exhaust the gas to store the code.
    let code_len = 0x100;
    let code_creator = bytecode! {
        PUSH1(Word::zero()) // value
        PUSH32(code_len) // offset
        MSTORE
        PUSH32(code_len) // length
        PUSH1(0x00) // offset
        RETURN
    };

    // code_a calls code_b which executes code_creator in CREATE
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };

    let mut code_b = Bytecode::default();
    // pad code_creator to multiple of 32 bytes
    let len = code_creator.to_vec().len();
    let code_creator: Vec<u8> = code_creator
        .to_vec()
        .iter()
        .cloned()
        .chain(0..(32 - len % 32) as u8)
        .collect();
    for (index, word) in code_creator.chunks(32).enumerate() {
        code_b.push(32, Word::from_big_endian(word));
        code_b.push(32, Word::from(index * 32));
        code_b.write_op(OpcodeId::MSTORE);
    }
    let code_b_end = bytecode! {
        PUSH32(len) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // value
        CREATE

        PUSH3(0xbb)
    };
    code_b.append(&code_b_end);
    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    // get last RETURN
    let (index, step) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| s.op == OpcodeId::RETURN)
        .unwrap();
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert!(check_err_code_store_out_of_gas(step, next_step));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    // Set up call context at CREATE
    builder.tx_ctx.call_is_success.push(false);
    builder.state_ref().push_call(mock_internal_create());
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::CodeStoreOutOfGas)
    );
}

fn check_err_invalid_code(step: &GethExecStep, next_step: Option<&GethExecStep>) -> bool {
    let offset = step.stack.nth_last(0).unwrap();
    let length = step.stack.nth_last(1).unwrap();
    step.op == OpcodeId::RETURN
        && step.error.is_none()
        && result(next_step).is_zero()
        && length > Word::zero()
        && !step.memory.is_empty()
        && step.memory.0.get(offset.low_u64() as usize) == Some(&0xef)
}

#[test]
fn tracer_err_invalid_code() {
    // code_creator outputs byte array that starts with 0xef, which is
    // invalid code.
    let code_creator = bytecode! {
        PUSH32(word!("0xef00000000000000000000000000000000000000000000000000000000000000")) // value
        PUSH1(0x00) // offset
        MSTORE
        PUSH1(0x01) // length
        PUSH1(0x00) // offset
        RETURN
    };

    // code_a calls code_b which executes code_creator in CREATE
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };

    let mut code_b = Bytecode::default();
    // pad code_creator to multiple of 32 bytes
    let len = code_creator.to_vec().len();
    let code_creator: Vec<u8> = code_creator
        .to_vec()
        .iter()
        .cloned()
        .chain(0u8..((32 - len % 32) as u8))
        .collect();
    for (index, word) in code_creator.chunks(32).enumerate() {
        code_b.push(32, Word::from_big_endian(word));
        code_b.push(32, Word::from(index * 32));
        code_b.write_op(OpcodeId::MSTORE);
    }
    let code_b_end = bytecode! {
        PUSH1(len) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // value
        CREATE

        PUSH3(0xbb)
    };
    code_b.append(&code_b_end);
    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    // get last RETURN
    let (index, step) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| s.op == OpcodeId::RETURN)
        .unwrap();
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert!(check_err_invalid_code(step, next_step));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    // Set up call context at RETURN
    builder.tx_ctx.call_is_success.push(false);
    builder.state_ref().push_call(mock_internal_create());
    builder.state_ref().call_ctx_mut().unwrap().memory = step.memory.clone();
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::InvalidCreationCode)
    );
}

fn check_err_max_code_size_exceeded(step: &GethExecStep, next_step: Option<&GethExecStep>) -> bool {
    let length = step.stack.nth_last(1).unwrap();
    step.op == OpcodeId::RETURN
        && step.error.is_none()
        && result(next_step).is_zero()
        && length > Word::from(0x6000)
}

#[test]
fn tracer_err_max_code_size_exceeded() {
    // code_creator outputs an empty array of length 0x6000 + 1, which will
    // trigger the max code size limit.
    let code_len = 0x6000 + 1;
    let code_creator = bytecode! {
        PUSH1(Word::zero()) // value
        PUSH32(code_len) // offset
        MSTORE
        PUSH32(code_len) // length
        PUSH1(0x00) // offset
        RETURN
    };

    // code_a calls code_b which executes code_creator in CREATE
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x10_0000) // gas
        CALL

        PUSH2(0xaa)
    };

    let mut code_b = Bytecode::default();
    // pad code_creator to multiple of 32 bytes
    let len = code_creator.to_vec().len();
    let code_creator: Vec<u8> = code_creator
        .to_vec()
        .iter()
        .cloned()
        .chain(0u8..((32 - len % 32) as u8))
        .collect();
    for (index, word) in code_creator.chunks(32).enumerate() {
        code_b.push(32, Word::from_big_endian(word));
        code_b.push(32, Word::from(index * 32));
        code_b.write_op(OpcodeId::MSTORE);
    }
    let code_b_end = bytecode! {
        PUSH32(len) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // value
        CREATE

        PUSH3(0xbb)
    };
    code_b.append(&code_b_end);
    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    // get last RETURN
    let (index, step) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| s.op == OpcodeId::RETURN)
        .unwrap();
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert!(check_err_max_code_size_exceeded(step, next_step));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    // Set up call context at RETURN
    builder.tx_ctx.call_is_success.push(false);
    builder.state_ref().push_call(mock_internal_create());
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::MaxCodeSizeExceeded)
    );
}

#[test]
fn tracer_create_stop() {
    // code_creator doesn't output anything because it stops.
    let code_creator = bytecode! {
        PUSH32(word!("0xef00000000000000000000000000000000000000000000000000000000000000")) // value
        PUSH1(0x00) // offset
        MSTORE
        PUSH1(0x01) // length
        PUSH1(0x00) // offset
        STOP
    };

    // code_a calls code_b which executes code_creator in CREATE
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };

    let mut code_b = Bytecode::default();
    // pad code_creator to multiple of 32 bytes
    let len = code_creator.to_vec().len();
    let code_creator: Vec<u8> = code_creator
        .to_vec()
        .iter()
        .cloned()
        .chain(0u8..((32 - len % 32) as u8))
        .collect();
    for (index, word) in code_creator.chunks(32).enumerate() {
        code_b.push(32, Word::from_big_endian(word));
        code_b.push(32, Word::from(index * 32));
        code_b.write_op(OpcodeId::MSTORE);
    }
    let code_b_end = bytecode! {
        PUSH1(len) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // value
        CREATE

        PUSH3(0xbb)
    };
    code_b.append(&code_b_end);
    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1]
                .address(address!("0x000000000000000000000000000000000cafe001"))
                .code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    // get first STOP
    let (index, step) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .find(|(_, s)| s.op == OpcodeId::STOP)
        .unwrap();
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    // Set up call context at STOP
    builder.tx_ctx.call_is_success.push(false);
    builder.state_ref().push_call(mock_internal_create());
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        None
    );
}

//
// Geth Errors not reported
//
// These errors are specific to some opcodes and due to the way the tracing
// works, they are never captured, because the trace is made before the
// step is executed, so when these errors happen, the trace step
// contains error = null.

fn result(step: Option<&GethExecStep>) -> Word {
    step.map(|s| s.stack.last().unwrap_or_else(|_| Word::zero()))
        .unwrap_or_else(Word::zero)
}

fn check_err_invalid_jump(step: &GethExecStep, next_step: Option<&GethExecStep>) -> bool {
    let next_depth = next_step.map(|s| s.depth).unwrap_or(0);
    matches!(step.op, OpcodeId::JUMP | OpcodeId::JUMPI)
        && step.error.is_none()
        && result(next_step).is_zero()
        && step.depth != next_depth
}

#[test]
fn tracer_err_invalid_jump() {
    // jump to 0x10 which is outside the code (and also not marked with
    // JUMPDEST)
    let code = bytecode! {
        PUSH1(0x10)
        JUMP
        STOP
    };
    let index = 1; // JUMP
    let block: GethData = TestContext::<2, 1>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000010"))
                .balance(Word::from(1u64 << 20))
                .code(code.clone());
            accs[1]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .balance(Word::from(1u64 << 20));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[1].address);
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    assert_eq!(block.geth_traces[0].struct_logs.len(), 2);
    let step = &block.geth_traces[0].struct_logs[index];
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert!(check_err_invalid_jump(step, next_step));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::InvalidJump)
    );

    // With CALL

    // code_a calls code
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        STATICCALL

        PUSH2(0xaa)
    };
    let index = 8; // JUMP

    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let step = &block.geth_traces[0].struct_logs[index];
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert!(check_err_invalid_jump(step, next_step));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::InvalidJump)
    );
}

fn check_err_execution_reverted(step: &GethExecStep, next_step: Option<&GethExecStep>) -> bool {
    let next_depth = next_step.map(|s| s.depth).unwrap_or(0);
    step.op == OpcodeId::REVERT
        && step.error.is_none()
        && result(next_step).is_zero()
        && step.depth != next_depth
}

#[test]
fn tracer_err_execution_reverted() {
    // Do a REVERT
    let code = bytecode! {
        PUSH1(0x0)
        PUSH2(0x0)
        REVERT
        PUSH3(0x12)
        STOP
    };
    let index = 2; // REVERT
    let block: GethData = TestContext::<2, 1>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000010"))
                .balance(Word::from(1u64 << 20))
                .code(code.clone());
            accs[1]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .balance(Word::from(1u64 << 20));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[1].address);
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    assert_eq!(block.geth_traces[0].struct_logs.len(), 3);
    let step = &block.geth_traces[0].struct_logs[index];
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert!(check_err_execution_reverted(step, next_step));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        None
    );

    // With CALL

    // code_a calls code
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };
    let index = 10; // REVERT

    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let step = &block.geth_traces[0].struct_logs[index];
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert!(check_err_execution_reverted(step, next_step));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        None
    );
}

#[test]
fn tracer_stop() {
    // Do a STOP
    let code = bytecode! {
        PUSH1(0x0)
        PUSH2(0x0)
        STOP
        PUSH3(0x12)
        STOP
    };

    // code_a calls code
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };
    let index = 10; // STOP

    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let step = &block.geth_traces[0].struct_logs[index];
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        None
    );
}

fn check_err_return_data_out_of_bounds(
    step: &GethExecStep,
    next_step: Option<&GethExecStep>,
) -> bool {
    let next_depth = next_step.map(|s| s.depth).unwrap_or(0);
    step.op == OpcodeId::RETURNDATACOPY
        && step.error.is_none()
        && result(next_step).is_zero()
        && step.depth != next_depth
}

#[test]
fn tracer_err_return_data_out_of_bounds() {
    // code_a calls code_b and gets the return data with a length 0x02 but
    // code_b returns data with length 0x01.
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH1(0x02) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // destOffset
        RETURNDATACOPY

        PUSH2(0xaa)
    };
    let code_b = bytecode! {
        PUSH2(0x42) // value
        PUSH2(0x00) // offset
        MSTORE
        PUSH1(0x01) // length
        PUSH1(0x00) // offset
        RETURN
    };
    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    // get last RETURNDATACOPY
    let (index, step) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| s.op == OpcodeId::RETURNDATACOPY)
        .unwrap();
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert!(check_err_return_data_out_of_bounds(step, next_step));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::ReturnDataOutOfBounds)
    );
}

//
// Geth Errors Reported
//
// These errors can be found in the trace step error field.

#[test]
fn tracer_err_gas_uint_overflow() {
    // MSTORE a value at an offset so high that the gast cost is big enough
    // to overflow an uint64
    let code = bytecode! {
        PUSH32(0x42) // value
        PUSH32(0x100_0000_0000_0000_0000_u128) // offset
        MSTORE
    };
    let block: GethData = TestContext::<2, 1>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000010"))
                .balance(Word::from(1u64 << 20))
                .code(code);
            accs[1]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .balance(Word::from(1u64 << 20));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[1].address);
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let index = 2; // MSTORE
    let step = &block.geth_traces[0].struct_logs[index];
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert_eq!(step.op, OpcodeId::MSTORE);
    assert_eq!(step.error, Some(GETH_ERR_GAS_UINT_OVERFLOW.to_string()));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::OutOfGas(OogError::StaticMemoryExpansion))
    );
}

#[test]
fn tracer_err_invalid_opcode() {
    // The second opcode is invalid (0x0f)
    let mut code = bytecode::Bytecode::default();
    code.write_op(OpcodeId::PC);
    code.write(0x0f, true);
    let block: GethData = TestContext::<2, 1>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000010"))
                .balance(Word::from(1u64 << 20))
                .code(code);
            accs[1]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .balance(Word::from(1u64 << 20));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[1].address);
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let index = block.geth_traces[0].struct_logs.len() - 1; // 0x0f
    let step = &block.geth_traces[0].struct_logs[index];
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert_eq!(step.op, OpcodeId::INVALID(0x0f));

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::InvalidOpcode)
    );
}

#[test]
fn test_tracer_err_write_protection() {
    // test write_protection error happens in sstore
    tracer_err_write_protection(false);
    // test write_protection error happens in call
    tracer_err_write_protection(true);
}

// this helper generates write_protection error for sstore by default, if
// is_call, for call opcode.
fn tracer_err_write_protection(is_call: bool) {
    // code_a calls code_b via static call, which tries to SSTORE and fails.
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        STATICCALL

        PUSH2(0xaa)
    };
    let mut code_b = bytecode! {
        PUSH1(0x01) // value
        PUSH1(0x02) // key
    };
    if is_call {
        code_b.push(1, Word::zero());
        code_b.push(1, Word::from(0x20));
        code_b.push(1, Word::from(0x10)); // value
        code_b.push(32, *WORD_ADDR_B); //addr
        code_b.push(32, Word::from(0x1000)); // gas
        code_b.write_op(OpcodeId::CALL);
    } else {
        code_b.write_op(OpcodeId::SSTORE);
    }
    code_b.push(2, Word::from(0xbb));

    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let index = if is_call { 14 } else { 9 };
    let step = &block.geth_traces[0].struct_logs[index];
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    let opcode = if is_call {
        OpcodeId::CALL
    } else {
        OpcodeId::SSTORE
    };
    assert_eq!(step.op, opcode);

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    builder.tx_ctx.call_is_success.push(false);
    builder.state_ref().push_call(Call {
        call_id: 0,
        caller_id: 0,
        last_callee_id: 0,
        kind: CallKind::StaticCall,
        is_static: true,
        is_root: false,
        is_persistent: false,
        is_success: false,
        rw_counter_end_of_reversion: 0,
        caller_address: *ADDR_A,
        address: *ADDR_B,
        code_source: CodeSource::Address(*ADDR_B),
        code_hash: Hash::zero(),
        depth: 2,
        value: Word::zero(),
        call_data_offset: 0,
        call_data_length: 0,
        return_data_offset: 0,
        return_data_length: 0,
        last_callee_return_data_offset: 0,
        last_callee_return_data_length: 0,
    });

    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::WriteProtection)
    );
}

#[test]
fn tracer_err_out_of_gas() {
    // Do 3 PUSH1 with gas = 4, which causes out of gas
    let code = bytecode! {
        PUSH1(0x0)
        PUSH1(0x1)
        PUSH1(0x2)
    };
    // Create a custom tx setting Gas to
    let block: GethData = TestContext::<2, 1>::new_with_logger_config(
        None,
        account_0_code_account_1_no_code(code),
        |mut txs, accs| {
            txs[0]
                .to(accs[0].address)
                .from(accs[1].address)
                .gas(Word::from(21004u64));
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();
    let struct_logs = &block.geth_traces[0].struct_logs;

    assert_eq!(struct_logs[1].error, Some(GETH_ERR_OUT_OF_GAS.to_string()));
}

#[test]
fn tracer_err_stack_overflow() {
    // PUSH2 1025 times, causing a stack overflow
    let mut code = bytecode::Bytecode::default();
    for i in 0u64..1025 {
        code.push(2, Word::from(i));
    }
    let block: GethData = TestContext::<2, 1>::new_with_logger_config(
        None,
        account_0_code_account_1_no_code(code),
        tx_from_1_to_0,
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let index = block.geth_traces[0].struct_logs.len() - 1; // PUSH2
    let step = &block.geth_traces[0].struct_logs[index];
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert_eq!(
        step.error,
        Some(format!("{} 1024 (1023)", GETH_ERR_STACK_OVERFLOW))
    );

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::StackOverflow)
    );
}

#[test]
fn tracer_err_stack_underflow() {
    // SWAP5 with an empty stack, which causes a stack underflow
    let code = bytecode! {
        SWAP5
    };
    let block: GethData = TestContext::<2, 1>::new_with_logger_config(
        None,
        account_0_code_account_1_no_code(code),
        tx_from_1_to_0,
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let index = 0; // SWAP5
    let step = &block.geth_traces[0].struct_logs[index];
    let next_step = block.geth_traces[0].struct_logs.get(index + 1);
    assert_eq!(
        step.error,
        Some(format!("{} (0 <=> 6)", GETH_ERR_STACK_UNDERFLOW))
    );

    let mut builder = CircuitInputBuilderTx::new(&block, step);
    assert_eq!(
        builder.state_ref().get_step_err(step, next_step).unwrap(),
        Some(ExecError::StackUnderflow)
    );
}

//
// Circuit Input Builder tests
//

#[test]
fn create2_address() {
    // code_creator outputs 0x6050.
    let code_creator = bytecode! {
        PUSH32(word!("0x6050000000000000000000000000000000000000000000000000000000000000")) // value
        PUSH1(0x00) // offset
        MSTORE
        PUSH1(0x02) // length
        PUSH1(0x00) // offset
        RETURN
    };

    // code_a calls code_b which executes code_creator in CREATE
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };

    let mut code_b = Bytecode::default();
    // pad code_creator to multiple of 32 bytes
    let len = code_creator.to_vec().len();
    let code_creator: Vec<u8> = code_creator
        .to_vec()
        .iter()
        .cloned()
        .chain(0u8..((32 - len % 32) as u8))
        .collect();
    for (index, word) in code_creator.chunks(32).enumerate() {
        code_b.push(32, Word::from_big_endian(word));
        code_b.push(32, Word::from(index * 32));
        code_b.write_op(OpcodeId::MSTORE);
    }
    let code_b_end = bytecode! {
        PUSH3(0x123456) // salt
        PUSH1(len) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // value
        CREATE2

        PUSH3(0xbb)
    };
    code_b.append(&code_b_end);
    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    // get RETURN
    let (index_return, _) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .find(|(_, s)| s.op == OpcodeId::RETURN)
        .unwrap();
    let next_step_return = block.geth_traces[0].struct_logs.get(index_return + 1);
    let addr_expect = next_step_return.unwrap().stack.last().unwrap();
    let memory = next_step_return.unwrap().memory.clone();

    // get CREATE2
    let step_create2 = block.geth_traces[0]
        .struct_logs
        .iter()
        .find(|s| s.op == OpcodeId::CREATE2)
        .unwrap();
    let mut builder = CircuitInputBuilderTx::new(&block, step_create2);
    // Set up call context at CREATE2
    builder.tx_ctx.call_is_success.push(false);
    builder.state_ref().push_call(mock_internal_create());
    builder.state_ref().call_ctx_mut().unwrap().memory = memory;
    let addr = builder.state_ref().create2_address(step_create2).unwrap();

    assert_eq!(addr.to_word(), addr_expect);
}

#[test]
fn create_address() {
    // code_creator outputs 0x6050.
    let code_creator = bytecode! {
        PUSH32(word!("0x6050000000000000000000000000000000000000000000000000000000000000")) // value
        PUSH1(0x00) // offset
        MSTORE
        PUSH1(0x02) // length
        PUSH1(0x00) // offset
        RETURN
    };

    // code_a calls code_b which executes code_creator in CREATE
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };

    let mut code_b = Bytecode::default();
    // pad code_creator to multiple of 32 bytes
    let len = code_creator.to_vec().len();
    let code_creator: Vec<u8> = code_creator
        .to_vec()
        .iter()
        .cloned()
        .chain(0u8..((32 - len % 32) as u8))
        .collect();
    for (index, word) in code_creator.chunks(32).enumerate() {
        code_b.push(32, Word::from_big_endian(word));
        code_b.push(32, Word::from(index * 32));
        code_b.write_op(OpcodeId::MSTORE);
    }
    // We do CREATE 2 times to use a nonce != 0 in the second one.
    let code_b_end = bytecode! {
        PUSH1(len) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // value
        CREATE

        PUSH1(len) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // value
        CREATE

        PUSH3(0xbb)
    };
    code_b.append(&code_b_end);
    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code_b);
            accs[2]
                .address(address!("0x000000000000000000000000000000000cafe002"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    // get last RETURN
    let (index_return, _) = block.geth_traces[0]
        .struct_logs
        .iter()
        .enumerate()
        .rev()
        .find(|(_, s)| s.op == OpcodeId::RETURN)
        .unwrap();
    let next_step_return = block.geth_traces[0].struct_logs.get(index_return + 1);
    let addr_expect = next_step_return.unwrap().stack.last().unwrap();

    // get last CREATE
    let step_create = block.geth_traces[0]
        .struct_logs
        .iter()
        .rev()
        .find(|s| s.op == OpcodeId::CREATE)
        .unwrap();
    let mut builder = CircuitInputBuilderTx::new(&block, step_create);
    // Set up call context at CREATE
    builder.tx_ctx.call_is_success.push(false);
    builder.state_ref().push_call(mock_internal_create());
    builder.builder.sdb.set_account(
        &ADDR_B,
        Account {
            nonce: Word::from(1),
            balance: Word::zero(),
            storage: HashMap::new(),
            code_hash: Hash::zero(),
        },
    );
    let addr = builder.state_ref().create_address().unwrap();

    assert_eq!(addr.to_word(), addr_expect);
}

#[test]
fn test_gen_access_trace() {
    use AccessValue::{Account, Code, Storage};
    use RW::{READ, WRITE};
    let ADDR_0 = address!("0x00000000000000000000000000000000c014ba5e");

    // code_a calls code_b via static call, which tries to SSTORE and fails.
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };
    let code_b = bytecode! {
        PUSH32(word!("0x1234567890000000000000000000abcdef000000000000000000112233445566")) // value
        PUSH1(0x01) // offset
        MSTORE
        PUSH1(0x01) // value
        PUSH1(0x02) // key
        SSTORE
        PUSH1(0x03) // key
        SLOAD

        PUSH3(0xbb)
    };

    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .code(code_a);
            accs[1].address(*ADDR_B).code(code_b);
            accs[2].address(ADDR_0).balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let access_trace = gen_state_access_trace(
        &block.eth_block,
        &block.eth_block.transactions[0],
        &block.geth_traces[0],
    )
    .unwrap();

    assert_eq!(
        access_trace,
        vec![
            Access::new(None, WRITE, Account { address: ADDR_0 }),
            Access::new(None, WRITE, Account { address: *ADDR_A }),
            Access::new(None, READ, Code { address: *ADDR_A }),
            Access::new(Some(7), WRITE, Account { address: *ADDR_A }),
            Access::new(Some(7), WRITE, Account { address: *ADDR_B }),
            Access::new(Some(7), READ, Code { address: *ADDR_B }),
            Access::new(
                Some(13),
                WRITE,
                Storage {
                    address: *ADDR_B,
                    key: Word::from(2),
                }
            ),
            Access::new(
                Some(15),
                READ,
                Storage {
                    address: *ADDR_B,
                    key: Word::from(3),
                }
            ),
        ]
    );

    let access_set = AccessSet::from(access_trace);
    assert_eq!(
        access_set,
        AccessSet {
            state: HashMap::from_iter([
                (ADDR_0, HashSet::new()),
                (*ADDR_A, HashSet::new()),
                (*ADDR_B, HashSet::from_iter([Word::from(2), Word::from(3)]))
            ]),
            code: HashSet::from_iter([*ADDR_A, *ADDR_B]),
        }
    )
}

#[test]
fn test_gen_access_trace_call_EOA_no_new_stack_frame() {
    use AccessValue::{Account, Code, Storage};
    use RW::{READ, WRITE};

    // code calls an EOA with not code, so it won't push new stack frame.
    let code = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL
        PUSH1(0x01) // value
        PUSH1(0x02) // key
        SSTORE
        PUSH1(0x03) // key
        SLOAD

        PUSH2(0xaa)
    };

    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<2, 1>::new_with_logger_config(
        None,
        |accs| {
            accs[0].address(*MOCK_COINBASE).code(code);
            accs[1].address(*ADDR_B).balance(Word::from(1u64 << 30));
        },
        tx_from_1_to_0,
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let access_trace = gen_state_access_trace(
        &block.eth_block,
        &block.eth_block.transactions[0],
        &block.geth_traces[0],
    )
    .unwrap();

    assert_eq!(
        access_trace,
        vec![
            Access::new(None, WRITE, Account { address: *ADDR_B }),
            Access::new(
                None,
                WRITE,
                Account {
                    address: *MOCK_COINBASE
                }
            ),
            Access::new(
                None,
                READ,
                Code {
                    address: *MOCK_COINBASE
                }
            ),
            Access::new(
                Some(7),
                WRITE,
                Account {
                    address: *MOCK_COINBASE
                }
            ),
            Access::new(Some(7), WRITE, Account { address: *ADDR_B }),
            Access::new(Some(7), READ, Code { address: *ADDR_B }),
            Access::new(
                Some(10),
                WRITE,
                Storage {
                    address: *MOCK_COINBASE,
                    key: Word::from(2u64),
                }
            ),
            Access::new(
                Some(12),
                READ,
                Storage {
                    address: *MOCK_COINBASE,
                    key: Word::from(3u64),
                }
            ),
        ]
    );

    let access_set = AccessSet::from(access_trace);
    assert_eq!(
        access_set,
        AccessSet {
            state: HashMap::from_iter([
                (
                    *MOCK_COINBASE,
                    HashSet::from_iter([Word::from(2u64), Word::from(3u64)])
                ),
                (*ADDR_B, HashSet::new()),
            ]),
            code: HashSet::from_iter([*ADDR_B, *MOCK_COINBASE]),
        }
    );
}

#[test]
fn test_gen_access_trace_create_push_call_stack() {
    use AccessValue::{Account, Code};
    use RW::{READ, WRITE};

    // revert
    let code_creator = bytecode! {
        PUSH1(0x00) // length
        PUSH1(0x00) // offset
        REVERT
    };

    // code_a calls code_b which executes code_creator in CREATE
    let code_a = bytecode! {
        PUSH1(0x0) // retLength
        PUSH1(0x0) // retOffset
        PUSH1(0x0) // argsLength
        PUSH1(0x0) // argsOffset
        PUSH1(0x0) // value
        PUSH32(*WORD_ADDR_B) // addr
        PUSH32(0x1_0000) // gas
        CALL

        PUSH2(0xaa)
    };

    let mut code_b = Bytecode::default();
    // pad code_creator to multiple of 32 bytes
    let len = code_creator.to_vec().len();
    let code_creator: Vec<u8> = code_creator
        .to_vec()
        .iter()
        .cloned()
        .chain(0u8..((32 - len % 32) as u8))
        .collect();
    for (index, word) in code_creator.chunks(32).enumerate() {
        code_b.push(32, Word::from_big_endian(word));
        code_b.push(32, Word::from(index * 32));
        code_b.write_op(OpcodeId::MSTORE);
    }
    let code_b_end = bytecode! {
        PUSH1(len) // length
        PUSH1(0x00) // offset
        PUSH1(0x00) // value
        CREATE

        PUSH3(0xbb)
    };
    code_b.append(&code_b_end);

    // Get the execution steps from the external tracer
    let block: GethData = TestContext::<3, 2>::new_with_logger_config(
        None,
        |accs| {
            accs[0].address(*MOCK_COINBASE).code(code_a);
            accs[1].address(*ADDR_B).code(code_b);
            accs[2].balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0].to(accs[0].address).from(accs[2].address);
            txs[1]
                .to(accs[1].address)
                .from(accs[2].address)
                .nonce(Word::one());
        },
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    let access_trace = gen_state_access_trace(
        &block.eth_block,
        &block.eth_block.transactions[0],
        &block.geth_traces[0],
    )
    .unwrap();

    assert_eq!(
        access_trace,
        vec![
            Access::new(
                None,
                WRITE,
                Account {
                    address: Address::zero()
                }
            ),
            Access::new(
                None,
                WRITE,
                Account {
                    address: *MOCK_COINBASE
                }
            ),
            Access::new(
                None,
                READ,
                Code {
                    address: *MOCK_COINBASE
                }
            ),
            Access::new(
                Some(7),
                WRITE,
                Account {
                    address: *MOCK_COINBASE
                }
            ),
            Access::new(Some(7), WRITE, Account { address: *ADDR_B }),
            Access::new(Some(7), READ, Code { address: *ADDR_B }),
        ]
    );

    let access_set = AccessSet::from(access_trace);
    assert_eq!(
        access_set,
        AccessSet {
            state: HashMap::from_iter([
                (*MOCK_COINBASE, HashSet::new()),
                (*ADDR_A, HashSet::new()),
                (*ADDR_B, HashSet::new()),
            ]),
            code: HashSet::from_iter([*MOCK_COINBASE, *ADDR_B]),
        }
    )
}
