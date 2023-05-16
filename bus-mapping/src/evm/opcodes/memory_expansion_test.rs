use eth_types::{bytecode, geth_types::GethData, word, Bytecode, GethExecStep};
use mock::{
    test_ctx::{
        helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
        LoggerConfig,
    },
    TestContext,
};

fn might_neg_index(index: isize, len: usize) -> usize {
    if index < 0 {
        (len as isize + index) as usize
    } else {
        index as usize
    }
}

fn assert_expanded(_traces: &[GethExecStep], _before: isize, _after: isize) {
    // FIXME: memory is removed
    // let traces_len = traces.len();
    // let before = might_neg_index(before, traces_len);
    // let after = might_neg_index(after, traces_len);
    // let size_before = traces[before].memory.borrow().len();
    // let size_after = traces[after].memory.borrow().len();
    // assert_ne!(size_before, size_after);
}

fn trace_and_assert<FN>(code: Bytecode, before: isize, after: isize, assert_fn: FN)
where
    FN: Fn(&[GethExecStep], isize, isize),
{
    let block: GethData = TestContext::<2, 1>::new_with_logger_config(
        None,
        account_0_code_account_1_no_code(code),
        tx_from_1_to_0,
        |block, _tx| block.number(0xcafeu64),
        LoggerConfig::enable_memory(),
    )
    .unwrap()
    .into();

    assert_fn(&block.geth_traces[0].struct_logs, before, after);
}

#[test]
fn sha3_test() {
    let code = bytecode! {
        PUSH1(0xffu64)
        PUSH1(0x40u64)
        SHA3
        STOP
    };
    trace_and_assert(code, -2, -1, assert_expanded);
}

#[test]
fn mload_test() {
    let code = bytecode! {
        PUSH1(0xffu64)
        MLOAD
        STOP
    };
    trace_and_assert(code, -2, -1, assert_expanded);
}

#[test]
fn log0_test() {
    let code = bytecode! {
        PUSH1(0xffu64)
        PUSH1(0x40u64)
        LOG0
        STOP
    };
    trace_and_assert(code, -2, -1, assert_expanded);
}

#[test]
fn create_test() {
    let code = bytecode! {
        PUSH21(word!("0x6B6020600060003760006000F3600052600C6014F3"))
        PUSH1(0)
        MSTORE
        PUSH1 (0xff)
        PUSH1 (0xB)
        PUSH1 (0)
        CREATE
        STOP
    };
    trace_and_assert(code, -2, -1, assert_expanded);
}

#[test]
fn call_test() {
    // // deployed contract
    // PUSH1 0x20
    // PUSH1 0
    // PUSH1 0
    // CALLDATACOPY
    // PUSH1 0
    // PUSH1 0
    // RETURN
    //
    // bytecode: 0x6020600060003760006000F3
    //
    // // constructor
    // PUSH12 0x6020600060003760006000F3
    // PUSH1 0
    // MSTORE
    // PUSH1 0xC
    // PUSH1 0x14
    // RETURN
    //
    // bytecode: 0x6B6020600060003760006000F3600052600C6014F3
    let code = bytecode! {
        PUSH21(word!("0x6B6020600060003760006000F3600052600C6014F3"))
        PUSH1(0)
        MSTORE
        PUSH1 (0x15)
        PUSH1 (0xB)
        PUSH1 (0)
        CREATE
        PUSH1 (0x0)
        PUSH1 (0x0)
        PUSH1 (0x20)
        PUSH1 (0xff)
        PUSH1 (0)
        DUP6
        PUSH2 (0xFFFF)
        CALL
        STOP
    };
    trace_and_assert(code, -2, -1, assert_expanded);
}
