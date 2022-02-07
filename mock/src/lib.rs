//! Mock types and functions to generate GethData used for tests

use eth_types::bytecode::Bytecode;
use eth_types::evm_types::Gas;
use eth_types::geth_types::{Account, BlockConstants, GethData, Transaction};
use eth_types::{
    address, Address, Block, Bytes, ChainConstants, Error, GethExecStep, GethExecTrace, Hash, Word,
    U64,
};
use lazy_static::lazy_static;

/// Mock chain ID
const MOCK_CHAIN_ID: u64 = 1338;

lazy_static! {
    /// Mock coinbase value
    static ref MOCK_COINBASE: Address =
        address!("0x00000000000000000000000000000000c014ba5e");
}

/// Create a new block with a single tx that executes the code found in the
/// account with address 0x0 (which can call code in the other accounts),
/// with the given gas limit.
/// The trace will be generated automatically with the external_tracer
/// from the accounts code.
pub fn new_single_tx_trace_accounts_gas(
    accounts: Vec<Account>,
    gas: Gas,
) -> Result<GethData, Error> {
    let eth_block = new_block();
    let mut eth_tx = new_tx(&eth_block);
    eth_tx.gas = Word::from(gas.0);
    let c_constant = new_chain_constants();
    let b_constant = BlockConstants::from_eth_block(&eth_block, &Word::from(c_constant.chain_id));
    let tracer_tx = Transaction::from_eth_tx(&eth_tx);
    let geth_trace = GethExecTrace {
        gas: Gas(eth_tx.gas.as_u64()),
        failed: false,
        struct_logs: external_tracer::trace(&b_constant, &tracer_tx, &accounts)?.to_vec(),
    };

    Ok(GethData {
        eth_block,
        eth_tx,
        c_constant,
        b_constant,
        geth_trace,
        accounts,
    })
}

/// Create a new block with a single tx that executes the code found in the
/// account with address 0x0 (which can call code in the other accounts).
/// The trace will be generated automatically with the external_tracer
/// from the accounts code.
pub fn new_single_tx_trace_accounts(accounts: Vec<Account>) -> Result<GethData, Error> {
    new_single_tx_trace_accounts_gas(accounts, Gas(1_000_000u64))
}

/// Create a new block with a single tx that executes the code passed by
/// argument.  The trace will be generated automatically with the
/// external_tracer from the code.
pub fn new_single_tx_trace_code(code: &Bytecode) -> Result<GethData, Error> {
    let tracer_account = new_tracer_account(code);
    new_single_tx_trace_accounts(vec![tracer_account])
}

/// Create a new block with a single tx with the given gas limit that
/// executes the code passed by argument.  The trace will be generated
/// automatically with the external_tracer from the code.
pub fn new_single_tx_trace_code_gas(code: &Bytecode, gas: Gas) -> Result<GethData, Error> {
    let tracer_account = new_tracer_account(code);
    new_single_tx_trace_accounts_gas(vec![tracer_account], gas)
}

/// Create a new block with a single tx that executes the code_a passed by
/// argument, with code_b deployed at address 0x123.  The trace will be
/// generated automatically with the external_tracer from the code.
pub fn new_single_tx_trace_code_2(code_a: &Bytecode, code_b: &Bytecode) -> Result<GethData, Error> {
    let tracer_account_a = new_tracer_account(code_a);
    let mut tracer_account_b = new_tracer_account(code_b);
    tracer_account_b.address = address!("0x0000000000000000000000000000000000000123");
    new_single_tx_trace_accounts(vec![tracer_account_a, tracer_account_b])
}

/// Create a new block with a single tx that executes the code passed by
/// argument.  The trace will be generated automatically with the
/// external_tracer from the code.  The trace steps will start at the
/// "start" position as tagged in the code.
pub fn new_single_tx_trace_code_at_start(code: &Bytecode) -> Result<GethData, Error> {
    let mut geth_data = new_single_tx_trace_code(code)?;
    geth_data.geth_trace.struct_logs =
        geth_data.geth_trace.struct_logs[code.get_pos("start")..].to_vec();
    Ok(geth_data)
}

/// Create a new block with a single tx that leads to the geth_steps passed
/// by argument.
pub fn new_single_tx_geth_steps(geth_steps: Vec<GethExecStep>) -> GethData {
    let eth_block = new_block();
    let eth_tx = new_tx(&eth_block);
    let c_constant = new_chain_constants();
    let b_constant = BlockConstants::from_eth_block(&eth_block, &Word::from(c_constant.chain_id));
    let geth_trace = eth_types::GethExecTrace {
        gas: Gas(eth_tx.gas.as_u64()),
        failed: false,
        struct_logs: geth_steps,
    };

    GethData {
        eth_block,
        eth_tx,
        c_constant,
        b_constant,
        geth_trace,
        accounts: vec![],
    }
}

/// Generate a new mock block with preloaded data, useful for tests.
pub fn new_block() -> Block<()> {
    eth_types::Block {
        hash: Some(Hash::zero()),
        parent_hash: Hash::zero(),
        uncles_hash: Hash::zero(),
        author: Address::zero(),
        state_root: Hash::zero(),
        transactions_root: Hash::zero(),
        receipts_root: Hash::zero(),
        number: Some(U64([123456u64])),
        gas_used: Word::from(15_000_000u64),
        gas_limit: Word::from(15_000_000u64),
        base_fee_per_gas: Some(Word::from(97u64)),
        extra_data: Bytes::default(),
        logs_bloom: None,
        timestamp: Word::from(1633398551u64),
        difficulty: Word::from(0x200000u64),
        total_difficulty: None,
        seal_fields: Vec::new(),
        uncles: Vec::new(),
        transactions: Vec::new(),
        size: None,
        mix_hash: None,
        nonce: Some(U64::zero()),
    }
}

/// Generate a new mock transaction with preloaded data, useful for tests.
pub fn new_tx<TX>(block: &Block<TX>) -> eth_types::Transaction {
    eth_types::Transaction {
        hash: Hash::zero(),
        nonce: Word::zero(),
        block_hash: block.hash,
        block_number: block.number,
        transaction_index: Some(U64::zero()),
        from: *MOCK_COINBASE,
        to: Some(Address::zero()),
        value: Word::zero(),
        gas_price: Some(Word::zero()),
        gas: Word::from(1_000_000u64),
        input: Bytes::default(),
        v: U64::zero(),
        r: Word::zero(),
        s: Word::zero(),
        transaction_type: Some(U64::zero()),
        access_list: None,
        max_priority_fee_per_gas: Some(Word::zero()),
        max_fee_per_gas: Some(Word::zero()),
        chain_id: Some(Word::from(MOCK_CHAIN_ID)),
    }
}

/// Generate a new mock chain constants, useful for tests.
fn new_chain_constants() -> eth_types::ChainConstants {
    ChainConstants {
        chain_id: MOCK_CHAIN_ID,
    }
}

/// Generate a new mock tracer Account with preloaded data, useful for tests.
fn new_tracer_account(code: &Bytecode) -> Account {
    Account {
        address: new_tracer_tx().target,
        balance: Word::from(555u64),
        code: Bytes::from(code.to_vec()),
    }
}

/// Generate a new mock tracer Transaction with preloaded data, useful for
/// tests.
pub fn new_tracer_tx() -> Transaction {
    Transaction {
        origin: *MOCK_COINBASE,
        gas_limit: Word::from(1_000_000u64),
        target: Address::zero(),
    }
}
