//! Mock types and functions to generate mock data useful for tests
use crate::bytecode::Bytecode;
use crate::circuit_input_builder::CircuitInputBuilder;
use crate::external_tracer;
use crate::external_tracer::BlockConstants;
use crate::state_db::{self, CodeDB, StateDB};
use crate::Error;
use eth_types::evm_types::Gas;
use eth_types::{
    self, address, Address, Bytes, ChainConstants, Hash, Word, U64,
};
use lazy_static::lazy_static;
use std::collections::HashMap;

/// Mock chain ID
pub const CHAIN_ID: u64 = 1338;

lazy_static! {
    /// Mock coinbase value
    pub static ref COINBASE: Address =
        address!("0x00000000000000000000000000000000c014ba5e");
}

/// Generate a new mock chain constants, useful for tests.
pub fn new_chain_constants() -> eth_types::ChainConstants {
    ChainConstants { chain_id: CHAIN_ID }
}

/// Generate a new mock block with preloaded data, useful for tests.
pub fn new_block() -> eth_types::Block<()> {
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
pub fn new_tx<TX>(block: &eth_types::Block<TX>) -> eth_types::Transaction {
    eth_types::Transaction {
        hash: Hash::zero(),
        nonce: Word::zero(),
        block_hash: block.hash,
        block_number: block.number,
        transaction_index: Some(U64::zero()),
        from: *COINBASE,
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
        chain_id: Some(Word::from(CHAIN_ID)),
    }
}

/// BlockData is a type that contains all the information from a block required
/// to build the circuit inputs.
#[derive(Debug)]
pub struct BlockData {
    /// StateDB
    pub sdb: StateDB,
    /// CodeDB
    pub code_db: CodeDB,
    /// Block from geth
    pub eth_block: eth_types::Block<()>,
    /// Transaction from geth
    pub eth_tx: eth_types::Transaction,
    /// Constants
    pub c_constant: ChainConstants,
    /// Constants
    pub b_constant: BlockConstants,
    /// Execution Trace from geth
    pub geth_trace: eth_types::GethExecTrace,
}

impl BlockData {
    /// Create a new block with a single tx that executes the code found in the
    /// account with address 0x0 (which can call code in the other accounts),
    /// with the given gas limit.
    /// The trace will be generated automatically with the external_tracer
    /// from the accounts code.
    fn new_single_tx_trace_accounts_gas(
        accounts: &[external_tracer::Account],
        gas: Gas,
    ) -> Result<Self, Error> {
        let eth_block = new_block();
        let mut eth_tx = new_tx(&eth_block);
        eth_tx.gas = Word::from(gas.0);
        let c_constant = new_chain_constants();
        let b_constant = BlockConstants::from_eth_block(
            &eth_block,
            &Word::from(c_constant.chain_id),
        );
        let tracer_tx = external_tracer::Transaction::from_eth_tx(&eth_tx);
        let geth_trace = eth_types::GethExecTrace {
            gas: Gas(eth_tx.gas.as_u64()),
            failed: false,
            struct_logs: external_tracer::trace(
                &b_constant,
                &tracer_tx,
                accounts,
            )?
            .to_vec(),
        };
        let mut sdb = StateDB::new();
        let mut code_db = CodeDB::new();
        for account in accounts {
            let code_hash = code_db.insert(account.code.to_vec());
            sdb.set_account(
                &account.address,
                state_db::Account {
                    nonce: Word::zero(),
                    balance: account.balance,
                    storage: HashMap::new(),
                    code_hash,
                },
            );
        }
        Ok(Self {
            sdb,
            code_db,
            eth_block,
            eth_tx,
            c_constant,
            b_constant,
            geth_trace,
        })
    }

    /// Create a new block with a single tx that executes the code found in the
    /// account with address 0x0 (which can call code in the other accounts).
    /// The trace will be generated automatically with the external_tracer
    /// from the accounts code.
    fn new_single_tx_trace_accounts(
        accounts: &[external_tracer::Account],
    ) -> Result<Self, Error> {
        Self::new_single_tx_trace_accounts_gas(accounts, Gas(1_000_000u64))
    }

    /// Create a new block with a single tx that executes the code passed by
    /// argument.  The trace will be generated automatically with the
    /// external_tracer from the code.
    pub fn new_single_tx_trace_code(code: &Bytecode) -> Result<Self, Error> {
        let tracer_account = new_tracer_account(code);
        Self::new_single_tx_trace_accounts(&[tracer_account])
    }

    /// Create a new block with a single tx with the given gas limit that
    /// executes the code passed by argument.  The trace will be generated
    /// automatically with the external_tracer from the code.
    pub fn new_single_tx_trace_code_gas(
        code: &Bytecode,
        gas: Gas,
    ) -> Result<Self, Error> {
        let tracer_account = new_tracer_account(code);
        Self::new_single_tx_trace_accounts_gas(&[tracer_account], gas)
    }

    /// Create a new block with a single tx that executes the code_a passed by
    /// argument, with code_b deployed at address 0x123.  The trace will be
    /// generated automatically with the external_tracer from the code.
    pub fn new_single_tx_trace_code_2(
        code_a: &Bytecode,
        code_b: &Bytecode,
    ) -> Result<Self, Error> {
        let tracer_account_a = new_tracer_account(code_a);
        let mut tracer_account_b = new_tracer_account(code_b);
        tracer_account_b.address =
            address!("0x0000000000000000000000000000000000000123");
        Self::new_single_tx_trace_accounts(&[
            tracer_account_a,
            tracer_account_b,
        ])
    }

    /// Create a new block with a single tx that executes the code passed by
    /// argument.  The trace will be generated automatically with the
    /// external_tracer from the code.  The trace steps will start at the
    /// "start" position as tagged in the code.
    pub fn new_single_tx_trace_code_at_start(
        code: &Bytecode,
    ) -> Result<Self, Error> {
        let mut mock = Self::new_single_tx_trace_code(code)?;
        mock.geth_trace.struct_logs =
            mock.geth_trace.struct_logs[code.get_pos("start")..].to_vec();
        Ok(mock)
    }

    /// Create a new block with a single tx that leads to the geth_steps passed
    /// by argument.  The returned BlockData contains an empty StateDB and
    /// CodeDB.
    pub fn new_single_tx_geth_steps(
        geth_steps: Vec<eth_types::GethExecStep>,
    ) -> Self {
        let eth_block = new_block();
        let eth_tx = new_tx(&eth_block);
        let c_constant = new_chain_constants();
        let b_constant = BlockConstants::from_eth_block(
            &eth_block,
            &Word::from(c_constant.chain_id),
        );
        let geth_trace = eth_types::GethExecTrace {
            gas: Gas(eth_tx.gas.as_u64()),
            failed: false,
            struct_logs: geth_steps,
        };
        let sdb = StateDB::new();
        let code_db = CodeDB::new();
        Self {
            sdb,
            code_db,
            eth_block,
            eth_tx,
            c_constant,
            b_constant,
            geth_trace,
        }
    }

    /// Generate a new CircuitInputBuilder initialized with the context of the
    /// BlockData.
    pub fn new_circuit_input_builder(&self) -> CircuitInputBuilder {
        CircuitInputBuilder::new(
            self.sdb.clone(),
            self.code_db.clone(),
            &self.eth_block,
            self.c_constant.clone(),
            self.b_constant.clone(),
        )
    }
}

/// Generate a new mock tracer Transaction with preloaded data, useful for
/// tests.
pub fn new_tracer_tx() -> external_tracer::Transaction {
    external_tracer::Transaction {
        origin: *COINBASE,
        gas_limit: Word::from(1_000_000u64),
        target: Address::zero(),
    }
}

/// Generate a new mock tracer Account with preloaded data, useful for tests.
pub fn new_tracer_account(code: &Bytecode) -> external_tracer::Account {
    external_tracer::Account {
        address: new_tracer_tx().target,
        balance: Word::from(555u64),
        code: Bytes::from(code.to_vec()),
    }
}
