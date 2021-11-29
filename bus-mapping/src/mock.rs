//! Mock types and functions to generate mock data useful for tests
use crate::address;
use crate::bytecode::Bytecode;
use crate::eth_types::{self, Address, Bytes, Hash, Word, U64};
use crate::evm::Gas;
use crate::external_tracer;
use crate::BlockConstants;
use crate::Error;

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
        from: address!("0x00000000000000000000000000000000c014ba5e"),
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
        chain_id: Some(Word::zero()),
    }
}

/// BlockData is a type that contains all the information from a block required
/// to build the circuit inputs.
#[derive(Debug)]
pub struct BlockData {
    /// Block from geth
    pub eth_block: eth_types::Block<()>,
    /// Transaction from geth
    pub eth_tx: eth_types::Transaction,
    /// Block Constants
    pub block_ctants: BlockConstants,
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
        let block_ctants = BlockConstants::from_eth_block(
            &eth_block,
            &eth_types::Word::one(),
            &address!("0x00000000000000000000000000000000c014ba5e"),
        );
        let tracer_tx = external_tracer::Transaction::from_eth_tx(&eth_tx);
        let geth_trace = eth_types::GethExecTrace {
            gas: Gas(eth_tx.gas.as_u64()),
            failed: false,
            struct_logs: external_tracer::trace(
                &block_ctants,
                &tracer_tx,
                accounts,
            )?
            .to_vec(),
        };
        Ok(Self {
            eth_block,
            eth_tx,
            block_ctants,
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
    /// by argument.
    pub fn new_single_tx_geth_steps(
        geth_steps: Vec<eth_types::GethExecStep>,
    ) -> Self {
        let eth_block = new_block();
        let eth_tx = new_tx(&eth_block);
        let block_ctants = BlockConstants::from_eth_block(
            &eth_block,
            &eth_types::Word::one(),
            &crate::address!("0x00000000000000000000000000000000c014ba5e"),
        );
        let geth_trace = eth_types::GethExecTrace {
            gas: Gas(eth_tx.gas.as_u64()),
            failed: false,
            struct_logs: geth_steps,
        };
        Self {
            eth_block,
            eth_tx,
            block_ctants,
            geth_trace,
        }
    }
}

/// Generate a new mock tracer Transaction with preloaded data, useful for
/// tests.
pub fn new_tracer_tx() -> external_tracer::Transaction {
    external_tracer::Transaction {
        origin: address!("0x00000000000000000000000000000000c014ba5e"),
        gas_limit: Word::from(1_000_000u64),
        target: Address::zero(),
    }
}

/// Generate a new mock tracer Account with preloaded data, useful for tests.
pub fn new_tracer_account(code: &Bytecode) -> external_tracer::Account {
    external_tracer::Account {
        address: new_tracer_tx().target,
        balance: Word::from(555u64),
        code: hex::encode(code.to_bytes()),
    }
}
