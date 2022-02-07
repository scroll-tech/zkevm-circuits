//! Mock types and functions to generate mock data useful for tests

use crate::circuit_input_builder::CircuitInputBuilder;
use crate::state_db::{self, CodeDB, StateDB};
use eth_types::geth_types::{BlockConstants, GethData};
use eth_types::{ChainConstants, Word};
use std::collections::HashMap;

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

    /// Create a new block from the given Geth data.
    pub fn new_from_geth_data(geth_data: GethData) -> Self {
        let mut sdb = StateDB::new();
        let mut code_db = CodeDB::new();
        for account in geth_data.accounts {
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
        Self {
            sdb,
            code_db,
            eth_block: geth_data.eth_block,
            eth_tx: geth_data.eth_tx,
            c_constant: geth_data.c_constant,
            b_constant: geth_data.b_constant,
            geth_trace: geth_data.geth_trace,
        }
    }
}
