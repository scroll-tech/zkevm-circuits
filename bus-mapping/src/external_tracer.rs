//! This module generates traces by connecting to an external tracer
use crate::eth_types::{self, Address, GethExecStep, Word};
use crate::BlockConstants;
use crate::Error;
use geth_utils;
use serde::Serialize;

/// Definition of all of the constants related to an Ethereum transaction.
#[derive(Debug, Clone, Serialize)]
pub struct Transaction {
    /// Origin Address
    pub origin: Address,
    /// Gas Limit
    pub gas_limit: Word,
    /// Target Address
    pub target: Address,
}

impl Transaction {
    /// Create Self from a web3 transaction
    pub fn from_eth_tx(tx: &eth_types::Transaction) -> Self {
        Self {
            origin: tx.from,
            gas_limit: tx.gas,
            target: tx.to.unwrap(),
        }
    }
}

/// Definition of all of the data related to an account.
#[derive(Debug, Clone, Serialize)]
pub struct Account {
    /// Address
    pub address: Address,
    /// Balance
    pub balance: Word,
    /// EVM Code
    pub code: String,
}

#[derive(Debug, Clone, Serialize)]
struct GethConfig {
    block_constants: BlockConstants,
    transaction: Transaction,
    accounts: Vec<Account>,
}

/// Creates a trace for the specified config
pub fn trace(
    block_constants: &BlockConstants,
    tx: &Transaction,
    accounts: &[Account],
) -> Result<Vec<GethExecStep>, Error> {
    let geth_config = GethConfig {
        block_constants: block_constants.clone(),
        transaction: tx.clone(),
        accounts: accounts.to_vec(),
    };

    // Get the trace
    let trace_string =
        geth_utils::trace(&serde_json::to_string(&geth_config).unwrap())
            .map_err(|_| Error::TracingError)?;

    let trace: Vec<GethExecStep> =
        serde_json::from_str(&trace_string).map_err(Error::SerdeError)?;
    Ok(trace)
}
