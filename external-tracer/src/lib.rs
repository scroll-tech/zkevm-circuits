//! This module generates traces by connecting to an external tracer

use eth_types::{
    geth_types::{Account, BlockConstants, Transaction},
    Address, Bytes, Error, GethExecTrace, Hash, ToBigEndian, Word,
};
use serde::Serialize;
use std::collections::HashMap;

/// Configuration structure for `geth_utlis::trace`
#[derive(Debug, Default, Clone)]
pub struct TraceConfig {
    /// chain id
    pub chain_id: Word,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// block constants
    pub block_constants: BlockConstants,
    /// accounts
    pub accounts: HashMap<Address, Account>,
    /// transaction
    pub transactions: Vec<Transaction>,
}

// TraceConfigForSerde is used for converting Word to Hash for storage kvs.
// Without the conversion, Geth will report error: "cannot unmarshal hex string
// of odd length into Go struct field".
#[derive(Debug, Default, Clone, Serialize)]
struct TraceConfigForSerde {
    pub chain_id: Word,
    pub history_hashes: Vec<Word>,
    pub block_constants: BlockConstants,
    pub accounts: HashMap<Address, AccountForSerde>,
    pub transactions: Vec<Transaction>,
}

impl From<TraceConfig> for TraceConfigForSerde {
    fn from(t: TraceConfig) -> Self {
        Self {
            chain_id: t.chain_id,
            history_hashes: t.history_hashes,
            block_constants: t.block_constants,
            accounts: t.accounts.into_iter().map(|(k, v)| (k, v.into())).collect(),
            transactions: t.transactions,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct AccountForSerde {
    pub address: Address,
    pub nonce: Word,
    pub balance: Word,
    pub code: Bytes,
    pub storage: HashMap<Hash, Hash>,
}

impl From<Account> for AccountForSerde {
    fn from(a: Account) -> Self {
        Self {
            address: a.address,
            nonce: a.nonce,
            balance: a.balance,
            code: a.code,
            storage: a
                .storage
                .into_iter()
                .map(|(k, v)| (Hash::from(k.to_be_bytes()), Hash::from(v.to_be_bytes())))
                .collect(),
        }
    }
}

/// Creates a trace for the specified config
pub fn trace(config: &TraceConfig) -> Result<Vec<GethExecTrace>, Error> {
    // Get the trace
    let trace_string = geth_utils::trace(
        &serde_json::to_string(&TraceConfigForSerde::from(config.clone())).unwrap(),
    )
    .map_err(|error| match error {
        geth_utils::Error::TracingError(error) => Error::TracingError(error),
    })?;

    let trace = serde_json::from_str(&trace_string).map_err(Error::SerdeError)?;
    Ok(trace)
}
