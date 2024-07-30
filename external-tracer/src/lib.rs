//! This module generates traces by connecting to an external tracer

#[cfg(feature = "scroll")]
use eth_types::l2_types::BlockTrace;
use eth_types::{
    geth_types::{Account, BlockConstants, Transaction},
    Address, Error, GethExecTrace, Word,
};
use serde::Serialize;
use std::collections::BTreeMap;

/// Configuration structure for `geth_utlis::trace`
#[derive(Debug, Default, Clone, Serialize)]
pub struct TraceConfig {
    /// chain id
    pub chain_id: u64,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the latest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// block constants
    pub block_constants: BlockConstants,
    /// accounts
    pub accounts: BTreeMap<Address, Account>,
    /// transaction
    pub transactions: Vec<Transaction>,
    /// logger config
    pub logger_config: LoggerConfig,
    /// chain config
    pub chain_config: Option<ChainConfig>,
    /// beginning index of l1 queue
    #[cfg(feature = "scroll")]
    pub l1_queue_index: u64,
}

/// Configuration structure for `logger.Config`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct LoggerConfig {
    /// enable memory capture
    pub enable_memory: bool,
    /// disable stack capture
    pub disable_stack: bool,
    /// disable storage capture
    pub disable_storage: bool,
    /// enable return data capture
    pub enable_return_data: bool,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            enable_memory: cfg!(feature = "enable-memory"),
            disable_stack: !cfg!(feature = "enable-stack"),
            disable_storage: !cfg!(feature = "enable-storage"),
            enable_return_data: true,
        }
    }
}

impl LoggerConfig {
    #[cfg(feature = "enable-memory")]
    pub fn enable_memory() -> Self {
        Self {
            enable_memory: true,
            ..Self::default()
        }
    }

    pub fn enable_stack() -> Self {
        Self {
            disable_stack: false,
            ..Self::default()
        }
    }
}

/// Configuration structure for `params.ChainConfig`
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChainConfig {}

#[cfg(not(feature = "scroll"))]
pub fn trace(config: &TraceConfig) -> Result<Vec<GethExecTrace>, Error> {
    let trace_config = &serde_json::to_string_pretty(&config).unwrap();
    log::trace!("trace config: {}", trace_config);
    // Get the trace
    let trace_string = geth_utils::trace(trace_config).map_err(|error| match error {
        geth_utils::Error::TracingError(error) => Error::TracingError(error),
    })?;

    log::trace!("trace: {}", trace_string);

    let mut deserializer = serde_json::Deserializer::from_str(&trace_string);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
    serde::Deserialize::deserialize(deserializer).map_err(Error::SerdeError)
}

/// Creates a l2-trace for the specified config
#[cfg(feature = "scroll")]
pub fn l2trace(config: &TraceConfig) -> Result<BlockTrace, Error> {
    let l2_config = config.clone();
    let trace_config = &serde_json::to_string_pretty(&l2_config).unwrap();
    log::trace!("trace config: {}", trace_config);
    // Get the trace
    let trace_string = geth_utils::trace(trace_config).map_err(|error| match error {
        geth_utils::Error::TracingError(error) => Error::TracingError(error),
    })?;

    log::trace!("trace: {}", trace_string);

    let mut deserializer = serde_json::Deserializer::from_str(&trace_string);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
    serde::Deserialize::deserialize(deserializer).map_err(Error::SerdeError)
}

#[cfg(feature = "scroll")]
pub fn trace(config: &TraceConfig) -> Result<Vec<GethExecTrace>, Error> {
    let block_trace = l2trace(config)?;

    Ok(block_trace
        .execution_results
        .into_iter()
        .map(From::from)
        .collect::<Vec<_>>())
}
