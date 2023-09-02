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
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
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
            enable_memory: false,
            disable_stack: false,
            disable_storage: false,
            enable_return_data: true,
        }
    }
}

impl LoggerConfig {
    pub fn enable_memory() -> Self {
        Self {
            enable_memory: true,
            ..Self::default()
        }
    }
}

/// Configuration structure for `params.ChainConfig`
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChainConfig {
    /// Archimedes switch time (nil = no fork, 0 = already on)
    pub archimedes_block: Option<u64>,
    /// Shanghai switch time (nil = no fork, 0 = already on shanghai)
    /// Scroll EVM use the name `ShanghaiBlock` instead
    pub shanghai_time: Option<u64>,
    /// TerminalTotalDifficulty is the amount of total difficulty reached by
    /// the network that triggers the consensus upgrade.
    pub terminal_total_difficulty: Option<u64>,
    /// TerminalTotalDifficultyPassed is a flag specifying that the network already
    /// passed the terminal total difficulty. Its purpose is to disable legacy sync
    /// even without having seen the TTD locally (safer long term).
    pub terminal_total_difficulty_passed: bool,
}

impl ChainConfig {
    /// Create a chain config for Shanghai fork.
    pub fn shanghai() -> Self {
        Self {
            archimedes_block: None,
            shanghai_time: Some(0),
            terminal_total_difficulty: Some(0),
            terminal_total_difficulty_passed: true,
        }
    }
}

/// Creates a trace for the specified config
#[cfg(not(feature = "scroll"))]
pub fn trace(config: &TraceConfig) -> Result<Vec<GethExecTrace>, Error> {
    // Get the trace
    let trace_string = geth_utils::trace(&serde_json::to_string(&config).unwrap()).map_err(
        |error| match error {
            geth_utils::Error::TracingError(error) => Error::TracingError(error),
        },
    )?;

    log::trace!("trace: {}", trace_string);

    let trace = serde_json::from_str(&trace_string).map_err(Error::SerdeError)?;
    Ok(trace)
}

/// Creates a l2-trace for the specified config
#[cfg(feature = "scroll")]
pub fn l2trace(config: &TraceConfig) -> Result<BlockTrace, Error> {
    let mut l2_config = config.clone();
    if let Some(chain_config) = l2_config.chain_config.as_mut() {
        chain_config.archimedes_block = Some(0);
    } else {
        l2_config.chain_config = Some(ChainConfig {
            archimedes_block: Some(0),
            shanghai_time: None,
            terminal_total_difficulty: None,
            terminal_total_difficulty_passed: false,
        });
    }
    // Get the trace
    let trace_string = geth_utils::trace(&serde_json::to_string(&l2_config).unwrap()).map_err(
        |error| match error {
            geth_utils::Error::TracingError(error) => Error::TracingError(error),
        },
    )?;

    log::trace!("trace: {}", trace_string);

    serde_json::from_str(&trace_string).map_err(Error::SerdeError)
}

#[cfg(feature = "scroll")]
pub fn trace(config: &TraceConfig) -> Result<Vec<GethExecTrace>, Error> {
    let block_trace = l2trace(config)?;

    Ok(block_trace
        .execution_results
        .iter()
        .map(From::from)
        .collect::<Vec<_>>())
}
