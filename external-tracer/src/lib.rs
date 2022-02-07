//! This module generates traces by connecting to an external tracer

use eth_types::geth_types::{Account, BlockConstants, Transaction};
use eth_types::{fix_geth_trace_memory_size, Error, GethExecStep};
use serde::Serialize;

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
    let trace_string = geth_utils::trace(&serde_json::to_string(&geth_config).unwrap())
        .map_err(|_| Error::TracingError)?;

    let mut trace: Vec<GethExecStep> =
        serde_json::from_str(&trace_string).map_err(Error::SerdeError)?;
    fix_geth_trace_memory_size(&mut trace);
    Ok(trace)
}
