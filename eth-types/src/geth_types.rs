//! Types needed for generating Ethereum traces

use crate::{Address, Block, Bytes, ChainConstants, GethExecTrace, Hash, Word, U64};
use serde::Serialize;

/// Definition of all of the data related to an account.
#[derive(Debug, Clone, Serialize)]
pub struct Account {
    /// Address
    pub address: Address,
    /// Balance
    pub balance: Word,
    /// EVM Code
    pub code: Bytes,
}

/// Definition of all of the constants related to an Ethereum block and
/// chain to be used as setup for the external tracer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockConstants {
    /// hash
    pub hash: Hash,
    /// coinbase
    pub coinbase: Address,
    /// time
    pub timestamp: Word,
    /// number
    pub number: U64,
    /// difficulty
    pub difficulty: Word,
    /// gas limit
    pub gas_limit: Word,
    /// chain id
    pub chain_id: Word,
    /// base fee
    pub base_fee: Word,
}

impl BlockConstants {
    #[allow(clippy::too_many_arguments)]
    /// Generates a new `BlockConstants` instance from it's fields.
    pub fn new(
        hash: Hash,
        coinbase: Address,
        timestamp: Word,
        number: U64,
        difficulty: Word,
        gas_limit: Word,
        chain_id: Word,
        base_fee: Word,
    ) -> BlockConstants {
        BlockConstants {
            hash,
            coinbase,
            timestamp,
            number,
            difficulty,
            gas_limit,
            chain_id,
            base_fee,
        }
    }

    /// Generate a BlockConstants from an ethereum block, useful for testing.
    pub fn from_eth_block<TX>(block: &Block<TX>, chain_id: &Word) -> Self {
        Self {
            hash: block.hash.unwrap(),
            coinbase: block.author,
            timestamp: block.timestamp,
            number: block.number.unwrap(),
            difficulty: block.difficulty,
            gas_limit: block.gas_limit,
            chain_id: *chain_id,
            base_fee: block.base_fee_per_gas.unwrap(),
        }
    }
}

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
    pub fn from_eth_tx(tx: &crate::Transaction) -> Self {
        Self {
            origin: tx.from,
            gas_limit: tx.gas,
            target: tx.to.unwrap(),
        }
    }
}

/// GethData is a type that contains all the information of a Ethereum block
#[derive(Debug)]
pub struct GethData {
    /// Block from geth
    pub eth_block: Block<()>,
    /// Transaction from geth
    pub eth_tx: crate::Transaction,
    /// Constants
    pub c_constant: ChainConstants,
    /// Constants
    pub b_constant: BlockConstants,
    /// Execution Trace from geth
    pub geth_trace: GethExecTrace,
    /// Accounts
    pub accounts: Vec<Account>,
}
