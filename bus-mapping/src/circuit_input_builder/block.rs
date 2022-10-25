//! Block-related utility module

use super::{transaction::Transaction, CopyEvent};
use crate::{
    operation::{OperationContainer, RWCounter},
    Error,
};
use eth_types::{Address, Hash, Word, U256};
use std::collections::{BTreeMap, HashMap};

/// Context of a [`Block`] which can mutate in a [`Transaction`].
#[derive(Debug)]
pub struct BlockContext {
    /// Used to track the global counter in every operation in the block.
    /// Contains the next available value.
    pub(crate) rwc: RWCounter,
    /// Map call_id to (tx_index, call_index) (where tx_index is the index used
    /// in Block.txs and call_index is the index used in Transaction.
    /// calls).
    pub(crate) call_map: HashMap<usize, (usize, usize)>,
    /// Total gas used by previous transactions in this block.
    pub(crate) cumulative_gas_used: u64,
}

impl Default for BlockContext {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockContext {
    /// Create a new Self
    pub fn new() -> Self {
        Self {
            rwc: RWCounter::new(),
            call_map: HashMap::new(),
            cumulative_gas_used: 0,
        }
    }
}

/// Circuit Input related to a block.
#[derive(Debug, Clone)]
pub struct BlockHead {
    /// chain id
    pub chain_id: Word,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// coinbase
    pub coinbase: Address,
    /// time
    pub gas_limit: u64,
    /// number
    pub number: Word,
    /// difficulty
    pub timestamp: Word,
    /// gas limit
    pub difficulty: Word,
    /// base fee
    pub base_fee: Word,
}
impl BlockHead {
    /// Create a new block.
    pub fn new<TX>(
        chain_id: Word,
        history_hashes: Vec<Word>,
        eth_block: &eth_types::Block<TX>,
    ) -> Result<Self, Error> {
        if eth_block.base_fee_per_gas.is_none() {
            // FIXME: resolve this once we have proper EIP-1559 support
            log::warn!(
                "This does not look like a EIP-1559 block - base_fee_per_gas defaults to zero"
            );
        }

        Ok(Self {
            chain_id,
            history_hashes,
            coinbase: eth_block
                .author
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?,
            gas_limit: eth_block.gas_limit.low_u64(),
            number: eth_block
                .number
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?
                .low_u64()
                .into(),
            timestamp: eth_block.timestamp,
            difficulty: eth_block.difficulty,
            base_fee: eth_block.base_fee_per_gas.unwrap_or_default(),
        })
    }
}

/// Circuit Input related to a block.
#[derive(Debug, Default)]
pub struct Block {
    /// The `Block` struct is in fact "Batch" for l2
    /// while "headers" are "Blocks" insides a batch
    pub headers: BTreeMap<u64, BlockHead>,
    /// Container of operations done in this block.
    pub container: OperationContainer,
    /// Transactions contained in the block
    pub txs: Vec<Transaction>,
    /// Copy events in this block.
    pub copy_events: Vec<CopyEvent>,
    /// ..
    pub code: HashMap<Hash, Vec<u8>>,
    /// Inputs to the SHA3 opcode
    pub sha3_inputs: Vec<Vec<u8>>,
}

impl Block {
    /// Create a new block.
    pub fn new<TX>(
        chain_id: Word,
        history_hashes: Vec<Word>,
        eth_block: &eth_types::Block<TX>,
    ) -> Result<Self, Error> {
        let mut block = Self::default();
        let info = BlockHead::new(chain_id, history_hashes, eth_block)?;
        block.headers.insert(info.number.as_u64(), info);
        Ok(block)
    }

    /// Return the list of transactions of this block.
    pub fn txs(&self) -> &[Transaction] {
        &self.txs
    }

    /// Return the chain id.
    pub fn chain_id(&self) -> U256 {
        self.headers.iter().next().unwrap().1.chain_id
    }

    #[cfg(test)]
    pub fn txs_mut(&mut self) -> &mut Vec<Transaction> {
        &mut self.txs
    }
}

impl Block {
    /// Push a copy event to the block.
    pub fn add_copy_event(&mut self, copy: CopyEvent) {
        self.copy_events.push(copy);
    }
}
