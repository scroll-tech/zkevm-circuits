//! Block-related utility module

use super::{
    execution::ExecState, transaction::Transaction, CircuitsParams, CopyEvent, ExecStep, ExpEvent,
};
use crate::{
    operation::{OperationContainer, RWCounter},
    Error,
};
use eth_types::{Address, Hash, ToWord, Word, U256};
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

/// Block-wise execution steps that don't belong to any Transaction.
#[derive(Debug, Clone)]
pub struct BlockSteps {
    /// EndBlock step that is repeated after the last transaction and before
    /// reaching the last EVM row.
    pub end_block_not_last: ExecStep,
    /// Last EndBlock step that appears in the last EVM row.
    pub end_block_last: ExecStep,
}

impl Default for BlockSteps {
    fn default() -> Self {
        Self {
            end_block_not_last: ExecStep {
                exec_state: ExecState::EndBlock,
                ..ExecStep::default()
            },
            end_block_last: ExecStep {
                exec_state: ExecState::EndBlock,
                ..ExecStep::default()
            },
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
    /// Original block from geth
    pub eth_block: eth_types::Block<eth_types::Transaction>,
}
impl BlockHead {
    /// Create a new block.
    pub fn new(
        chain_id: Word,
        history_hashes: Vec<Word>,
        eth_block: &eth_types::Block<eth_types::Transaction>,
    ) -> Result<Self, Error> {
        if eth_block.base_fee_per_gas.is_none() {
            // FIXME: resolve this once we have proper EIP-1559 support
            log::debug!(
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
            difficulty: if eth_block.difficulty.is_zero() {
                eth_block
                    .mix_hash
                    .unwrap_or_default()
                    .to_fixed_bytes()
                    .into()
            } else {
                eth_block.difficulty
            },
            base_fee: eth_block.base_fee_per_gas.unwrap_or_default(),
            eth_block: eth_block.clone(),
        })
    }
}

/// Circuit Input related to a block.
#[derive(Debug, Default, Clone)]
pub struct Block {
    /// The `Block` struct is in fact "Batch" for l2
    /// while "headers" are "Blocks" insides a batch
    pub headers: BTreeMap<u64, BlockHead>,
    /// State root of the previous block
    pub prev_state_root: Word,
    /// Withdraw root
    pub withdraw_root: Word,
    /// Withdraw roof of the previous block
    pub prev_withdraw_root: Word,
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
    /// Block-wise steps
    pub block_steps: BlockSteps,
    /// Exponentiation events in the block.
    pub exp_events: Vec<ExpEvent>,
    /// Circuits Setup Paramteres
    pub circuits_params: CircuitsParams,
    /// chain id
    pub chain_id: Word,
}

impl Block {
    /// ...
    pub fn from_headers(headers: &[BlockHead], circuits_params: CircuitsParams) -> Self {
        Self {
            block_steps: BlockSteps {
                end_block_not_last: ExecStep {
                    exec_state: ExecState::EndBlock,
                    ..ExecStep::default()
                },
                end_block_last: ExecStep {
                    exec_state: ExecState::EndBlock,
                    ..ExecStep::default()
                },
            },
            headers: headers
                .iter()
                .map(|b| (b.number.as_u64(), b.clone()))
                .collect::<BTreeMap<_, _>>(),
            circuits_params,
            ..Default::default()
        }
    }
    /// Create a new block.
    pub fn new<TX>(
        chain_id: Word,
        history_hashes: Vec<Word>,
        eth_block: &eth_types::Block<eth_types::Transaction>,
        circuits_params: CircuitsParams,
    ) -> Result<Self, Error> {
        let mut block = Self {
            block_steps: BlockSteps {
                end_block_not_last: ExecStep {
                    exec_state: ExecState::EndBlock,
                    ..ExecStep::default()
                },
                end_block_last: ExecStep {
                    exec_state: ExecState::EndBlock,
                    ..ExecStep::default()
                },
            },
            exp_events: Vec::new(),
            chain_id,
            circuits_params,
            ..Default::default()
        };
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
        self.chain_id
    }

    /// ..
    pub fn end_state_root(&self) -> Word {
        self.headers
            .last_key_value()
            .map(|(_, blk)| blk.eth_block.state_root.to_word())
            .unwrap_or(self.prev_state_root)
    }

    #[cfg(test)]
    pub fn txs_mut(&mut self) -> &mut Vec<Transaction> {
        &mut self.txs
    }
}

impl Block {
    /// Push a copy event to the block.
    pub fn add_copy_event(&mut self, event: CopyEvent) {
        self.copy_events.push(event);
    }
    /// Push an exponentiation event to the block.
    pub fn add_exp_event(&mut self, event: ExpEvent) {
        self.exp_events.push(event);
    }
}
