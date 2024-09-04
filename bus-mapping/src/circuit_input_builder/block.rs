//! Block-related utility module

use super::{
    execution::{ExecState, PrecompileEvent, PrecompileEvents},
    transaction::Transaction,
    CircuitsParams, CopyEvent, ExecStep, ExpEvent,
};
use crate::{
    operation::{OperationContainer, RWCounter},
    Error,
};
use eth_types::{Address, Word, H256};
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
    /// Padding step that is repeated after the last transaction and before
    /// reaching the last EVM row.
    pub padding_step: ExecStep,
    /// EndBlock step that appears in the last EVM row.
    pub end_block_step: ExecStep,
}

impl Default for BlockSteps {
    fn default() -> Self {
        Self {
            padding_step: ExecStep {
                exec_state: ExecState::Padding,
                ..ExecStep::default()
            },
            end_block_step: ExecStep {
                exec_state: ExecState::EndBlock,
                ..ExecStep::default()
            },
        }
    }
}

/// Circuit Input related to a block.
#[derive(Debug, Clone)]
pub struct Block {
    /// chain id
    pub chain_id: u64,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the latest one is at history_hashes[history_hashes.len() - 1].
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
    /// start l1 queue index
    pub start_l1_queue_index: u64,
    /// Parent block hash
    pub parent_hash: H256,
    /// State root of this block
    pub state_root: H256,
}
impl Block {
    /// Create a new block.
    pub fn new(
        chain_id: u64,
        history_hashes: Vec<Word>,
        eth_block: &eth_types::Block<eth_types::Transaction>,
    ) -> Result<Self, Error> {
        Self::new_with_l1_queue_index(chain_id, 0, history_hashes, eth_block)
    }

    /// Create a new block.
    pub fn new_with_l1_queue_index(
        chain_id: u64,
        start_l1_queue_index: u64,
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
            start_l1_queue_index,
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
            parent_hash: eth_block.parent_hash,
            state_root: eth_block.state_root,
        })
    }
}

/// Circuit Input related to many blocks, or a `Chunk`.
#[derive(Debug, Default, Clone)]
pub struct Blocks {
    /// Blocks inside this chunk
    pub blocks: BTreeMap<u64, Block>,
    /// State root of the previous block
    pub prev_state_root: H256,
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
    /// Inputs to the SHA3 opcode
    pub sha3_inputs: Vec<Vec<u8>>,
    /// Block-wise steps
    pub block_steps: BlockSteps,
    /// Exponentiation events in the block.
    pub exp_events: Vec<ExpEvent>,
    /// Circuits Setup Parameters
    pub circuits_params: CircuitsParams,
    /// chain id
    pub chain_id: u64,
    /// start_l1_queue_index
    pub start_l1_queue_index: u64,
    /// IO to/from the precompiled contract calls.
    pub precompile_events: PrecompileEvents,
    /// circuit capacity counter
    copy_counter: usize,
}

impl Blocks {
    /// Init from circuit params
    pub fn init(chain_id: u64, circuits_params: CircuitsParams) -> Self {
        Self {
            chain_id,
            circuits_params,
            ..Default::default()
        }
    }

    /// Add a new block
    pub fn add_block(&mut self, block: Block) {
        log::debug!("add_block with number {}", block.number.as_u64());
        self.blocks.insert(block.number.as_u64(), block);
    }

    /// Create a new block.
    pub fn new_with_l1_queue_index(
        chain_id: u64,
        start_l1_queue_index: u64,
        history_hashes: Vec<Word>,
        eth_block: &eth_types::Block<eth_types::Transaction>,
        circuits_params: CircuitsParams,
    ) -> Result<Self, Error> {
        let mut blocks = Self {
            block_steps: BlockSteps::default(),
            exp_events: Vec::new(),
            chain_id,
            start_l1_queue_index,
            circuits_params,
            ..Default::default()
        };
        let block = Block::new_with_l1_queue_index(
            chain_id,
            start_l1_queue_index,
            history_hashes,
            eth_block,
        )?;
        blocks.add_block(block);
        Ok(blocks)
    }

    /// Return the list of transactions of this block.
    pub fn txs(&self) -> &[Transaction] {
        &self.txs
    }

    /// Return the chain id.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// State root after all blocks in this chunk
    pub fn end_state_root(&self) -> H256 {
        self.blocks
            .last_key_value()
            .map(|(_, blk)| blk.state_root)
            .unwrap_or(self.prev_state_root)
    }

    /// Get last block number
    pub fn last_block_num(&self) -> Option<u64> {
        self.blocks.iter().next_back().map(|(k, _)| *k)
    }

    #[cfg(test)]
    pub fn txs_mut(&mut self) -> &mut Vec<Transaction> {
        &mut self.txs
    }
}

impl Blocks {
    /// Push a copy event to the block.
    pub fn add_copy_event(&mut self, event: CopyEvent) -> Result<(), Error> {
        self.copy_counter += event.full_length() as usize;
        self.copy_events.push(event);
        // Each byte needs 2 rows
        // TODO: magic num

        if self.copy_counter > 500_000 && cfg!(feature = "strict-ccc") {
            log::error!("copy event len overflow {}", self.copy_counter);
            return Err(Error::InvalidGethExecTrace("copy event len overflow"));
        }
        Ok(())
    }
    fn copy_event_total_len(&self) -> usize {
        self.copy_events
            .iter()
            .map(|c| c.full_length() as usize)
            .sum()
    }
    /// Push an exponentiation event to the block.
    pub fn add_exp_event(&mut self, event: ExpEvent) {
        self.exp_events.push(event);
    }
    /// Push a precompile event to the block.
    pub fn add_precompile_event(&mut self, event: PrecompileEvent) {
        self.precompile_events.events.push(event);
    }
}
