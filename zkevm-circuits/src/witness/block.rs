use ethers_core::types::Signature;
use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::{evm_circuit::util::RandomLinearCombination, table::BlockContextFieldTag};
use bus_mapping::{
    circuit_input_builder::{self, CircuitsParams, CopyEvent, ExpEvent},
    Error,
};
use eth_types::{Address, Field, ToLittleEndian, ToScalar, Word};

use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::halo2curves::bn256::Fr;

use itertools::Itertools;

use super::{step::step_convert, tx::tx_convert, Bytecode, ExecStep, RwMap, Transaction};
use crate::util::DEFAULT_RAND;

// TODO: Remove fields that are duplicated in`eth_block`
/// Block is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default)]
pub struct Block<F> {
    /// The randomness for random linear combination
    pub randomness: F,
    /// Transactions in the block
    pub txs: Vec<Transaction>,
    /// Signatures in the block
    pub sigs: Vec<Signature>,
    /// EndBlock step that is repeated after the last transaction and before
    /// reaching the last EVM row.
    pub end_block_not_last: ExecStep,
    /// Last EndBlock step that appears in the last EVM row.
    pub end_block_last: ExecStep,
    /// Read write events in the RwTable
    pub rws: RwMap,
    /// Bytecode used in the block
    pub bytecodes: HashMap<Word, Bytecode>,
    /// The block context
    pub context: BlockContexts,
    /// Copy events for the copy circuit's table.
    pub copy_events: Vec<CopyEvent>,
    /// Exponentiation traces for the exponentiation circuit's table.
    pub exp_events: Vec<ExpEvent>,
    // TODO: Rename to `max_evm_rows`, maybe move to CircuitsParams
    /// Pad evm circuit to make selectors fixed, so vk/pk can be universal.
    /// When 0, the EVM circuit contains as many rows for all steps + 1 row
    /// for EndBlock.
    pub evm_circuit_pad_to: usize,
    /// Pad exponentiation circuit to make selectors fixed.
    pub exp_circuit_pad_to: usize,
    /// Circuit Setup Parameters
    pub circuits_params: CircuitsParams,
    /// Inputs to the SHA3 opcode
    pub sha3_inputs: Vec<Vec<u8>>,
    /// State root of the previous block
    pub prev_state_root: Word, // TODO: Make this H256
    /// Keccak inputs
    pub keccak_inputs: Vec<Vec<u8>>,
}

/// ...
#[derive(Debug, Default, Clone)]
pub struct BlockContexts {
    /// Hashmap that maps block number to its block context.
    pub ctxs: BTreeMap<u64, BlockContext>,
}

impl BlockContexts {
    /// Get the chain ID for the block.
    pub fn chain_id(&self) -> Word {
        self.first().chain_id
    }
    /// ..
    pub fn first(&self) -> &BlockContext {
        self.ctxs.iter().next().unwrap().1
    }
}

/// Block context for execution
#[derive(Debug, Default, Clone)]
pub struct BlockContext {
    /// The address of the miner for the block
    pub coinbase: Address,
    /// The gas limit of the block
    pub gas_limit: u64,
    /// The number of the block
    pub number: Word,
    /// The timestamp of the block
    pub timestamp: Word,
    /// The difficulty of the blcok
    pub difficulty: Word,
    /// The base fee, the minimum amount of gas fee for a transaction
    pub base_fee: Word,
    /// The hash of previous blocks
    pub history_hashes: Vec<Word>,
    /// The chain id
    pub chain_id: Word,
    /// Original Block from geth
    pub eth_block: eth_types::Block<eth_types::Transaction>,
}

impl BlockContext {
    /// Assignments for block table
    pub fn table_assignments<F: Field>(
        &self,
        num_txs: usize,
        cum_num_txs: usize,
        randomness: F,
    ) -> Vec<[F; 3]> {
        let current_block_number = self.number.to_scalar().unwrap();
        [
            vec![
                [
                    F::from(BlockContextFieldTag::Coinbase as u64),
                    current_block_number,
                    self.coinbase.to_scalar().unwrap(),
                ],
                [
                    F::from(BlockContextFieldTag::Timestamp as u64),
                    current_block_number,
                    self.timestamp.to_scalar().unwrap(),
                ],
                [
                    F::from(BlockContextFieldTag::Number as u64),
                    current_block_number,
                    current_block_number,
                ],
                [
                    F::from(BlockContextFieldTag::Difficulty as u64),
                    current_block_number,
                    RandomLinearCombination::random_linear_combine(
                        self.difficulty.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(BlockContextFieldTag::GasLimit as u64),
                    current_block_number,
                    F::from(self.gas_limit),
                ],
                [
                    F::from(BlockContextFieldTag::BaseFee as u64),
                    current_block_number,
                    RandomLinearCombination::random_linear_combine(
                        self.base_fee.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(BlockContextFieldTag::ChainId as u64),
                    current_block_number,
                    RandomLinearCombination::random_linear_combine(
                        self.chain_id.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(BlockContextFieldTag::NumTxs as u64),
                    current_block_number,
                    F::from(num_txs as u64),
                ],
                [
                    F::from(BlockContextFieldTag::CumNumTxs as u64),
                    current_block_number,
                    F::from(cum_num_txs as u64),
                ],
            ],
            {
                let len_history = self.history_hashes.len();
                self.history_hashes
                    .iter()
                    .enumerate()
                    .map(|(idx, hash)| {
                        [
                            F::from(BlockContextFieldTag::BlockHash as u64),
                            (self.number - len_history + idx).to_scalar().unwrap(),
                            RandomLinearCombination::random_linear_combine(
                                hash.to_le_bytes(),
                                randomness,
                            ),
                        ]
                    })
                    .collect()
            },
        ]
        .concat()
    }
}

impl From<&circuit_input_builder::Block> for BlockContexts {
    fn from(block: &circuit_input_builder::Block) -> Self {
        Self {
            ctxs: block
                .headers
                .values()
                .map(|block| {
                    (
                        block.number.as_u64(),
                        BlockContext {
                            coinbase: block.coinbase,
                            gas_limit: block.gas_limit,
                            number: block.number,
                            timestamp: block.timestamp,
                            difficulty: block.difficulty,
                            base_fee: block.base_fee,
                            history_hashes: block.history_hashes.clone(),
                            chain_id: block.chain_id,
                            eth_block: block.eth_block.clone(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        }
    }
}

/// Convert a block struct in bus-mapping to a witness block used in circuits
pub fn block_convert(
    block: &circuit_input_builder::Block,
    code_db: &bus_mapping::state_db::CodeDB,
) -> Result<Block<Fr>, Error> {
    let num_txs = block.txs().len();
    let last_block_num = block
        .headers
        .iter()
        .rev()
        .next()
        .map(|(k, _)| *k)
        .unwrap_or_default();
    let chain_id = block
        .headers
        .values()
        .into_iter()
        .next()
        .map(|header| header.chain_id.as_u64())
        .unwrap_or(1);

    Ok(Block {
        randomness: Fr::from_u128(DEFAULT_RAND),
        context: block.into(),
        rws: RwMap::from(&block.container),
        txs: block
            .txs()
            .iter()
            .enumerate()
            .map(|(idx, tx)| {
                let next_tx = if idx + 1 < num_txs {
                    Some(&block.txs()[idx + 1])
                } else {
                    None
                };
                tx_convert(tx, idx + 1, chain_id, next_tx)
            })
            .collect(),
        sigs: block.txs().iter().map(|tx| tx.signature).collect(),
        end_block_not_last: step_convert(&block.block_steps.end_block_not_last, last_block_num),
        end_block_last: step_convert(&block.block_steps.end_block_last, last_block_num),
        bytecodes: block
            .txs()
            .iter()
            .flat_map(|tx| {
                tx.calls()
                    .iter()
                    .map(|call| call.code_hash)
                    .unique()
                    .into_iter()
                    .map(|code_hash| {
                        let bytes = code_db
                            .0
                            .get(&code_hash)
                            .cloned()
                            .expect("code db should has contain the code");
                        let hash = Word::from_big_endian(code_hash.as_bytes());
                        (hash, Bytecode { hash, bytes })
                    })
            })
            .collect(),
        copy_events: block.copy_events.clone(),
        exp_events: block.exp_events.clone(),
        sha3_inputs: block.sha3_inputs.clone(),
        circuits_params: block.circuits_params.clone(),
        evm_circuit_pad_to: <usize>::default(),
        exp_circuit_pad_to: <usize>::default(),
        prev_state_root: block.prev_state_root,
        keccak_inputs: circuit_input_builder::keccak_inputs(block, code_db)?,
    })
}
