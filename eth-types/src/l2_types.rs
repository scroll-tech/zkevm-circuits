//! L2 types used to deserialize traces for l2geth.

use crate::{
    evm_types::{Gas, GasCost, Memory, OpcodeId, ProgramCounter, Stack, Storage},
    Block, GethExecStep, GethExecTrace, Hash, Transaction, Word, H256,
};
use ethers_core::types::{Address, Bytes, U256, U64};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// l2 block full trace
#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct BlockTrace {
    /// chain id
    #[serde(rename = "chainID", default)]
    pub chain_id: u64,
    /// coinbase's status AFTER execution
    pub coinbase: AccountProofWrapper,
    /// block
    pub header: EthBlock,
    /// txs
    pub transactions: Vec<TransactionTrace>,
    /// execution results
    #[serde(rename = "executionResults")]
    pub execution_results: Vec<ExecutionResult>,
    /// storage trace BEFORE execution
    #[serde(rename = "storageTrace")]
    pub storage_trace: StorageTrace,
    /// per-tx storage used by ccc
    #[serde(rename = "txStorageTraces", default)]
    pub tx_storage_trace: Vec<StorageTrace>,
    /// l1 tx queue
    #[serde(rename = "startL1QueueIndex", default)]
    pub start_l1_queue_index: u64,
}

impl From<BlockTrace> for EthBlock {
    fn from(mut b: BlockTrace) -> Self {
        let mut txs = Vec::new();
        for (idx, tx_data) in b.transactions.iter_mut().enumerate() {
            let tx_idx = Some(U64::from(idx));
            let tx = tx_data.to_eth_tx(b.header.hash, b.header.number, tx_idx);
            txs.push(tx)
        }
        EthBlock {
            transactions: txs,
            difficulty: 0.into(),
            ..b.header
        }
    }
}

/// l2 tx trace
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TransactionTrace {
    // FIXME after traces upgraded
    /// tx hash
    #[serde(default, rename = "txHash")]
    pub tx_hash: H256,
    /// tx type (in raw from)
    #[serde(rename = "type")]
    pub type_: u8,
    /// nonce
    pub nonce: u64,
    /// gas limit
    pub gas: u64,
    #[serde(rename = "gasPrice")]
    /// gas price
    pub gas_price: U256,
    /// from
    pub from: Address,
    /// to, NONE for creation (0 addr)
    pub to: Option<Address>,
    /// chain id
    #[serde(rename = "chainId")]
    pub chain_id: U256,
    /// value amount
    pub value: U256,
    /// call data
    pub data: Bytes,
    /// is creation
    #[serde(rename = "isCreate")]
    pub is_create: bool,
    /// signature v
    pub v: U64,
    /// signature r
    pub r: U256,
    /// signature s
    pub s: U256,
}

impl TransactionTrace {
    /// transfer to eth type tx
    pub fn to_eth_tx(
        &self,
        block_hash: Option<H256>,
        block_number: Option<U64>,
        transaction_index: Option<U64>,
    ) -> Transaction {
        Transaction {
            hash: self.tx_hash,
            nonce: U256::from(self.nonce),
            block_hash,
            block_number,
            transaction_index,
            from: self.from,
            to: self.to,
            value: self.value,
            gas_price: Some(self.gas_price),
            gas: U256::from(self.gas),
            input: self.data.clone(),
            v: self.v,
            r: self.r,
            s: self.s,
            transaction_type: Some(U64::from(self.type_ as u64)),
            access_list: None,
            max_priority_fee_per_gas: None,
            max_fee_per_gas: None,
            chain_id: Some(self.chain_id),
            other: Default::default(),
        }
    }
}

/// account trie proof in storage proof
pub type AccountTrieProofs = HashMap<Address, Vec<Bytes>>;
/// storage trie proof in storage proof
pub type StorageTrieProofs = HashMap<Address, HashMap<Word, Vec<Bytes>>>;

/// storage trace
#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct StorageTrace {
    /// root before
    #[serde(rename = "rootBefore")]
    pub root_before: Hash,
    /// root after
    #[serde(rename = "rootAfter")]
    pub root_after: Hash,
    /// account proofs
    pub proofs: Option<AccountTrieProofs>,
    #[serde(rename = "storageProofs", default)]
    /// storage proofs for each account
    pub storage_proofs: StorageTrieProofs,
    #[serde(rename = "deletionProofs", default)]
    /// additional deletion proofs
    pub deletion_proofs: Vec<Bytes>,
}

/// ...
pub type EthBlock = Block<Transaction>;

/// extension of `GethExecTrace`, with compatible serialize form
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ExecutionResult {
    /// L1 fee
    #[serde(rename = "l1DataFee", default)]
    pub l1_fee: U256,
    /// used gas
    pub gas: u64,
    /// True when the transaction has failed.
    pub failed: bool,
    /// Return value of execution which is a hex encoded byte array
    #[serde(rename = "returnValue", default)]
    pub return_value: String,
    /// Status of from account AFTER execution
    pub from: Option<AccountProofWrapper>,
    /// Status of to account AFTER execution
    pub to: Option<AccountProofWrapper>,
    #[serde(rename = "accountAfter", default)]
    /// List of accounts' (coinbase etc) status AFTER execution
    pub account_after: Vec<AccountProofWrapper>,
    #[serde(rename = "accountCreated")]
    /// Status of created account AFTER execution
    pub account_created: Option<AccountProofWrapper>,
    #[serde(rename = "poseidonCodeHash")]
    /// code hash of called
    pub code_hash: Option<Hash>,
    #[serde(rename = "byteCode")]
    /// called code
    pub byte_code: Option<String>,
    #[serde(rename = "structLogs")]
    /// Exec steps
    pub exec_steps: Vec<ExecStep>,
}

impl From<&ExecutionResult> for GethExecTrace {
    fn from(e: &ExecutionResult) -> Self {
        let mut struct_logs = Vec::new();
        for exec_step in &e.exec_steps {
            let step = exec_step.into();
            struct_logs.push(step)
        }
        GethExecTrace {
            l1_fee: e.l1_fee.as_u64(),
            gas: Gas(e.gas),
            failed: e.failed,
            return_value: e.return_value.clone(),
            struct_logs,
        }
    }
}

/// extension of `GethExecStep`, with compatible serialize form
#[derive(Deserialize, Serialize, Debug, Clone)]
#[doc(hidden)]
pub struct ExecStep {
    pub pc: u64,
    pub op: OpcodeId,
    pub gas: u64,
    #[serde(rename = "gasCost")]
    pub gas_cost: u64,
    #[serde(default)]
    pub refund: u64,
    pub depth: isize,
    pub error: Option<String>,
    pub stack: Option<Vec<Word>>,
    pub memory: Option<Vec<Word>>,
    pub storage: Option<HashMap<Word, Word>>,
    #[serde(rename = "extraData")]
    pub extra_data: Option<ExtraData>,
}

impl From<&ExecStep> for GethExecStep {
    fn from(e: &ExecStep) -> Self {
        let stack = e.stack.clone().map_or_else(Stack::new, Stack::from);
        let storage = e.storage.clone().map_or_else(Storage::empty, Storage::from);
        let memory = e.memory.clone().map_or_else(Memory::default, Memory::from);

        GethExecStep {
            pc: ProgramCounter(e.pc as usize),
            // FIXME
            op: e.op,
            gas: Gas(e.gas),
            gas_cost: GasCost(e.gas_cost),
            refund: Gas(e.refund),
            depth: e.depth as u16,
            error: e.error.clone(),
            stack,
            memory,
            storage,
        }
    }
}

/// extra data for some steps
#[derive(Serialize, Deserialize, Debug, Clone)]
#[doc(hidden)]
pub struct ExtraData {
    #[serde(rename = "codeList")]
    pub code_list: Option<Vec<Bytes>>,
    #[serde(rename = "proofList")]
    pub proof_list: Option<Vec<AccountProofWrapper>>,
}

impl ExtraData {
    pub fn get_code_at(&self, i: usize) -> Option<Bytes> {
        self.code_list.as_ref().and_then(|c| c.get(i)).cloned()
    }

    pub fn get_code_hash_at(&self, i: usize) -> Option<H256> {
        self.get_proof_at(i).and_then(|a| a.poseidon_code_hash)
    }

    pub fn get_proof_at(&self, i: usize) -> Option<AccountProofWrapper> {
        self.proof_list.as_ref().and_then(|p| p.get(i)).cloned()
    }
}

/// account wrapper for account status
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[doc(hidden)]
pub struct AccountProofWrapper {
    pub address: Option<Address>,
    pub nonce: Option<u64>,
    pub balance: Option<U256>,
    #[serde(rename = "keccakCodeHash")]
    pub keccak_code_hash: Option<H256>,
    #[serde(rename = "poseidonCodeHash")]
    pub poseidon_code_hash: Option<H256>,
    pub storage: Option<StorageProofWrapper>,
}

/// storage wrapper for storage status
#[derive(Serialize, Deserialize, Clone, Debug)]
#[doc(hidden)]
pub struct StorageProofWrapper {
    pub key: Option<U256>,
    pub value: Option<U256>,
}
