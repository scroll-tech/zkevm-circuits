//! L2 types used to deserialize traces for l2geth.

use crate::{
    evm_types::{Gas, GasCost, OpcodeId, ProgramCounter},
    EthBlock, GethCallTrace, GethExecError, GethExecStep, GethExecTrace, GethPrestateTrace, Hash,
    ToBigEndian, Transaction, H256,
};
use ethers_core::types::{
    transaction::eip2930::{AccessList, AccessListItem},
    Address, Bytes, U256, U64,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use trace::collect_codes;

/// Trace related helpers
pub mod trace;

#[cfg(feature = "enable-memory")]
use crate::evm_types::Memory;
#[cfg(feature = "enable-stack")]
use crate::evm_types::Stack;
#[cfg(feature = "enable-storage")]
use crate::evm_types::Storage;

/// l2 block full trace
#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct BlockTraceV2 {
    /// chain id
    #[serde(rename = "chainID", default)]
    pub chain_id: u64,
    /// coinbase's status AFTER execution
    pub coinbase: AccountProofWrapper,
    /// block
    pub header: EthBlock,
    /// txs
    pub transactions: Vec<TransactionTrace>,
    /// Accessed bytecodes with hashes
    pub codes: Vec<BytecodeTrace>,
    /// storage trace BEFORE execution
    #[serde(rename = "storageTrace")]
    pub storage_trace: StorageTrace,
    /// l1 tx queue
    #[serde(rename = "startL1QueueIndex", default)]
    pub start_l1_queue_index: u64,
}

impl From<BlockTrace> for BlockTraceV2 {
    fn from(b: BlockTrace) -> Self {
        let codes = collect_codes(&b, None)
            .expect("collect codes should not fail")
            .into_iter()
            .map(|(hash, code)| BytecodeTrace {
                hash,
                code: code.into(),
            })
            .collect_vec();
        BlockTraceV2 {
            codes,
            chain_id: b.chain_id,
            coinbase: b.coinbase,
            header: b.header,
            transactions: b.transactions,
            storage_trace: b.storage_trace,
            start_l1_queue_index: b.start_l1_queue_index,
        }
    }
}

/// Bytecode
#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct BytecodeTrace {
    /// poseidon code hash
    pub hash: H256,
    /// bytecode
    pub code: Bytes,
}

/// l2 block full trace
#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct BlockTrace {
    /// Version string
    pub version: String,
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
    /// Accessed bytecodes with hashes
    #[serde(default)]
    pub codes: Vec<BytecodeTrace>,
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
    fn from(b: BlockTrace) -> Self {
        let mut txs = Vec::new();
        for (idx, tx_data) in b.transactions.iter().enumerate() {
            let tx_idx = Some(U64::from(idx));
            let tx = tx_data.to_eth_tx(
                b.header.hash,
                b.header.number,
                tx_idx,
                b.header.base_fee_per_gas,
            );
            txs.push(tx)
        }
        EthBlock {
            transactions: txs,
            difficulty: 0.into(),
            ..b.header
        }
    }
}

impl From<&BlockTrace> for EthBlock {
    fn from(b: &BlockTrace) -> Self {
        let mut txs = Vec::new();
        for (idx, tx_data) in b.transactions.iter().enumerate() {
            let tx_idx = Some(U64::from(idx));
            let tx = tx_data.to_eth_tx(
                b.header.hash,
                b.header.number,
                tx_idx,
                b.header.base_fee_per_gas,
            );
            txs.push(tx)
        }
        EthBlock {
            transactions: txs,
            difficulty: 0.into(),
            ..b.header.clone()
        }
    }
}

impl From<&BlockTraceV2> for revm_primitives::BlockEnv {
    fn from(block: &BlockTraceV2) -> Self {
        revm_primitives::BlockEnv {
            number: revm_primitives::U256::from(block.header.number.unwrap().as_u64()),
            coinbase: block.coinbase.address.unwrap().0.into(),
            timestamp: revm_primitives::U256::from_be_bytes(block.header.timestamp.to_be_bytes()),
            gas_limit: revm_primitives::U256::from_be_bytes(block.header.gas_limit.to_be_bytes()),
            basefee: revm_primitives::U256::from_be_bytes(
                block
                    .header
                    .base_fee_per_gas
                    .unwrap_or_default()
                    .to_be_bytes(),
            ),
            difficulty: revm_primitives::U256::from_be_bytes(block.header.difficulty.to_be_bytes()),
            prevrandao: block
                .header
                .mix_hash
                .map(|h| revm_primitives::B256::from(h.to_fixed_bytes())),
            blob_excess_gas_and_price: None,
        }
    }
}

impl From<&BlockTrace> for revm_primitives::BlockEnv {
    fn from(block: &BlockTrace) -> Self {
        revm_primitives::BlockEnv {
            number: revm_primitives::U256::from(block.header.number.unwrap().as_u64()),
            coinbase: block.coinbase.address.unwrap().0.into(),
            timestamp: revm_primitives::U256::from_be_bytes(block.header.timestamp.to_be_bytes()),
            gas_limit: revm_primitives::U256::from_be_bytes(block.header.gas_limit.to_be_bytes()),
            basefee: revm_primitives::U256::from_be_bytes(
                block
                    .header
                    .base_fee_per_gas
                    .unwrap_or_default()
                    .to_be_bytes(),
            ),
            difficulty: revm_primitives::U256::from_be_bytes(block.header.difficulty.to_be_bytes()),
            prevrandao: block
                .header
                .mix_hash
                .map(|h| revm_primitives::B256::from(h.to_fixed_bytes())),
            blob_excess_gas_and_price: None,
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
    #[serde(rename = "gasTipCap")]
    /// gas tip cap
    pub gas_tip_cap: Option<U256>,
    #[serde(rename = "gasFeeCap")]
    /// gas fee cap
    pub gas_fee_cap: Option<U256>,
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
    /// access list
    #[serde(rename = "accessList")]
    pub access_list: Option<Vec<AccessListItem>>,
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
        base_fee_per_gas: Option<U256>,
    ) -> Transaction {
        let gas_price = if self.type_ == 2 {
            let priority_fee_per_gas = std::cmp::min(
                self.gas_tip_cap.unwrap(),
                self.gas_fee_cap.unwrap() - base_fee_per_gas.unwrap(),
            );
            let effective_gas_price = priority_fee_per_gas + base_fee_per_gas.unwrap();
            effective_gas_price
        } else {
            self.gas_price
        };
        Transaction {
            hash: self.tx_hash,
            nonce: U256::from(self.nonce),
            block_hash,
            block_number,
            transaction_index,
            from: self.from,
            to: self.to,
            value: self.value,
            gas_price: Some(gas_price),
            gas: U256::from(self.gas),
            input: self.data.clone(),
            v: self.v,
            r: self.r,
            s: self.s,
            transaction_type: Some(U64::from(self.type_ as u64)),
            access_list: self.access_list.as_ref().map(|al| AccessList(al.clone())),
            max_priority_fee_per_gas: self.gas_tip_cap,
            max_fee_per_gas: self.gas_fee_cap,
            chain_id: Some(self.chain_id),
            other: Default::default(),
        }
    }
}

impl From<&TransactionTrace> for revm_primitives::TxEnv {
    fn from(tx: &TransactionTrace) -> Self {
        revm_primitives::TxEnv {
            caller: tx.from.0.into(),
            gas_limit: tx.gas,
            gas_price: revm_primitives::U256::from_be_bytes(tx.gas_price.to_be_bytes()),
            transact_to: match tx.to {
                Some(to) => revm_primitives::TransactTo::Call(to.0.into()),
                None => revm_primitives::TransactTo::Create,
            },
            value: revm_primitives::U256::from_be_bytes(tx.value.to_be_bytes()),
            data: revm_primitives::Bytes::copy_from_slice(tx.data.as_ref()),
            nonce: Some(tx.nonce),
            chain_id: Some(tx.chain_id.as_u64()),
            access_list: tx
                .access_list
                .as_ref()
                .map(|v| {
                    v.iter()
                        .map(|e| {
                            (
                                e.address.0.into(),
                                e.storage_keys
                                    .iter()
                                    .map(|s| {
                                        revm_primitives::U256::from_be_bytes(s.to_fixed_bytes())
                                    })
                                    .collect(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            gas_priority_fee: tx
                .gas_tip_cap
                .map(|g| revm_primitives::U256::from_be_bytes(g.to_be_bytes())),
            ..Default::default()
        }
    }
}

/// account trie proof in storage proof
pub type AccountTrieProofs = HashMap<Address, Vec<Bytes>>;
/// storage trie proof in storage proof
pub type StorageTrieProofs = HashMap<Address, HashMap<H256, Vec<Bytes>>>;

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
    /// callTrace
    #[serde(rename = "callTrace")]
    pub call_trace: GethCallTrace,
    /// prestate
    pub prestate: HashMap<Address, GethPrestateTrace>,
}

impl From<ExecutionResult> for GethExecTrace {
    fn from(e: ExecutionResult) -> Self {
        let struct_logs = e.exec_steps.into_iter().map(GethExecStep::from).collect();
        GethExecTrace {
            l1_fee: e.l1_fee.as_u64(),
            gas: Gas(e.gas),
            failed: e.failed,
            return_value: e.return_value,
            struct_logs,
            account_after: e.account_after,
            prestate: e.prestate,
            call_trace: e.call_trace,
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
    pub error: Option<GethExecError>,
    #[cfg(feature = "enable-stack")]
    pub stack: Option<Vec<crate::Word>>,
    #[cfg(feature = "enable-memory")]
    pub memory: Option<Vec<crate::Word>>,
    #[cfg(feature = "enable-storage")]
    pub storage: Option<HashMap<crate::Word, crate::Word>>,
    #[serde(rename = "extraData")]
    pub extra_data: Option<ExtraData>,
}

impl From<ExecStep> for GethExecStep {
    fn from(e: ExecStep) -> Self {
        GethExecStep {
            pc: ProgramCounter(e.pc as usize),
            // FIXME
            op: e.op,
            gas: Gas(e.gas),
            gas_cost: GasCost(e.gas_cost),
            refund: Gas(e.refund),
            depth: e.depth as u16,
            error: e.error,
            #[cfg(feature = "enable-stack")]
            stack: e.stack.map_or_else(Stack::new, Stack::from),
            #[cfg(feature = "enable-memory")]
            memory: e.memory.map_or_else(Memory::default, Memory::from),
            #[cfg(feature = "enable-storage")]
            storage: e.storage.map_or_else(Storage::empty, Storage::from),
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
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct AccountProofWrapper {
    pub address: Option<Address>,
    pub nonce: Option<u64>,
    pub balance: Option<U256>,
    #[serde(rename = "keccakCodeHash")]
    pub keccak_code_hash: Option<H256>,
    #[serde(rename = "poseidonCodeHash")]
    pub poseidon_code_hash: Option<H256>,
    #[serde(rename = "codeSize")]
    pub code_size: u64,
    pub storage: Option<StorageProofWrapper>,
}

/// storage wrapper for storage status
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct StorageProofWrapper {
    pub key: Option<U256>,
    pub value: Option<U256>,
}

#[ignore]
#[test]
fn test_block_trace_convert() {
    let trace_v1: BlockTrace =
        crate::utils::from_json_file("src/testdata/trace_v1_5224657.json").expect("should load");
    let trace_v2: BlockTraceV2 = trace_v1.into();
    let mut fd = std::fs::File::create("src/testdata/trace_v2_5224657.json").unwrap();
    serde_json::to_writer_pretty(&mut fd, &trace_v2).unwrap();
    // then we can use this command to compare the traces:
    // vimdiff <(jq -S "del(.executionResults)|del(.txStorageTraces)" src/testdata/trace_v1_5224657.json) <(jq -S . src/testdata/trace_v2_5224657.json)
}
