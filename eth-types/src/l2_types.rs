//! L2 types used to deserialize traces for l2geth.

use crate::{
    evm_types::{Gas, GasCost, OpcodeId, ProgramCounter},
    EthBlock, GethCallTrace, GethExecError, GethExecStep, GethExecTrace, GethPrestateTrace, Hash,
    ToBigEndian, Transaction, H256, H64,
};
use ethers_core::types::{
    transaction::eip2930::{AccessList, AccessListItem},
    Address, Bytes, U256, U64,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Map};
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
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Deserialize,
    Serialize,
    Default,
    Debug,
    Clone,
    PartialEq,
    Eq,
)]
#[archive(check_bytes)]
#[archive_attr(derive(Debug, PartialEq, Eq))]
pub struct BlockTraceV2 {
    /// chain id
    #[serde(rename = "chainID", default)]
    pub chain_id: u64,
    /// coinbase's status AFTER execution
    pub coinbase: AccountTrace,
    /// block
    pub header: BlockHeader,
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

/// Block header used by l2 block
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Deserialize,
    Serialize,
    Default,
    Debug,
    Clone,
    Eq,
    PartialEq,
)]
#[archive(check_bytes)]
#[archive_attr(derive(Debug, Hash, PartialEq, Eq))]
pub struct BlockHeader {
    /// Hash of the block
    pub hash: H256,
    /// Miner/author's address.
    #[serde(rename = "miner")]
    pub author: Address,
    /// State root hash
    #[serde(rename = "stateRoot")]
    pub state_root: H256,
    /// Block number
    pub number: U64,
    /// Gas Used
    #[serde(rename = "gasUsed")]
    pub gas_used: U256,
    /// Gas Limit
    #[serde(rename = "gasLimit")]
    pub gas_limit: U256,
    /// Timestamp
    pub timestamp: U256,
    /// Difficulty
    #[serde(default)]
    pub difficulty: U256,
    /// Mix Hash
    #[serde(default, rename = "mixHash")]
    pub mix_hash: Option<H256>,
    /// Nonce
    pub nonce: H64,
    /// Base fee per unit of gas (if past London)
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: Option<U256>,
}

impl From<BlockTrace> for BlockTraceV2 {
    fn from(b: BlockTrace) -> Self {
        let codes = collect_codes(&b)
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
            header: b.header.into(),
            transactions: b.transactions,
            storage_trace: b.storage_trace,
            start_l1_queue_index: b.start_l1_queue_index,
        }
    }
}

impl From<EthBlock> for BlockHeader {
    fn from(b: EthBlock) -> Self {
        BlockHeader {
            hash: b.hash.expect("incomplete block"),
            author: b.author.expect("incomplete block"),
            state_root: b.state_root,
            number: b.number.expect("incomplete block"),
            gas_used: b.gas_used,
            gas_limit: b.gas_limit,
            timestamp: b.timestamp,
            difficulty: b.difficulty,
            mix_hash: b.mix_hash,
            nonce: b.nonce.expect("incomplete block"),
            base_fee_per_gas: b.base_fee_per_gas,
        }
    }
}
/// Bytecode
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Deserialize,
    Serialize,
    Default,
    Debug,
    Clone,
    Eq,
    PartialEq,
)]
#[archive(check_bytes)]
#[archive_attr(derive(Debug, Hash, PartialEq, Eq))]
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
    //pub version: String,
    /// chain id
    #[serde(rename = "chainID", default)]
    pub chain_id: u64,
    /// coinbase's status AFTER execution
    pub coinbase: AccountTrace,
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
    /// Withdraw root
    pub withdraw_trie_root: H256,
}

impl BlockTrace {
    /// Get number of l2 txs
    pub fn num_l2_txs(&self) -> u64 {
        // 0x7e is l1 tx
        self.transactions.iter().filter(|tx| !tx.is_l1_tx()).count() as u64
    }
    /// Get number of l1 txs. L1 txs can be skipped, so just counting is not enough
    pub fn num_l1_txs(&self) -> u64 {
        // 0x7e is l1 tx
        match self
            .transactions
            .iter()
            .filter(|tx| tx.is_l1_tx())
            // tx.nonce for l1 tx is the l1 queue index, which is a globally index,
            // not per user as suggested by the name...
            .map(|tx| tx.nonce)
            .max()
        {
            None => 0, // not l1 tx in this block
            Some(end_l1_queue_index) => end_l1_queue_index - self.start_l1_queue_index + 1,
        }
    }
    /// Header encoding used for chunk hashing
    pub fn da_encode_header(&self) -> Vec<u8> {
        // https://github.com/scroll-tech/da-codec/blob/b842a0f961ad9180e16b50121ef667e15e071a26/encoding/codecv2/codecv2.go#L97
        let num_txs = (self.num_l1_txs() + self.num_l2_txs()) as u16;
        std::iter::empty()
            // Block Values
            .chain(self.header.number.unwrap().as_u64().to_be_bytes())
            .chain(self.header.timestamp.as_u64().to_be_bytes())
            .chain(
                self.header
                    .base_fee_per_gas
                    .unwrap_or_default()
                    .to_be_bytes(),
            )
            .chain(self.header.gas_limit.as_u64().to_be_bytes())
            .chain(num_txs.to_be_bytes())
            .collect_vec()
        // the `num_l1_txs` is not used for chunk hashing yet.
    }
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

/// l2 tx trace
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Deserialize,
    Serialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
)]
#[archive(check_bytes)]
#[archive_attr(derive(Debug, Hash, PartialEq, Eq))]
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
    /// Check whether it is layer1 tx
    pub fn is_l1_tx(&self) -> bool {
        self.type_ == 0x7e
    }

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
            // FIXME: is this correct? None for legacy?
            transaction_type: Some(U64::from(self.type_ as u64)),
            access_list: self.access_list.as_ref().map(|al| AccessList(al.clone())),
            max_priority_fee_per_gas: self.gas_tip_cap,
            max_fee_per_gas: self.gas_fee_cap,
            chain_id: Some(self.chain_id),
            other: Default::default(),
        }
    }
}

/// account trie proof in storage proof
pub type AccountTrieProofs = Vec<(Address, Vec<Bytes>)>;
/// storage trie proof in storage proof
pub type StorageTrieProofs = Vec<(Address, Vec<(H256, Vec<Bytes>)>)>;

/// storage trace
#[serde_as]
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Deserialize,
    Serialize,
    Default,
    Debug,
    Clone,
    Eq,
    PartialEq,
)]
#[archive(check_bytes)]
#[archive_attr(derive(Debug, PartialEq, Eq))]
pub struct StorageTrace {
    /// root before
    #[serde(rename = "rootBefore")]
    pub root_before: Hash,
    /// root after
    #[serde(rename = "rootAfter")]
    pub root_after: Hash,
    /// account proofs
    #[serde(default)]
    #[serde_as(as = "Map<_, _>")]
    pub proofs: AccountTrieProofs,
    #[serde(rename = "storageProofs", default)]
    #[serde_as(as = "Map<_, Map<_, _>>")]
    /// storage proofs for each account
    pub storage_proofs: StorageTrieProofs,
    #[serde(rename = "deletionProofs", default)]
    /// additional deletion proofs
    pub deletion_proofs: Vec<Bytes>,
    #[serde(rename = "flattenProofs", default)]
    ///
    pub flatten_proofs: HashMap<H256, Bytes>,
    #[serde(rename = "addressHashes", default)]
    ///
    pub address_hashes: HashMap<Address, Hash>,
    #[serde(rename = "storeKeyHashes", default)]
    ///
    pub store_key_hashes: HashMap<H256, Hash>,
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
    /// TODO: delete this
    pub from: Option<AccountTrace>,
    /// Status of to account AFTER execution
    /// TODO: delete this after curie upgrade
    pub to: Option<AccountTrace>,
    #[serde(rename = "accountAfter", default)]
    /// List of accounts' (coinbase etc) status AFTER execution
    pub account_after: Vec<AccountTrace>,
    #[serde(rename = "accountCreated")]
    /// Status of created account AFTER execution
    /// TODO: delete this
    pub account_created: Option<AccountTrace>,
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
    #[serde(default)]
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

/// account wrapper for account status
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Serialize,
    Deserialize,
    Clone,
    Default,
    Debug,
    PartialEq,
    Eq,
)]
#[archive(check_bytes)]
#[archive_attr(derive(Debug, Hash, PartialEq, Eq))]
#[doc(hidden)]
pub struct AccountTrace {
    pub address: Address,
    pub nonce: u64,
    pub balance: U256,
    #[serde(rename = "keccakCodeHash")]
    pub keccak_code_hash: H256,
    #[serde(rename = "poseidonCodeHash")]
    pub poseidon_code_hash: H256,
    #[serde(rename = "codeSize")]
    pub code_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::array;
    use std::sync::LazyLock;

    #[derive(serde::Deserialize, Default, Debug, Clone)]
    struct BlockTraceJsonRpcResult {
        result: BlockTrace,
    }

    static L2_TRACE: LazyLock<BlockTrace> = LazyLock::new(|| {
        const TRACE_STR: &str = include_str!("data/traces/5224657.json");
        serde_json::from_str(TRACE_STR).unwrap_or_else(|_| {
            serde_json::from_str::<BlockTraceJsonRpcResult>(TRACE_STR)
                .unwrap()
                .result
        })
    });

    #[test]
    fn test_bincode_trace_v2() {
        let trace = BlockTraceV2::from(L2_TRACE.clone());
        let encoded = bincode::serialize(&trace).unwrap();
        let decoded: BlockTraceV2 = bincode::deserialize(&encoded).unwrap();

        assert_eq!(trace, decoded);
    }

    #[test]
    fn test_rkyv_trace_v2() {
        let trace = BlockTraceV2::from(L2_TRACE.clone());
        let bytes = rkyv::to_bytes::<_, 256>(&trace).unwrap();
        // let archived = unsafe { rkyv::archived_root::<BlockTraceV2>(&bytes[..]) };
        let _archived = rkyv::check_archived_root::<BlockTraceV2>(&bytes[..]).unwrap();
        // assert_eq!(archived.chain_id, trace.chain_id);
        // assert_eq!(archived.coinbase, trace.coinbase);
        // assert_eq!(archived.header, trace.header);
        // assert_eq!(archived.transactions, trace.transactions);
        // assert_eq!(archived.codes, trace.codes);
        // assert_eq!(archived.start_l1_queue_index, trace.start_l1_queue_index);
    }

    #[ignore = "expected to fail, rkyv HashMap has issue"]
    #[test]
    fn test_rkyv_hashmap() {
        let map = HashMap::from(array::from_fn::<_, 10, _>(|idx| {
            (Address::from_low_u64_be(idx as u64), idx)
        }));
        let bytes = rkyv::to_bytes::<_, 256>(&map).unwrap();
        rkyv::check_archived_root::<HashMap<Address, usize>>(&bytes[..]).unwrap();
    }
}
