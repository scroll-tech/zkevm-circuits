use eth_types::{
    evm_types::{Gas, GasCost, OpcodeId, ProgramCounter, Stack, Storage},
    l2_types::BlockTrace,
    Block, GethExecStep, GethExecTrace, Hash, Transaction, Word, H256,
};
use ethers_core::types::{Address, Bytes, U256, U64};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct BlockTraceJsonRpcResult {
    pub result: BlockTrace,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TransactionTrace {
    // FIXME after traces upgraded
    #[serde(default, rename = "txHash")]
    pub tx_hash: H256,
    #[serde(rename = "type")]
    pub type_: u8,
    pub nonce: u64,
    pub gas: u64,
    #[serde(rename = "gasPrice")]
    pub gas_price: U256,
    pub from: Address,
    pub to: Option<Address>,
    #[serde(rename = "chainId")]
    pub chain_id: U256,
    pub value: U256,
    pub data: Bytes,
    #[serde(rename = "isCreate")]
    pub is_create: bool,
    pub v: U64,
    pub r: U256,
    pub s: U256,
}

impl TransactionTrace {
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

pub type AccountTrieProofs = HashMap<Address, Vec<Bytes>>;
pub type StorageTrieProofs = HashMap<Address, HashMap<Word, Vec<Bytes>>>;

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct StorageTrace {
    #[serde(rename = "rootBefore")]
    pub root_before: Hash,
    #[serde(rename = "rootAfter")]
    pub root_after: Hash,
    pub proofs: Option<AccountTrieProofs>,
    #[serde(rename = "storageProofs", default)]
    pub storage_proofs: StorageTrieProofs,
    #[serde(rename = "deletionProofs", default)]
    pub deletion_proofs: Vec<Bytes>,
}

pub type EthBlock = Block<Transaction>;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ExecutionResult {
    #[serde(rename = "l1DataFee", default)]
    pub l1_fee: U256,
    pub gas: u64,
    pub failed: bool,
    #[serde(rename = "returnValue", default)]
    pub return_value: String,
    pub from: Option<AccountProofWrapper>,
    pub to: Option<AccountProofWrapper>,
    #[serde(rename = "accountAfter", default)]
    pub account_after: Vec<AccountProofWrapper>,
    #[serde(rename = "accountCreated")]
    pub account_created: Option<AccountProofWrapper>,
    #[serde(rename = "poseidonCodeHash")]
    pub code_hash: Option<Hash>,
    #[serde(rename = "byteCode")]
    pub byte_code: Option<String>,
    #[serde(rename = "structLogs")]
    pub exec_steps: Vec<ExecStep>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
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
            memory: Default::default(),
            storage,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct AccountProofWrapper {
    pub address: Option<Address>,
    pub nonce: Option<u64>,
    pub balance: Option<U256>,
    #[serde(rename = "keccakCodeHash")]
    pub keccak_code_hash: Option<H256>,
    #[serde(rename = "poseidonCodeHash")]
    pub poseidon_code_hash: Option<H256>,
    pub proof: Option<Vec<Bytes>>,
    pub storage: Option<StorageProofWrapper>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StorageProofWrapper {
    pub key: Option<U256>,
    pub value: Option<U256>,
    pub proof: Option<Vec<Bytes>>,
}
