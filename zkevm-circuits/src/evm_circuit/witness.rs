#![allow(missing_docs)]
use crate::{
    evm_circuit::{
        param::{N_BYTES_WORD, STACK_CAPACITY},
        step::ExecutionState,
        table::{
            AccountFieldTag, BlockContextFieldTag, BytecodeFieldTag, CallContextFieldTag,
            RwTableTag, TxContextFieldTag, TxLogFieldTag, TxReceiptFieldTag,
        },
        util::RandomLinearCombination,
    },
    util::DEFAULT_RAND,
};
use bus_mapping::{
    circuit_input_builder::{self, StepAuxiliaryData},
    error::{ExecError, OogError},
    operation::{self, AccountField, CallContextField, TxReceiptField},
};

use eth_types::evm_types::OpcodeId;
use eth_types::{Address, Field, ToLittleEndian, ToScalar, ToWord, Word};
use eth_types::{ToAddress, U256};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::pairing::bn256::Fr;
use itertools::Itertools;
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, convert::TryInto, iter};

#[derive(Debug, Default, Clone)]
pub struct Block<F> {
    /// The randomness for random linear combination
    pub randomness: F,
    /// Transactions in the block
    pub txs: Vec<Transaction>,
    /// Read write events in the RwTable
    pub rws: RwMap,
    /// Bytecode used in the block
    pub bytecodes: Vec<Bytecode>,
    /// The block context
    pub context: BlockContext,
    /// ..
    pub pad_to: usize,
}

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
}

impl BlockContext {
    pub fn table_assignments<F: Field>(&self, randomness: F) -> Vec<[F; 3]> {
        [
            vec![
                [
                    F::from(BlockContextFieldTag::Coinbase as u64),
                    F::zero(),
                    self.coinbase.to_scalar().unwrap(),
                ],
                [
                    F::from(BlockContextFieldTag::Timestamp as u64),
                    F::zero(),
                    self.timestamp.to_scalar().unwrap(),
                ],
                [
                    F::from(BlockContextFieldTag::Number as u64),
                    F::zero(),
                    self.number.to_scalar().unwrap(),
                ],
                [
                    F::from(BlockContextFieldTag::Difficulty as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.difficulty.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(BlockContextFieldTag::GasLimit as u64),
                    F::zero(),
                    F::from(self.gas_limit),
                ],
                [
                    F::from(BlockContextFieldTag::BaseFee as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.base_fee.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(BlockContextFieldTag::ChainId as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.chain_id.to_le_bytes(),
                        randomness,
                    ),
                ],
            ],
            self.history_hashes
                .iter()
                .enumerate()
                .map(|(idx, hash)| {
                    [
                        F::from(BlockContextFieldTag::BlockHash as u64),
                        (self.number - idx - 1).to_scalar().unwrap(),
                        RandomLinearCombination::random_linear_combine(
                            hash.to_le_bytes(),
                            randomness,
                        ),
                    ]
                })
                .collect(),
        ]
        .concat()
    }
}

#[derive(Debug, Default, Clone)]
pub struct Transaction {
    /// The transaction identifier in the block
    pub id: usize,
    /// The sender account nonce of the transaction
    pub nonce: u64,
    /// The gas limit of the transaction
    pub gas: u64,
    /// The gas price
    pub gas_price: Word,
    /// The caller address
    pub caller_address: Address,
    /// The callee address
    pub callee_address: Address,
    /// Whether it's a create transaction
    pub is_create: bool,
    /// The ether amount of the transaction
    pub value: Word,
    /// The call data
    pub call_data: Vec<u8>,
    /// The call data length
    pub call_data_length: usize,
    /// The gas cost for transaction call data
    pub call_data_gas_cost: u64,
    /// The calls made in the transaction
    pub calls: Vec<Call>,
    /// The steps executioned in the transaction
    pub steps: Vec<ExecStep>,
}

impl Transaction {
    pub fn table_assignments<F: Field>(&self, randomness: F) -> Vec<[F; 4]> {
        [
            vec![
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::Nonce as u64),
                    F::zero(),
                    F::from(self.nonce),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::Gas as u64),
                    F::zero(),
                    F::from(self.gas),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::GasPrice as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.gas_price.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::CallerAddress as u64),
                    F::zero(),
                    self.caller_address.to_scalar().unwrap(),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::CalleeAddress as u64),
                    F::zero(),
                    self.callee_address.to_scalar().unwrap(),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::IsCreate as u64),
                    F::zero(),
                    F::from(self.is_create as u64),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::Value as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.value.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::CallDataLength as u64),
                    F::zero(),
                    F::from(self.call_data_length as u64),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::CallDataGasCost as u64),
                    F::zero(),
                    F::from(self.call_data_gas_cost),
                ],
            ],
            self.call_data
                .iter()
                .enumerate()
                .map(|(idx, byte)| {
                    [
                        F::from(self.id as u64),
                        F::from(TxContextFieldTag::CallData as u64),
                        F::from(idx as u64),
                        F::from(*byte as u64),
                    ]
                })
                .collect(),
        ]
        .concat()
    }
}

#[derive(Debug, Clone)]
pub enum CodeSource {
    Account(Word),
}

impl Default for CodeSource {
    fn default() -> Self {
        Self::Account(0.into())
    }
}

#[derive(Debug, Default, Clone)]
pub struct Call {
    /// The unique identifier of call in the whole proof, using the
    /// `rw_counter` at the call step.
    pub id: usize,
    /// Indicate if the call is the root call
    pub is_root: bool,
    /// Indicate if the call is a create call
    pub is_create: bool,
    /// The identifier of current executed bytecode
    pub code_source: CodeSource,
    /// The `rw_counter` at the end of reversion of a call if it has
    /// `is_persistent == false`
    pub rw_counter_end_of_reversion: usize,
    /// The call index of caller
    pub caller_id: usize,
    /// The depth in the call stack
    pub depth: usize,
    /// The caller address
    pub caller_address: Address,
    /// The callee address
    pub callee_address: Address,
    /// The call data offset in the memory
    pub call_data_offset: u64,
    /// The length of call data
    pub call_data_length: u64,
    /// The return data offset in the memory
    pub return_data_offset: u64,
    /// The length of return data
    pub return_data_length: u64,
    /// The ether amount of the transaction
    pub value: Word,
    /// Indicate if this call halts successfully.
    pub is_success: bool,
    /// Indicate if this call and all its caller have `is_success == true`
    pub is_persistent: bool,
    /// Indicate if it's a static call
    pub is_static: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ExecStep {
    /// The index in the Transaction calls
    pub call_index: usize,
    /// The indices in the RW trace incurred in this step
    pub rw_indices: Vec<(RwTableTag, usize)>,
    /// The execution state for the step
    pub execution_state: ExecutionState,
    /// The Read/Write counter before the step
    pub rw_counter: usize,
    /// The program counter
    pub program_counter: u64,
    /// The stack pointer
    pub stack_pointer: usize,
    /// The amount of gas left
    pub gas_left: u64,
    /// The gas cost in this step
    pub gas_cost: u64,
    /// The memory size in bytes
    pub memory_size: u64,
    /// The counter for reversible writes
    pub reversible_write_counter: usize,
    /// The counter for log index within tx
    pub log_id: usize,
    /// The opcode corresponds to the step
    pub opcode: Option<OpcodeId>,
    /// Step auxiliary data
    pub aux_data: Option<StepAuxiliaryData>,
}

impl ExecStep {
    pub fn memory_word_size(&self) -> u64 {
        // EVM always pads the memory size to word size
        // https://github.com/ethereum/go-ethereum/blob/master/core/vm/interpreter.go#L212-L216
        // Thus, the memory size must be a multiple of 32 bytes.
        assert_eq!(self.memory_size % N_BYTES_WORD as u64, 0);
        self.memory_size / N_BYTES_WORD as u64
    }
}

#[derive(Clone, Debug)]
pub struct Bytecode {
    pub hash: Word,
    pub bytes: Vec<u8>,
}

impl Bytecode {
    pub fn new(bytes: Vec<u8>) -> Self {
        let hash = Word::from_big_endian(Keccak256::digest(&bytes).as_slice());
        Self { hash, bytes }
    }

    pub fn table_assignments<F: FieldExt>(&self, randomness: F) -> Vec<[F; 5]> {
        let n = 1 + self.bytes.len();
        let mut rows = Vec::with_capacity(n);
        let hash =
            RandomLinearCombination::random_linear_combine(self.hash.to_le_bytes(), randomness);

        rows.push([
            hash,
            F::from(BytecodeFieldTag::Length as u64),
            F::zero(),
            F::zero(),
            F::from(self.bytes.len() as u64),
        ]);

        let mut push_data_left = 0;
        for (idx, byte) in self.bytes.iter().enumerate() {
            let mut is_code = true;
            if push_data_left > 0 {
                is_code = false;
                push_data_left -= 1;
            } else if (OpcodeId::PUSH1.as_u8()..=OpcodeId::PUSH32.as_u8()).contains(byte) {
                push_data_left = *byte as usize - (OpcodeId::PUSH1.as_u8() - 1) as usize;
            }
            rows.push([
                hash,
                F::from(BytecodeFieldTag::Byte as u64),
                F::from(idx as u64),
                F::from(is_code as u64),
                F::from(*byte as u64),
            ])
        }
        rows
    }
}

#[derive(Debug, Default, Clone)]
pub struct RwMap(pub HashMap<RwTableTag, Vec<Rw>>);

impl std::ops::Index<(RwTableTag, usize)> for RwMap {
    type Output = Rw;

    fn index(&self, (tag, idx): (RwTableTag, usize)) -> &Self::Output {
        &self.0.get(&tag).unwrap()[idx]
    }
}

impl RwMap {
    /// These "sorted_xx" methods are used in state circuit
    pub fn sorted_memory_rw(&self) -> Vec<Rw> {
        let mut sorted = self.0[&RwTableTag::Memory].clone();
        sorted.sort_by_key(|x| match x {
            Rw::Memory {
                call_id,
                memory_address,
                ..
            } => (*call_id, *memory_address),
            _ => panic!("invalid memory rw"),
        });
        sorted
    }

    pub fn sorted_stack_rw(&self) -> Vec<Rw> {
        let mut sorted = self.0[&RwTableTag::Stack].clone();
        sorted.sort_by_key(|x| match x {
            Rw::Stack {
                call_id,
                stack_pointer,
                ..
            } => (*call_id, *stack_pointer),
            _ => panic!("invalid stack rw"),
        });
        sorted
    }

    pub fn sorted_storage_rw(&self) -> Vec<Rw> {
        let mut sorted = self.0[&RwTableTag::AccountStorage].clone();
        sorted.sort_by_key(|x| match x {
            Rw::AccountStorage {
                account_address,
                storage_key,
                ..
            } => (*account_address, *storage_key),
            _ => panic!("invalid storage rw"),
        });
        sorted
    }
}

#[derive(Clone, Debug)]
pub enum Rw {
    TxAccessListAccount {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        account_address: Address,
        is_warm: bool,
        is_warm_prev: bool,
    },
    TxAccessListAccountStorage {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        account_address: Address,
        storage_key: Word,
        is_warm: bool,
        is_warm_prev: bool,
    },
    TxRefund {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        value: u64,
        value_prev: u64,
    },
    Account {
        rw_counter: usize,
        is_write: bool,
        account_address: Address,
        field_tag: AccountFieldTag,
        value: Word,
        value_prev: Word,
    },
    AccountStorage {
        rw_counter: usize,
        is_write: bool,
        account_address: Address,
        storage_key: Word,
        value: Word,
        value_prev: Word,
        tx_id: usize,
        committed_value: Word,
    },
    AccountDestructed {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        account_address: Address,
        is_destructed: bool,
        is_destructed_prev: bool,
    },
    CallContext {
        rw_counter: usize,
        is_write: bool,
        call_id: usize,
        field_tag: CallContextFieldTag,
        value: Word,
    },
    Stack {
        rw_counter: usize,
        is_write: bool,
        call_id: usize,
        stack_pointer: usize,
        value: Word,
    },
    Memory {
        rw_counter: usize,
        is_write: bool,
        call_id: usize,
        memory_address: u64,
        byte: u8,
    },
    TxLog {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        log_id: u64, // pack this can index together into address?
        field_tag: TxLogFieldTag,
        // topic index (0..4) if field_tag is TxLogFieldTag:Topic
        // byte index if field_tag is TxLogFieldTag:Data
        // 0 for other field tags
        index: usize,

        // when it is topic field, value can be word type
        value: Word,
    },
    TxReceipt {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        field_tag: TxReceiptFieldTag,
        value: u64,
    },
}
#[derive(Default, Clone, Copy)]
pub struct RwRow<F: FieldExt> {
    pub rw_counter: F,
    pub is_write: F,
    pub tag: F,
    pub key1: F,
    pub key2: F,
    pub key3: F,
    pub key4: F,
    pub value: F,
    pub value_prev: F,
    pub aux1: F,
    pub aux2: F,
}

impl<F: FieldExt> From<[F; 11]> for RwRow<F> {
    fn from(row: [F; 11]) -> Self {
        Self {
            rw_counter: row[0],
            is_write: row[1],
            tag: row[2],
            key1: row[3],
            key2: row[4],
            key3: row[5],
            key4: row[6],
            value: row[7],
            value_prev: row[8],
            aux1: row[9],
            aux2: row[10],
        }
    }
}

impl<F: FieldExt> RwRow<F> {
    pub fn values(&self) -> [F; 11] {
        [
            self.rw_counter,
            self.is_write,
            self.tag,
            self.key1,
            self.key2,
            self.key3,
            self.key4,
            self.value,
            self.value_prev,
            self.aux1,
            self.aux2,
        ]
    }
    pub fn rlc(&self, randomness: F) -> F {
        self.values()
            .iter()
            .rev()
            .fold(F::zero(), |acc, value| acc * randomness + value)
    }
}

impl Rw {
    pub fn tx_access_list_value_pair(&self) -> (bool, bool) {
        match self {
            Self::TxAccessListAccount {
                is_warm,
                is_warm_prev,
                ..
            } => (*is_warm, *is_warm_prev),
            Self::TxAccessListAccountStorage {
                is_warm,
                is_warm_prev,
                ..
            } => (*is_warm, *is_warm_prev),
            _ => unreachable!(),
        }
    }

    pub fn tx_refund_value_pair(&self) -> (u64, u64) {
        match self {
            Self::TxRefund {
                value, value_prev, ..
            } => (*value, *value_prev),
            _ => unreachable!(),
        }
    }

    pub fn account_value_pair(&self) -> (Word, Word) {
        match self {
            Self::Account {
                value, value_prev, ..
            } => (*value, *value_prev),
            _ => unreachable!(),
        }
    }

    pub fn aux_pair(&self) -> (usize, Word) {
        match self {
            Self::AccountStorage {
                tx_id,
                committed_value,
                ..
            } => (*tx_id, *committed_value),
            _ => unreachable!(),
        }
    }

    pub fn storage_value_aux(&self) -> (Word, Word, usize, Word) {
        match self {
            Self::AccountStorage {
                value,
                value_prev,
                tx_id,
                committed_value,
                ..
            } => (*value, *value_prev, *tx_id, *committed_value),
            _ => unreachable!(),
        }
    }

    pub fn call_context_value(&self) -> Word {
        match self {
            Self::CallContext { value, .. } => *value,
            _ => unreachable!(),
        }
    }

    pub fn stack_value(&self) -> Word {
        match self {
            Self::Stack { value, .. } => *value,
            _ => unreachable!(),
        }
    }

    pub fn log_value(&self) -> Word {
        match self {
            Self::TxLog { value, .. } => *value,
            _ => unreachable!(),
        }
    }

    pub fn receipt_value(&self) -> u64 {
        match self {
            Self::TxReceipt { value, .. } => *value,
            _ => unreachable!(),
        }
    }

    pub fn memory_value(&self) -> u8 {
        match self {
            Self::Memory { byte, .. } => *byte,
            _ => unreachable!(),
        }
    }

    pub fn table_assignment<F: Field>(&self, randomness: F) -> RwRow<F> {
        RwRow {
            rw_counter: F::from(self.rw_counter() as u64),
            is_write: F::from(self.is_write() as u64),
            tag: F::from(self.tag() as u64),
            key1: F::from(self.id().unwrap_or_default() as u64),
            key2: self.address().unwrap_or_default().to_scalar().unwrap(),
            key3: F::from(self.field_tag().unwrap_or_default() as u64),
            key4: RandomLinearCombination::random_linear_combine(
                self.storage_key().unwrap_or_default().to_le_bytes(),
                randomness,
            ),
            value: self.value_assignment(randomness),
            value_prev: self.value_prev_assignment(randomness).unwrap_or_default(),
            aux1: F::zero(), // only used for AccountStorage::tx_id, which moved to key1.
            aux2: self
                .committed_value_assignment(randomness)
                .unwrap_or_default(),
        }
    }

    pub fn rw_counter(&self) -> usize {
        match self {
            Self::Memory { rw_counter, .. }
            | Self::Stack { rw_counter, .. }
            | Self::AccountStorage { rw_counter, .. }
            | Self::TxAccessListAccount { rw_counter, .. }
            | Self::TxAccessListAccountStorage { rw_counter, .. }
            | Self::TxRefund { rw_counter, .. }
            | Self::Account { rw_counter, .. }
            | Self::AccountDestructed { rw_counter, .. }
            | Self::CallContext { rw_counter, .. }
            | Self::TxLog { rw_counter, .. }
            | Self::TxReceipt { rw_counter, .. } => *rw_counter,
        }
    }

    pub fn is_write(&self) -> bool {
        match self {
            Self::Memory { is_write, .. }
            | Self::Stack { is_write, .. }
            | Self::AccountStorage { is_write, .. }
            | Self::TxAccessListAccount { is_write, .. }
            | Self::TxAccessListAccountStorage { is_write, .. }
            | Self::TxRefund { is_write, .. }
            | Self::Account { is_write, .. }
            | Self::AccountDestructed { is_write, .. }
            | Self::CallContext { is_write, .. }
            | Self::TxLog { is_write, .. }
            | Self::TxReceipt { is_write, .. } => *is_write,
        }
    }

    pub fn tag(&self) -> RwTableTag {
        match self {
            Self::Memory { .. } => RwTableTag::Memory,
            Self::Stack { .. } => RwTableTag::Stack,
            Self::AccountStorage { .. } => RwTableTag::AccountStorage,
            Self::TxAccessListAccount { .. } => RwTableTag::TxAccessListAccount,
            Self::TxAccessListAccountStorage { .. } => RwTableTag::TxAccessListAccountStorage,
            Self::TxRefund { .. } => RwTableTag::TxRefund,
            Self::Account { .. } => RwTableTag::Account,
            Self::AccountDestructed { .. } => RwTableTag::AccountDestructed,
            Self::CallContext { .. } => RwTableTag::CallContext,
            Self::TxLog { .. } => RwTableTag::TxLog,
            Self::TxReceipt { .. } => RwTableTag::TxReceipt,
        }
    }

    pub fn id(&self) -> Option<usize> {
        match self {
            Self::AccountStorage { tx_id, .. }
            | Self::TxAccessListAccount { tx_id, .. }
            | Self::TxAccessListAccountStorage { tx_id, .. }
            | Self::TxRefund { tx_id, .. }
            | Self::TxLog { tx_id, .. }
            | Self::TxReceipt { tx_id, .. } => Some(*tx_id),
            Self::CallContext { call_id, .. }
            | Self::Stack { call_id, .. }
            | Self::Memory { call_id, .. } => Some(*call_id),
            Self::Account { .. } | Self::AccountDestructed { .. } => None,
        }
    }

    pub fn address(&self) -> Option<Address> {
        match self {
            Self::TxAccessListAccount {
                account_address, ..
            }
            | Self::TxAccessListAccountStorage {
                account_address, ..
            }
            | Self::Account {
                account_address, ..
            }
            | Self::AccountStorage {
                account_address, ..
            }
            | Self::AccountDestructed {
                account_address, ..
            } => Some(*account_address),
            Self::Memory { memory_address, .. } => Some(U256::from(*memory_address).to_address()),
            Self::Stack { stack_pointer, .. } => {
                Some(U256::from(*stack_pointer as u64).to_address())
            }
            Self::TxLog { log_id, index, .. } => {
                Some((U256::from(*index as u64) + (U256::from(*log_id) << 8)).to_address())
            }
            Self::CallContext { .. } | Self::TxRefund { .. } | Self::TxReceipt { .. } => None,
        }
    }

    pub fn field_tag(&self) -> Option<u64> {
        match self {
            Self::Account { field_tag, .. } => Some(*field_tag as u64),
            Self::CallContext { field_tag, .. } => Some(*field_tag as u64),
            Self::TxLog { field_tag, .. } => Some(*field_tag as u64),
            Self::TxReceipt { field_tag, .. } => Some(*field_tag as u64),
            Self::Memory { .. }
            | Self::Stack { .. }
            | Self::AccountStorage { .. }
            | Self::TxAccessListAccount { .. }
            | Self::TxAccessListAccountStorage { .. }
            | Self::TxRefund { .. }
            | Self::AccountDestructed { .. } => None,
        }
    }

    pub fn storage_key(&self) -> Option<Word> {
        match self {
            Self::AccountStorage { storage_key, .. }
            | Self::TxAccessListAccountStorage { storage_key, .. } => Some(*storage_key),
            Self::CallContext { .. }
            | Self::Stack { .. }
            | Self::Memory { .. }
            | Self::TxRefund { .. }
            | Self::Account { .. }
            | Self::TxAccessListAccount { .. }
            | Self::AccountDestructed { .. }
            | Self::TxLog { .. }
            | Self::TxReceipt { .. } => None,
        }
    }

    fn value_assignment<F: Field>(&self, randomness: F) -> F {
        match self {
            Self::CallContext {
                field_tag, value, ..
            } => {
                match field_tag {
                    // Only these two tags have values that may not fit into a scalar, so we need to
                    // RLC.
                    CallContextFieldTag::CodeSource | CallContextFieldTag::Value => {
                        RandomLinearCombination::random_linear_combine(
                            value.to_le_bytes(),
                            randomness,
                        )
                    }
                    _ => value.to_scalar().unwrap(),
                }
            }
            Self::Account { value, .. }
            | Self::AccountStorage { value, .. }
            | Self::Stack { value, .. }
            | Self::TxLog { value, .. } => {
                RandomLinearCombination::random_linear_combine(value.to_le_bytes(), randomness)
            }
            Self::TxAccessListAccount { is_warm, .. }
            | Self::TxAccessListAccountStorage { is_warm, .. } => F::from(*is_warm as u64),
            Self::AccountDestructed { is_destructed, .. } => F::from(*is_destructed as u64),
            Self::Memory { byte, .. } => F::from(u64::from(*byte)),
            Self::TxRefund { value, .. } | Self::TxReceipt { value, .. } => F::from(*value),
        }
    }

    fn value_prev_assignment<F: Field>(&self, randomness: F) -> Option<F> {
        match self {
            Self::Account { value_prev, .. } | Self::AccountStorage { value_prev, .. } => {
                Some(RandomLinearCombination::random_linear_combine(
                    value_prev.to_le_bytes(),
                    randomness,
                ))
            }
            Self::TxAccessListAccount { is_warm_prev, .. }
            | Self::TxAccessListAccountStorage { is_warm_prev, .. } => {
                Some(F::from(*is_warm_prev as u64))
            }
            Self::AccountDestructed {
                is_destructed_prev, ..
            } => Some(F::from(*is_destructed_prev as u64)),
            Self::TxRefund { value_prev, .. } => Some(F::from(*value_prev)),
            Self::Stack { .. }
            | Self::Memory { .. }
            | Self::CallContext { .. }
            | Self::TxLog { .. }
            | Self::TxReceipt { .. } => None,
        }
    }

    fn committed_value_assignment<F: Field>(&self, randomness: F) -> Option<F> {
        match self {
            Self::AccountStorage {
                committed_value, ..
            } => Some(RandomLinearCombination::random_linear_combine(
                committed_value.to_le_bytes(),
                randomness,
            )),
            _ => None,
        }
    }
}

impl From<&circuit_input_builder::Block> for BlockContext {
    fn from(block: &circuit_input_builder::Block) -> Self {
        Self {
            coinbase: block.coinbase,
            gas_limit: block.gas_limit,
            number: block.number,
            timestamp: block.timestamp,
            difficulty: block.difficulty,
            base_fee: block.base_fee,
            history_hashes: block.history_hashes.clone(),
            chain_id: block.chain_id,
        }
    }
}

impl From<&operation::OperationContainer> for RwMap {
    fn from(container: &operation::OperationContainer) -> Self {
        let mut rws = HashMap::default();

        rws.insert(
            RwTableTag::TxAccessListAccount,
            container
                .tx_access_list_account
                .iter()
                .map(|op| Rw::TxAccessListAccount {
                    rw_counter: op.rwc().into(),
                    is_write: true,
                    tx_id: op.op().tx_id,
                    account_address: op.op().address,
                    is_warm: op.op().is_warm,
                    is_warm_prev: op.op().is_warm_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::TxAccessListAccountStorage,
            container
                .tx_access_list_account_storage
                .iter()
                .map(|op| Rw::TxAccessListAccountStorage {
                    rw_counter: op.rwc().into(),
                    is_write: true,
                    tx_id: op.op().tx_id,
                    account_address: op.op().address,
                    storage_key: op.op().key,
                    is_warm: op.op().is_warm,
                    is_warm_prev: op.op().is_warm_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::TxRefund,
            container
                .tx_refund
                .iter()
                .map(|op| Rw::TxRefund {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    tx_id: op.op().tx_id,
                    value: op.op().value,
                    value_prev: op.op().value_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::Account,
            container
                .account
                .iter()
                .map(|op| Rw::Account {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    account_address: op.op().address,
                    field_tag: match op.op().field {
                        AccountField::Nonce => AccountFieldTag::Nonce,
                        AccountField::Balance => AccountFieldTag::Balance,
                        AccountField::CodeHash => AccountFieldTag::CodeHash,
                    },
                    value: op.op().value,
                    value_prev: op.op().value_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::AccountStorage,
            container
                .storage
                .iter()
                .map(|op| Rw::AccountStorage {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    account_address: op.op().address,
                    storage_key: op.op().key,
                    value: op.op().value,
                    value_prev: op.op().value_prev,
                    tx_id: op.op().tx_id,
                    committed_value: op.op().committed_value,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::AccountDestructed,
            container
                .account_destructed
                .iter()
                .map(|op| Rw::AccountDestructed {
                    rw_counter: op.rwc().into(),
                    is_write: true,
                    tx_id: op.op().tx_id,
                    account_address: op.op().address,
                    is_destructed: op.op().is_destructed,
                    is_destructed_prev: op.op().is_destructed_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::CallContext,
            container
                .call_context
                .iter()
                .map(|op| Rw::CallContext {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    call_id: op.op().call_id,
                    field_tag: match op.op().field {
                        CallContextField::RwCounterEndOfReversion => {
                            CallContextFieldTag::RwCounterEndOfReversion
                        }
                        CallContextField::CallerId => CallContextFieldTag::CallerId,
                        CallContextField::TxId => CallContextFieldTag::TxId,
                        CallContextField::Depth => CallContextFieldTag::Depth,
                        CallContextField::CallerAddress => CallContextFieldTag::CallerAddress,
                        CallContextField::CalleeAddress => CallContextFieldTag::CalleeAddress,
                        CallContextField::CallDataOffset => CallContextFieldTag::CallDataOffset,
                        CallContextField::CallDataLength => CallContextFieldTag::CallDataLength,
                        CallContextField::ReturnDataOffset => CallContextFieldTag::ReturnDataOffset,
                        CallContextField::ReturnDataLength => CallContextFieldTag::ReturnDataLength,
                        CallContextField::Value => CallContextFieldTag::Value,
                        CallContextField::IsSuccess => CallContextFieldTag::IsSuccess,
                        CallContextField::IsPersistent => CallContextFieldTag::IsPersistent,
                        CallContextField::IsStatic => CallContextFieldTag::IsStatic,
                        CallContextField::LastCalleeId => CallContextFieldTag::LastCalleeId,
                        CallContextField::LastCalleeReturnDataOffset => {
                            CallContextFieldTag::LastCalleeReturnDataOffset
                        }
                        CallContextField::LastCalleeReturnDataLength => {
                            CallContextFieldTag::LastCalleeReturnDataLength
                        }
                        CallContextField::IsRoot => CallContextFieldTag::IsRoot,
                        CallContextField::IsCreate => CallContextFieldTag::IsCreate,
                        CallContextField::CodeSource => CallContextFieldTag::CodeSource,
                        CallContextField::ProgramCounter => CallContextFieldTag::ProgramCounter,
                        CallContextField::StackPointer => CallContextFieldTag::StackPointer,
                        CallContextField::GasLeft => CallContextFieldTag::GasLeft,
                        CallContextField::MemorySize => CallContextFieldTag::MemorySize,
                        CallContextField::StateWriteCounter => {
                            CallContextFieldTag::StateWriteCounter
                        }
                    },
                    value: op.op().value,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::Stack,
            container
                .stack
                .iter()
                .map(|op| Rw::Stack {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    call_id: op.op().call_id(),
                    stack_pointer: usize::from(*op.op().address()),
                    value: *op.op().value(),
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::Memory,
            container
                .memory
                .iter()
                .map(|op| Rw::Memory {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    call_id: op.op().call_id(),
                    memory_address: u64::from_le_bytes(
                        op.op().address().to_le_bytes()[..8].try_into().unwrap(),
                    ),
                    byte: op.op().value(),
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::TxReceipt,
            container
                .tx_receipt
                .iter()
                .map(|op| Rw::TxReceipt {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    tx_id: op.op().tx_id,
                    field_tag: match op.op().field {
                        TxReceiptField::PostStateOrStatus => TxReceiptFieldTag::PostStateOrStatus,
                        TxReceiptField::LogLength => TxReceiptFieldTag::LogLength,
                        TxReceiptField::CumulativeGasUsed => TxReceiptFieldTag::CumulativeGasUsed,
                    },
                    value: op.op().value,
                })
                .collect(),
        );

        Self(rws)
    }
}

impl From<&ExecError> for ExecutionState {
    fn from(error: &ExecError) -> Self {
        match error {
            ExecError::InvalidOpcode => ExecutionState::ErrorInvalidOpcode,
            ExecError::StackOverflow => ExecutionState::ErrorStackOverflow,
            ExecError::StackUnderflow => ExecutionState::ErrorStackUnderflow,
            ExecError::WriteProtection => ExecutionState::ErrorWriteProtection,
            ExecError::Depth => ExecutionState::ErrorDepth,
            ExecError::InsufficientBalance => ExecutionState::ErrorInsufficientBalance,
            ExecError::ContractAddressCollision => ExecutionState::ErrorContractAddressCollision,
            ExecError::InvalidCreationCode => ExecutionState::ErrorInvalidCreationCode,
            ExecError::InvalidJump => ExecutionState::ErrorInvalidJump,
            ExecError::ReturnDataOutOfBounds => ExecutionState::ErrorReturnDataOutOfBound,
            ExecError::CodeStoreOutOfGas => ExecutionState::ErrorOutOfGasCodeStore,
            ExecError::MaxCodeSizeExceeded => ExecutionState::ErrorMaxCodeSizeExceeded,
            ExecError::OutOfGas(oog_error) => match oog_error {
                OogError::Constant => ExecutionState::ErrorOutOfGasConstant,
                OogError::StaticMemoryExpansion => {
                    ExecutionState::ErrorOutOfGasStaticMemoryExpansion
                }
                OogError::DynamicMemoryExpansion => {
                    ExecutionState::ErrorOutOfGasDynamicMemoryExpansion
                }
                OogError::MemoryCopy => ExecutionState::ErrorOutOfGasMemoryCopy,
                OogError::AccountAccess => ExecutionState::ErrorOutOfGasAccountAccess,
                OogError::CodeStore => ExecutionState::ErrorOutOfGasCodeStore,
                OogError::Log => ExecutionState::ErrorOutOfGasLOG,
                OogError::Exp => ExecutionState::ErrorOutOfGasEXP,
                OogError::Sha3 => ExecutionState::ErrorOutOfGasSHA3,
                OogError::ExtCodeCopy => ExecutionState::ErrorOutOfGasEXTCODECOPY,
                OogError::Sload => ExecutionState::ErrorOutOfGasSLOAD,
                OogError::Sstore => ExecutionState::ErrorOutOfGasSSTORE,
                OogError::Call => ExecutionState::ErrorOutOfGasCALL,
                OogError::CallCode => ExecutionState::ErrorOutOfGasCALLCODE,
                OogError::DelegateCall => ExecutionState::ErrorOutOfGasDELEGATECALL,
                OogError::Create2 => ExecutionState::ErrorOutOfGasCREATE2,
                OogError::StaticCall => ExecutionState::ErrorOutOfGasSTATICCALL,
                OogError::SelfDestruct => ExecutionState::ErrorOutOfGasSELFDESTRUCT,
            },
        }
    }
}

impl From<&circuit_input_builder::ExecStep> for ExecutionState {
    fn from(step: &circuit_input_builder::ExecStep) -> Self {
        if let Some(error) = step.error.as_ref() {
            return error.into();
        }
        match step.exec_state {
            circuit_input_builder::ExecState::Op(op) => {
                if op.is_dup() {
                    return ExecutionState::DUP;
                }
                if op.is_push() {
                    return ExecutionState::PUSH;
                }
                if op.is_swap() {
                    return ExecutionState::SWAP;
                }
                if op.is_log() {
                    return ExecutionState::LOG;
                }
                match op {
                    OpcodeId::ADD | OpcodeId::SUB => ExecutionState::ADD_SUB,
                    OpcodeId::MUL | OpcodeId::DIV | OpcodeId::MOD => ExecutionState::MUL_DIV_MOD,
                    OpcodeId::EQ | OpcodeId::LT | OpcodeId::GT => ExecutionState::CMP,
                    OpcodeId::SHA3 => ExecutionState::SHA3,
                    OpcodeId::SHR => ExecutionState::SHR,
                    OpcodeId::SLT | OpcodeId::SGT => ExecutionState::SCMP,
                    OpcodeId::SHL => ExecutionState::SHL,
                    OpcodeId::SIGNEXTEND => ExecutionState::SIGNEXTEND,
                    // TODO: Convert REVERT and RETURN to their own ExecutionState.
                    OpcodeId::STOP | OpcodeId::RETURN | OpcodeId::REVERT => ExecutionState::STOP,
                    OpcodeId::AND => ExecutionState::BITWISE,
                    OpcodeId::XOR => ExecutionState::BITWISE,
                    OpcodeId::OR => ExecutionState::BITWISE,
                    OpcodeId::POP => ExecutionState::POP,
                    OpcodeId::PUSH32 => ExecutionState::PUSH,
                    OpcodeId::BYTE => ExecutionState::BYTE,
                    OpcodeId::MLOAD => ExecutionState::MEMORY,
                    OpcodeId::MSTORE => ExecutionState::MEMORY,
                    OpcodeId::MSTORE8 => ExecutionState::MEMORY,
                    OpcodeId::JUMPDEST => ExecutionState::JUMPDEST,
                    OpcodeId::JUMP => ExecutionState::JUMP,
                    OpcodeId::JUMPI => ExecutionState::JUMPI,
                    OpcodeId::GASPRICE => ExecutionState::GASPRICE,
                    OpcodeId::PC => ExecutionState::PC,
                    OpcodeId::MSIZE => ExecutionState::MSIZE,
                    OpcodeId::CALLER => ExecutionState::CALLER,
                    OpcodeId::CALLVALUE => ExecutionState::CALLVALUE,
                    OpcodeId::EXTCODEHASH => ExecutionState::EXTCODEHASH,
                    OpcodeId::TIMESTAMP | OpcodeId::NUMBER | OpcodeId::GASLIMIT => {
                        ExecutionState::BLOCKCTXU64
                    }
                    OpcodeId::COINBASE => ExecutionState::BLOCKCTXU160,
                    OpcodeId::DIFFICULTY | OpcodeId::BASEFEE => ExecutionState::BLOCKCTXU256,
                    OpcodeId::GAS => ExecutionState::GAS,
                    OpcodeId::SELFBALANCE => ExecutionState::SELFBALANCE,
                    OpcodeId::SLOAD => ExecutionState::SLOAD,
                    OpcodeId::SSTORE => ExecutionState::SSTORE,
                    OpcodeId::CALLDATASIZE => ExecutionState::CALLDATASIZE,
                    OpcodeId::CALLDATACOPY => ExecutionState::CALLDATACOPY,
                    OpcodeId::CHAINID => ExecutionState::CHAINID,
                    OpcodeId::ISZERO => ExecutionState::ISZERO,
                    OpcodeId::CALL => ExecutionState::CALL,
                    OpcodeId::ORIGIN => ExecutionState::ORIGIN,
                    OpcodeId::CODECOPY => ExecutionState::CODECOPY,
                    OpcodeId::CALLDATALOAD => ExecutionState::CALLDATALOAD,
                    OpcodeId::INVALID(_) => ExecutionState::ErrorInvalidOpcode,
                    _ => {
                        log::warn!("unimplemented opcode {:?}", op);
                        ExecutionState::DUMMY
                    }
                }
            }
            circuit_input_builder::ExecState::BeginTx => ExecutionState::BeginTx,
            circuit_input_builder::ExecState::EndTx => ExecutionState::EndTx,
            circuit_input_builder::ExecState::CopyToMemory => ExecutionState::CopyToMemory,
            circuit_input_builder::ExecState::CopyCodeToMemory => ExecutionState::CopyCodeToMemory,
        }
    }
}

impl From<&eth_types::bytecode::Bytecode> for Bytecode {
    fn from(b: &eth_types::bytecode::Bytecode) -> Self {
        Bytecode::new(b.to_vec())
    }
}

fn step_convert(step: &circuit_input_builder::ExecStep) -> ExecStep {
    ExecStep {
        call_index: step.call_index,
        rw_indices: step
            .bus_mapping_instance
            .iter()
            .map(|x| {
                let tag = match x.target() {
                    operation::Target::Memory => RwTableTag::Memory,
                    operation::Target::Stack => RwTableTag::Stack,
                    operation::Target::Storage => RwTableTag::AccountStorage,
                    operation::Target::TxAccessListAccount => RwTableTag::TxAccessListAccount,
                    operation::Target::TxAccessListAccountStorage => {
                        RwTableTag::TxAccessListAccountStorage
                    }
                    operation::Target::TxRefund => RwTableTag::TxRefund,
                    operation::Target::Account => RwTableTag::Account,
                    operation::Target::AccountDestructed => RwTableTag::AccountDestructed,
                    operation::Target::CallContext => RwTableTag::CallContext,
                    operation::Target::TxReceipt => RwTableTag::TxReceipt,
                };
                (tag, x.as_usize())
            })
            .collect(),
        execution_state: ExecutionState::from(step),
        rw_counter: usize::from(step.rwc),
        program_counter: usize::from(step.pc) as u64,
        stack_pointer: STACK_CAPACITY - step.stack_size,
        gas_left: step.gas_left.0,
        gas_cost: step.gas_cost.as_u64(),
        opcode: match step.exec_state {
            circuit_input_builder::ExecState::Op(op) => Some(op),
            _ => None,
        },
        memory_size: step.memory_size as u64,
        reversible_write_counter: step.reversible_write_counter,
        log_id: step.log_id,
        aux_data: step.aux_data.map(Into::into),
    }
}

fn tx_convert(tx: &circuit_input_builder::Transaction, id: usize, is_last_tx: bool) -> Transaction {
    Transaction {
        id,
        nonce: tx.nonce,
        gas: tx.gas,
        gas_price: tx.gas_price,
        caller_address: tx.from,
        callee_address: tx.to,
        is_create: tx.is_create(),
        value: tx.value,
        call_data: tx.input.clone(),
        call_data_length: tx.input.len(),
        call_data_gas_cost: tx
            .input
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
        calls: tx
            .calls()
            .iter()
            .map(|call| Call {
                id: call.call_id,
                is_root: call.is_root,
                is_create: call.is_create(),
                code_source: match call.code_source {
                    circuit_input_builder::CodeSource::Address(_) => {
                        CodeSource::Account(call.code_hash.to_word())
                    }
                    circuit_input_builder::CodeSource::Memory => {
                        CodeSource::Account(call.code_hash.to_word())
                    }
                    _ => unimplemented!("unimplemented code source {:#?}", call.code_source),
                },
                rw_counter_end_of_reversion: call.rw_counter_end_of_reversion,
                caller_id: call.caller_id,
                depth: call.depth,
                caller_address: call.caller_address,
                callee_address: call.address,
                call_data_offset: call.call_data_offset,
                call_data_length: call.call_data_length,
                return_data_offset: call.return_data_offset,
                return_data_length: call.return_data_length,
                value: call.value,
                is_success: call.is_success,
                is_persistent: call.is_persistent,
                is_static: call.is_static,
            })
            .collect(),
        steps: tx
            .steps()
            .iter()
            .map(step_convert)
            .chain(
                (if is_last_tx {
                    Some(iter::once(ExecStep {
                        // if it is the first tx,  less 1 rw lookup, refer to end_tx gadget
                        rw_counter: tx.steps().last().unwrap().rwc.0 + 9 - (id == 1) as usize,
                        execution_state: ExecutionState::EndBlock,
                        ..Default::default()
                    }))
                } else {
                    None
                })
                .into_iter()
                .flatten(),
            )
            .collect(),
    }
}

pub fn block_convert(
    block: &circuit_input_builder::Block,
    code_db: &bus_mapping::state_db::CodeDB,
) -> Block<Fr> {
    Block {
        randomness: Fr::from_u128(DEFAULT_RAND),
        context: block.into(),
        rws: RwMap::from(&block.container),
        txs: block
            .txs()
            .iter()
            .enumerate()
            .map(|(idx, tx)| tx_convert(tx, idx + 1, idx + 1 == block.txs().len()))
            .collect(),
        bytecodes: block
            .txs()
            .iter()
            .flat_map(|tx| {
                tx.calls()
                    .iter()
                    .map(|call| call.code_hash)
                    .unique()
                    .into_iter()
                    .map(|code_hash| Bytecode::new(code_db.0.get(&code_hash).unwrap().to_vec()))
            })
            .collect(),
        pad_to: 0,
    }
}
