#![allow(missing_docs)]
use crate::evm_circuit::{
    param::{N_BYTES_WORD, STACK_CAPACITY},
    step::ExecutionState,
    table::{
        AccountFieldTag, BlockContextFieldTag, CallContextFieldTag, RwTableTag, TxContextFieldTag,
    },
    util::RandomLinearCombination,
};
use eth_types::evm_types::OpcodeId;
use eth_types::{Address, ToLittleEndian, ToScalar, ToWord, Word};
use halo2::arithmetic::FieldExt;
use pairing::bn256::Fr as Fp;
use sha3::{Digest, Keccak256};
use std::convert::TryInto;

#[derive(Debug, Default)]
pub struct Block<F> {
    /// The randomness for random linear combination
    pub randomness: F,
    /// Transactions in the block
    pub txs: Vec<Transaction<F>>,
    /// Read write events in the RwTable
    pub rws: Vec<Rw>,
    /// Bytecode used in the block
    pub bytecodes: Vec<Bytecode>,
    /// The block context
    pub context: BlockContext<F>,
}

#[derive(Debug, Default)]
pub struct BlockContext<F> {
    /// The address of the miner for the block
    pub coinbase: Address,
    /// The gas limit of the block
    pub gas_limit: u64,
    /// The block number
    pub block_number: F,
    /// The timestamp of the block
    pub time: u64,
    /// The difficulty of the blcok
    pub difficulty: Word,
    /// The base fee, the minimum amount of gas fee for a transaction
    pub base_fee: Word,
    /// The hash of previous blocks
    pub previous_block_hashes: Vec<Word>,
}

impl<F: FieldExt> BlockContext<F> {
    pub fn table_assignments(&self, randomness: F) -> Vec<[F; 3]> {
        [
            vec![
                [
                    F::from(BlockContextFieldTag::Coinbase as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.coinbase.to_word().to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(BlockContextFieldTag::GasLimit as u64),
                    F::zero(),
                    F::from(self.gas_limit),
                ],
                [
                    F::from(BlockContextFieldTag::BlockNumber as u64),
                    F::zero(),
                    self.block_number,
                ],
                [
                    F::from(BlockContextFieldTag::Time as u64),
                    F::zero(),
                    F::from(self.time),
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
                    F::from(BlockContextFieldTag::BaseFee as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.base_fee.to_le_bytes(),
                        randomness,
                    ),
                ],
            ],
            self.previous_block_hashes
                .iter()
                .enumerate()
                .map(|(idx, hash)| {
                    [
                        F::from(BlockContextFieldTag::BlockHash as u64),
                        self.block_number - F::from((idx + 1) as u64),
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

#[derive(Debug, Default)]
pub struct Transaction<F> {
    /// The transaction index in the block
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
    pub calls: Vec<Call<F>>,
    /// The steps executioned in the transaction
    pub steps: Vec<ExecStep>,
}

impl<F: FieldExt> Transaction<F> {
    pub fn table_assignments(&self, randomness: F) -> Vec<[F; 4]> {
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

#[derive(Debug, Default)]
pub struct Call<F> {
    /// The unique identifier of call in the whole proof, using the
    /// `rw_counter` at the call step.
    pub id: usize,
    /// Indicate if the call is the root call
    pub is_root: bool,
    /// Indicate if the call is a create call
    pub is_create: bool,
    /// The identifier of current executed bytecode
    pub opcode_source: F,
    /// The `rw_counter` at the end of reversion of a call if it has
    /// `is_persistent == false`
    pub rw_counter_end_of_reversion: usize,
    /// The call index of caller
    pub caller_call_id: usize,
    /// The depth in the call stack
    pub depth: usize,
    /// The caller address
    pub caller_address: Address,
    /// The callee address
    pub callee_address: Address,
    /// The call data offset in the memory
    pub call_data_offset: usize,
    /// The length of call data
    pub call_data_length: usize,
    /// The return data offset in the memory
    pub return_data_offset: usize,
    /// The length of return data
    pub return_data_length: usize,
    /// The ether amount of the transaction
    pub value: Word,
    /// TBD, Han will update this field
    pub result: Word,
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
    pub rw_indices: Vec<usize>,
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
    /// The counter for state writes
    pub state_write_counter: usize,
    /// The opcode corresponds to the step
    pub opcode: Option<OpcodeId>,
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

#[derive(Debug)]
pub struct Bytecode {
    pub hash: Word,
    pub bytes: Vec<u8>,
}

impl Bytecode {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            hash: Word::from_big_endian(Keccak256::digest(&bytes).as_slice()),
            bytes,
        }
    }

    pub fn table_assignments<'a, F: FieldExt>(
        &'a self,
        randomness: F,
    ) -> impl Iterator<Item = [F; 4]> + '_ {
        struct BytecodeIterator<'a, F> {
            idx: usize,
            push_data_left: usize,
            hash: F,
            bytes: &'a [u8],
        }

        impl<'a, F: FieldExt> Iterator for BytecodeIterator<'a, F> {
            type Item = [F; 4];

            fn next(&mut self) -> Option<Self::Item> {
                if self.idx == self.bytes.len() {
                    return None;
                }

                let idx = self.idx;
                let byte = self.bytes[self.idx];
                let mut is_code = true;

                if self.push_data_left > 0 {
                    is_code = false;
                    self.push_data_left -= 1;
                } else if (OpcodeId::PUSH1.as_u8()..=OpcodeId::PUSH32.as_u8()).contains(&byte) {
                    self.push_data_left = byte as usize - (OpcodeId::PUSH1.as_u8() - 1) as usize;
                }

                self.idx += 1;

                Some([
                    self.hash,
                    F::from(idx as u64),
                    F::from(byte as u64),
                    F::from(is_code as u64),
                ])
            }
        }

        BytecodeIterator {
            idx: 0,
            push_data_left: 0,
            hash: RandomLinearCombination::random_linear_combine(
                self.hash.to_le_bytes(),
                randomness,
            ),
            bytes: &self.bytes,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Rw {
    TxAccessListAccount {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        account_address: Address,
        value: bool,
        value_prev: bool,
    },
    TxAccessListAccountStorage {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        address: Address,
        key: Word,
        value: bool,
        value_prev: bool,
    },
    TxRefund {
        rw_counter: usize,
        is_write: bool,
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
        address: Address,
        key: Word,
        value: Word,
        value_prev: Word,
        tx_id: usize,
        committed_value: Word,
    },
    AccountDestructed {
        rw_counter: usize,
        is_write: bool,
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
}

impl Rw {
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

    pub fn stack_value(&self) -> Word {
        match self {
            Self::Stack { value, .. } => *value,
            _ => unreachable!(),
        }
    }

    pub fn accesslist_value_pair(&self) -> (bool, bool) {
        match self {
            Self::TxAccessListAccount {
                value, value_prev, ..
            } => (*value, *value_prev),
            Self::TxAccessListAccountStorage {
                value, value_prev, ..
            } => (*value, *value_prev),
            _ => unreachable!(),
        }
    }

    pub fn table_assignment<F: FieldExt>(&self, randomness: F) -> [F; 10] {
        match self {
            Self::TxAccessListAccount {
                rw_counter,
                is_write,
                tx_id,
                account_address,
                value,
                value_prev,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::TxAccessListAccount as u64),
                F::from(*tx_id as u64),
                account_address.to_scalar().unwrap(),
                F::zero(),
                F::from(*value as u64),
                F::from(*value_prev as u64),
                F::zero(),
                F::zero(),
            ],
            Self::TxAccessListAccountStorage {
                rw_counter,
                is_write,
                tx_id,
                address,
                key,
                value,
                value_prev,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::TxAccessListAccountStorage as u64),
                F::from(*tx_id as u64),
                F::zero(), // address.to_scalar().unwrap(),
                RandomLinearCombination::random_linear_combine(key.to_le_bytes(), randomness),
                F::zero(), // F::from(*value as u64),
                F::zero(), // F::from(*value_prev as u64),
                F::zero(),
                F::zero(),
            ],
            Self::AccountStorage {
                rw_counter,
                is_write,
                address,
                key,
                value,
                value_prev,
                tx_id,
                committed_value,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::AccountStorage as u64),
                address.to_scalar().unwrap(),
                RandomLinearCombination::random_linear_combine(key.to_le_bytes(), randomness),
                F::zero(),
                RandomLinearCombination::random_linear_combine(value.to_le_bytes(), randomness),
                RandomLinearCombination::random_linear_combine(
                    value_prev.to_le_bytes(),
                    randomness,
                ),
                F::from(*tx_id as u64),
                RandomLinearCombination::random_linear_combine(
                    committed_value.to_le_bytes(),
                    randomness,
                ),
            ],
            Self::Account {
                rw_counter,
                is_write,
                account_address,
                field_tag,
                value,
                value_prev,
            } => {
                let to_scalar = |value: &Word| match field_tag {
                    AccountFieldTag::Nonce => value.to_scalar().unwrap(),
                    _ => RandomLinearCombination::random_linear_combine(
                        value.to_le_bytes(),
                        randomness,
                    ),
                };
                [
                    F::from(*rw_counter as u64),
                    F::from(*is_write as u64),
                    F::from(RwTableTag::Account as u64),
                    account_address.to_scalar().unwrap(),
                    F::from(*field_tag as u64),
                    F::zero(),
                    to_scalar(value),
                    to_scalar(value_prev),
                    F::zero(),
                    F::zero(),
                ]
            }
            Self::CallContext {
                rw_counter,
                is_write,
                call_id,
                field_tag,
                value,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::CallContext as u64),
                F::from(*call_id as u64),
                F::from(*field_tag as u64),
                F::zero(),
                match field_tag {
                    CallContextFieldTag::OpcodeSource | CallContextFieldTag::Value => {
                        RandomLinearCombination::random_linear_combine(
                            value.to_le_bytes(),
                            randomness,
                        )
                    }
                    CallContextFieldTag::CallerAddress
                    | CallContextFieldTag::CalleeAddress
                    | CallContextFieldTag::Result => value.to_scalar().unwrap(),
                    _ => value.to_scalar().unwrap(),
                },
                F::zero(),
                F::zero(),
                F::zero(),
            ],
            Self::Stack {
                rw_counter,
                is_write,
                call_id,
                stack_pointer,
                value,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::Stack as u64),
                F::from(*call_id as u64),
                F::from(*stack_pointer as u64),
                F::zero(),
                RandomLinearCombination::random_linear_combine(value.to_le_bytes(), randomness),
                F::zero(),
                F::zero(),
                F::zero(),
            ],
            Self::Memory {
                rw_counter,
                is_write,
                call_id,
                memory_address,
                byte,
            } => [
                F::from(*rw_counter as u64),
                F::from(*is_write as u64),
                F::from(RwTableTag::Memory as u64),
                F::from(*call_id as u64),
                F::from(*memory_address),
                F::zero(),
                F::from(*byte as u64),
                F::zero(),
                F::zero(),
                F::zero(),
            ],
            _ => unimplemented!(),
        }
    }
}

impl From<&bus_mapping::circuit_input_builder::ExecStep> for ExecutionState {
    fn from(step: &bus_mapping::circuit_input_builder::ExecStep) -> Self {
        // TODO: error reporting. (errors are defined in
        // circuit_input_builder.rs)
        debug_assert!(step.error.is_none());
        if step.op.is_dup() {
            return ExecutionState::DUP;
        }
        if step.op.is_push() {
            return ExecutionState::PUSH;
        }
        if step.op.is_swap() {
            return ExecutionState::SWAP;
        }
        match step.op {
            OpcodeId::ADD => ExecutionState::ADD,
            OpcodeId::MUL => ExecutionState::MUL,
            OpcodeId::SUB => ExecutionState::ADD,
            OpcodeId::EQ | OpcodeId::LT | OpcodeId::GT => ExecutionState::CMP,
            OpcodeId::SLT | OpcodeId::SGT => ExecutionState::SCMP,
            OpcodeId::SIGNEXTEND => ExecutionState::SIGNEXTEND,
            OpcodeId::STOP => ExecutionState::STOP,
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
            OpcodeId::PC => ExecutionState::PC,
            OpcodeId::MSIZE => ExecutionState::MSIZE,
            OpcodeId::COINBASE => ExecutionState::COINBASE,
            OpcodeId::TIMESTAMP => ExecutionState::TIMESTAMP,
            OpcodeId::GAS => ExecutionState::GAS,
            OpcodeId::SLOAD => ExecutionState::SLOAD,
            _ => unimplemented!("unimplemented opcode {:?}", step.op),
        }
    }
}

impl From<&eth_types::Bytecode> for Bytecode {
    fn from(b: &eth_types::Bytecode) -> Self {
        Bytecode::new(b.to_vec())
    }
}

fn step_convert(
    step: &bus_mapping::circuit_input_builder::ExecStep,
    ops_len: (usize, usize, usize, usize),
) -> ExecStep {
    let (stack_ops_len, memory_ops_len, storage_ops_len, txaccesslist_storage_ops_len) = ops_len;
    // TODO: call_index is not set in the ExecStep
    let result = ExecStep {
        rw_indices: step
            .bus_mapping_instance
            .iter()
            .map(|x| {
                let index = x.as_usize() - 1;
                match x.target() {
                    bus_mapping::operation::Target::Stack => index,
                    bus_mapping::operation::Target::Memory => index + stack_ops_len,
                    bus_mapping::operation::Target::Storage => {
                        index + stack_ops_len + memory_ops_len
                    }
                    bus_mapping::operation::Target::TxAccessListAccountStorage => {
                        index + stack_ops_len + memory_ops_len + storage_ops_len
                    }
                    _ => unimplemented!(),
                }
            })
            .collect(),
        execution_state: ExecutionState::from(step),
        rw_counter: usize::from(step.rwc),
        program_counter: usize::from(step.pc) as u64,
        stack_pointer: STACK_CAPACITY - step.stack_size,
        gas_left: step.gas_left.0,
        gas_cost: step.gas_cost.as_u64(),
        opcode: Some(step.op),
        memory_size: step.memory_size as u64,
        ..Default::default()
    };
    result
}

fn tx_convert(
    randomness: Fp,
    bytecode: &Bytecode,
    tx: &bus_mapping::circuit_input_builder::Transaction,
    ops_len: (usize, usize, usize, usize),
) -> Transaction<Fp> {
    Transaction::<Fp> {
        calls: vec![Call {
            id: 1,
            is_root: true,
            is_create: tx.is_create(),
            opcode_source: RandomLinearCombination::random_linear_combine(
                bytecode.hash.to_le_bytes(),
                randomness,
            ),
            ..Default::default()
        }],
        steps: tx
            .steps()
            .iter()
            .map(|step| step_convert(step, ops_len))
            .collect(),
        ..Default::default()
    }
}

pub fn block_convert(
    randomness: Fp,
    bytecode: &[u8],
    b: &bus_mapping::circuit_input_builder::Block,
) -> Block<Fp> {
    let bytecode = Bytecode::new(bytecode.to_vec());

    // here stack_ops/memory_ops/etc are merged into a single array
    // in EVM circuit, we need rwc-sorted ops
    let mut stack_ops = b.container.sorted_stack();
    stack_ops.sort_by_key(|s| usize::from(s.rwc()));
    let mut memory_ops = b.container.sorted_memory();
    memory_ops.sort_by_key(|s| usize::from(s.rwc()));
    let mut storage_ops = b.container.sorted_storage();
    storage_ops.sort_by_key(|s| usize::from(s.rwc()));
    let mut txaccesslist_storage_ops = b.container.sorted_txaccesslist_storage();
    txaccesslist_storage_ops.sort_by_key(|s| usize::from(s.rwc()));

    // converting to block context
    let context = BlockContext {
        coinbase: b.block_const.coinbase,
        time: b.block_const.timestamp.try_into().unwrap(),
        ..Default::default()
    };

    let mut block = Block {
        randomness,
        context,
        txs: b
            .txs()
            .iter()
            .map(|tx| {
                tx_convert(
                    randomness,
                    &bytecode,
                    tx,
                    (
                        stack_ops.len(),
                        memory_ops.len(),
                        storage_ops.len(),
                        txaccesslist_storage_ops.len(),
                    ),
                )
            })
            .collect(),
        bytecodes: vec![bytecode],
        ..Default::default()
    };

    block.rws.extend(stack_ops.iter().map(|s| Rw::Stack {
        rw_counter: s.rwc().into(),
        is_write: s.op().rw().is_write(),
        call_id: 1,
        stack_pointer: usize::from(*s.op().address()),
        value: *s.op().value(),
    }));
    block.rws.extend(memory_ops.iter().map(|s| Rw::Memory {
        rw_counter: s.rwc().into(),
        is_write: s.op().rw().is_write(),
        call_id: 1,
        memory_address: u64::from_le_bytes(s.op().address().to_le_bytes()[..8].try_into().unwrap()),
        byte: s.op().value(),
    }));
    block
        .rws
        .extend(storage_ops.iter().map(|s| Rw::AccountStorage {
            rw_counter: s.rwc().into(),
            is_write: s.op().rw().is_write(),
            address: *s.op().address(),
            key: *s.op().key(),
            value: *s.op().value(),
            value_prev: *s.op().value_prev(),
            tx_id: 1usize,             // TODO:
            committed_value: 0.into(), // TODO:
        }));
    block.rws.extend(
        txaccesslist_storage_ops
            .iter()
            .map(|s| Rw::TxAccessListAccountStorage {
                rw_counter: s.rwc().into(),
                is_write: s.op().rw().is_write(),
                tx_id: s.op().tx_id(), // by default 1 for now
                address: *s.op().address(),
                key: *s.op().key(),
                value: s.op().value(),
                value_prev: s.op().value_prev(),
            }),
    );

    block
}
