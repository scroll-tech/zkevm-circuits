#![allow(missing_docs)]
use crate::evm_circuit::{
    step::ExecutionState,
    table::{RwTableTag, TxContextFieldTag, BlockContextFieldTag},
    util::RandomLinearCombination,
};
use bus_mapping::{
    eth_types::{Address, ToLittleEndian, ToScalar, Word},
    evm::OpcodeId,
};
use halo2::arithmetic::{BaseExt, FieldExt};
use pairing::bn256::Fr as Fp;
use sha3::{Digest, Keccak256};
use std::convert::TryInto;

#[derive(Debug, Default)]
pub struct Block<F> {
    // randomness for random linear combination
    pub randomness: F,
    pub txs: Vec<Transaction<F>>,
    pub rws: Vec<Rw>,
    pub bytecodes: Vec<Bytecode>,
    pub context: BlockContext<F>,
}

#[derive(Debug, Default)]
pub struct BlockContext<F> {
    pub coinbase: Address, // u160
    pub gas_limit: u64,
    pub block_number: Word,
    pub time: F, // maybe u64 is enough ? 
    pub difficulty: Word,
    pub base_fee: Word,
    pub previous_block_hashes: Vec<Word>,
}

impl<F: FieldExt> BlockContext<F> {
    pub fn table_assignments(&self, randomness: F) -> Vec<[F; 3]> {
        [
            vec![
                [
                    F::from(BlockContextFieldTag::Coinbase as u64),
                    F::zero(),
                    self.coinbase.to_scalar().unwrap(),
                ],
                [
                    F::from(BlockContextFieldTag::GasLimit as u64),
                    F::zero(),
                    F::from(self.gas_limit), 
                ],
                [
                    F::from(BlockContextFieldTag::BlockNumber as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.block_number.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(BlockContextFieldTag::Time as u64),
                    F::zero(),
                    self.time,
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
                        F::from(idx as u64),
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
    // Context
    pub id: usize,
    pub nonce: u64,
    pub gas: u64,
    pub gas_tip_cap: Word,
    pub gas_fee_cap: Word,
    pub caller_address: Address,
    pub callee_address: Address,
    pub is_create: bool,
    pub value: Word,
    pub call_data_length: usize,
    pub call_data: Vec<u8>,

    pub calls: Vec<Call<F>>,
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
                    F::from(TxContextFieldTag::GasTipCap as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.gas_tip_cap.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from(self.id as u64),
                    F::from(TxContextFieldTag::GasFeeCap as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.gas_fee_cap.to_le_bytes(),
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
    pub id: usize,
    pub is_root: bool,
    pub is_create: bool,
    pub opcode_source: F,
}

#[derive(Clone, Debug, Default)]
pub struct ExecStep {
    pub call_idx: usize,
    pub rw_indices: Vec<usize>,
    pub execution_state: ExecutionState,
    pub rw_counter: usize,
    pub program_counter: u64,
    pub stack_pointer: usize,
    pub gas_left: u64,
    pub gas_cost: u64,
    pub memory_size: u64,
    pub state_write_counter: usize,
    pub opcode: Option<OpcodeId>,
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
                } else if (OpcodeId::PUSH1.as_u8()..=OpcodeId::PUSH32.as_u8())
                    .contains(&byte)
                {
                    self.push_data_left =
                        byte as usize - (OpcodeId::PUSH1.as_u8() - 1) as usize;
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
    },
    TxAccessListStorageSlot {
        rw_counter: usize,
        is_write: bool,
    },
    TxRefund {
        rw_counter: usize,
        is_write: bool,
    },
    Account {
        rw_counter: usize,
        is_write: bool,
    },
    AccountStorage {
        rw_counter: usize,
        is_write: bool,
    },
    AccountDestructed {
        rw_counter: usize,
        is_write: bool,
    },
    CallContext {
        rw_counter: usize,
        is_write: bool,
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
    pub fn stack_value(&self) -> Word {
        match self {
            Self::Stack { value, .. } => *value,
            _ => unreachable!(),
        }
    }

    pub fn table_assignment<F: FieldExt>(&self, randomness: F) -> [F; 8] {
        match self {
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
                RandomLinearCombination::random_linear_combine(
                    value.to_le_bytes(),
                    randomness,
                ),
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
                F::from(*byte as u64),
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
        assert!(step.error.is_none());
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
            OpcodeId::SUB => ExecutionState::ADD,
            OpcodeId::EQ => ExecutionState::CMP,
            OpcodeId::GT => ExecutionState::CMP,
            OpcodeId::LT => ExecutionState::CMP,
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
            _ => unimplemented!("unimplemented opcode {:?}", step.op),
        }
    }
}

impl From<&bus_mapping::bytecode::Bytecode> for Bytecode {
    fn from(b: &bus_mapping::bytecode::Bytecode) -> Self {
        Bytecode::new(b.to_vec())
    }
}

fn step_convert(
    step: &bus_mapping::circuit_input_builder::ExecStep,
    ops_len: (usize, usize, usize),
) -> ExecStep {
    let (stack_ops_len, memory_ops_len, _storage_ops_len) = ops_len;
    let result = ExecStep {
        rw_indices: step
            .bus_mapping_instance
            .iter()
            .map(|x| {
                let index = x.as_usize() - 1;
                match x.target() {
                    bus_mapping::operation::Target::Stack => index,
                    bus_mapping::operation::Target::Memory => {
                        index + stack_ops_len
                    }
                    bus_mapping::operation::Target::Storage => {
                        index + stack_ops_len + memory_ops_len
                    }
                    _ => unimplemented!(),
                }
            })
            .collect(),
        execution_state: ExecutionState::from(step),
        rw_counter: usize::from(step.rwc),
        program_counter: usize::from(step.pc) as u64,
        stack_pointer: 1024 - step.stack_size,
        gas_left: step.gas_left.0,
        gas_cost: step.gas_cost.as_u64(),
        opcode: Some(step.op),
        memory_size: step.memory_size as u64 / 32, /* memory size in word */
        ..Default::default()
    };
    result
}

fn tx_convert(
    randomness: Fp,
    bytecode: &Bytecode,
    tx: &bus_mapping::circuit_input_builder::Transaction,
    ops_len: (usize, usize, usize),
) -> Transaction<Fp> {
    let mut result: Transaction<Fp> = Transaction::<Fp> {
        calls: vec![Call {
            id: 1,
            is_root: true,
            is_create: tx.is_create(),
            opcode_source: RandomLinearCombination::random_linear_combine(
                bytecode.hash.to_le_bytes(),
                randomness,
            ),
        }],
        ..Default::default()
    };
    let _ = tx.steps().iter().map(|step| {
        result.steps.push(step_convert(step, ops_len));
    });
    result
}

pub fn block_convert(
    bytecode: &bus_mapping::bytecode::Bytecode,
    b: &bus_mapping::circuit_input_builder::Block,
) -> Block<Fp> {
    let randomness = Fp::rand();
    let bytecode = bytecode.into();

    // here stack_ops/memory_ops/etc are merged into a single array
    // in EVM circuit, we need rwc-sorted ops
    let mut stack_ops = b.container.sorted_stack();
    stack_ops.sort_by_key(|s| usize::from(s.rwc()));
    let mut memory_ops = b.container.sorted_memory();
    memory_ops.sort_by_key(|s| usize::from(s.rwc()));
    let mut storage_ops = b.container.sorted_storage();
    storage_ops.sort_by_key(|s| usize::from(s.rwc()));

    let mut block = Block {
        randomness,
        txs: b
            .txs()
            .iter()
            .map(|tx| {
                tx_convert(
                    randomness,
                    &bytecode,
                    tx,
                    (stack_ops.len(), memory_ops.len(), storage_ops.len()),
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
        memory_address: u64::from_le_bytes(
            s.op().address().to_le_bytes()[..8].try_into().unwrap(),
        ),
        byte: s.op().value(),
    }));
    // TODO add storage ops

    block
}

pub fn build_block_from_trace_code_at_start(
    bytecode: &bus_mapping::bytecode::Bytecode,
) -> Block<Fp> {
    let block =
        bus_mapping::mock::BlockData::new_single_tx_trace_code_at_start(
            bytecode,
        )
        .unwrap();
    let mut builder = block.new_circuit_input_builder();
    builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

    block_convert(bytecode, &builder.block)
}
