#![allow(missing_docs)]
use crate::evm_circuit::{
    step::ExecutionResult,
    table::{RwTableTag, TxContextFieldTag},
    util::RandomLinearCombination,
};
use bus_mapping::{
    eth_types::{Address, ToLittleEndian, ToScalar, Word},
    evm::OpcodeId,
};
use halo2::arithmetic::FieldExt;
use sha3::{Digest, Keccak256};

#[derive(Debug, Default)]
pub struct Block<F> {
    // randomness for random linear combination
    pub randomness: F,
    pub txs: Vec<Transaction<F>>,
    pub rws: Vec<Rw>,
    pub bytecodes: Vec<Bytecode>,
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
    pub calldata_length: usize,
    pub calldata: Vec<u8>,

    pub calls: Vec<Call<F>>,
    pub steps: Vec<ExecStep>,
}

impl<F: FieldExt> Transaction<F> {
    pub fn table_assignments(&self, randomness: F) -> Vec<[F; 4]> {
        [
            vec![
                [
                    F::from_u64(self.id as u64),
                    F::from_u64(TxContextFieldTag::Nonce as u64),
                    F::zero(),
                    F::from_u64(self.nonce),
                ],
                [
                    F::from_u64(self.id as u64),
                    F::from_u64(TxContextFieldTag::Gas as u64),
                    F::zero(),
                    F::from_u64(self.gas),
                ],
                [
                    F::from_u64(self.id as u64),
                    F::from_u64(TxContextFieldTag::GasTipCap as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.gas_tip_cap.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from_u64(self.id as u64),
                    F::from_u64(TxContextFieldTag::GasFeeCap as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.gas_fee_cap.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from_u64(self.id as u64),
                    F::from_u64(TxContextFieldTag::CallerAddress as u64),
                    F::zero(),
                    self.caller_address.to_scalar().unwrap(),
                ],
                [
                    F::from_u64(self.id as u64),
                    F::from_u64(TxContextFieldTag::CalleeAddress as u64),
                    F::zero(),
                    self.callee_address.to_scalar().unwrap(),
                ],
                [
                    F::from_u64(self.id as u64),
                    F::from_u64(TxContextFieldTag::IsCreate as u64),
                    F::zero(),
                    F::from_u64(self.is_create as u64),
                ],
                [
                    F::from_u64(self.id as u64),
                    F::from_u64(TxContextFieldTag::Value as u64),
                    F::zero(),
                    RandomLinearCombination::random_linear_combine(
                        self.value.to_le_bytes(),
                        randomness,
                    ),
                ],
                [
                    F::from_u64(self.id as u64),
                    F::from_u64(TxContextFieldTag::CalldataLength as u64),
                    F::zero(),
                    F::from_u64(self.calldata_length as u64),
                ],
            ],
            self.calldata
                .iter()
                .enumerate()
                .map(|(idx, byte)| {
                    [
                        F::from_u64(self.id as u64),
                        F::from_u64(TxContextFieldTag::Calldata as u64),
                        F::from_u64(idx as u64),
                        F::from_u64(*byte as u64),
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

#[derive(Debug, Default)]
pub struct ExecStep {
    pub call_idx: usize,
    pub rw_indices: Vec<usize>,
    pub execution_result: ExecutionResult,
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
                F::from_u64(*rw_counter as u64),
                F::from_u64(*is_write as u64),
                F::from_u64(RwTableTag::Stack as u64),
                F::from_u64(*call_id as u64),
                F::from_u64(*stack_pointer as u64),
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
                F::from_u64(*rw_counter as u64),
                F::from_u64(*is_write as u64),
                F::from_u64(RwTableTag::Memory as u64),
                F::from_u64(*call_id as u64),
                F::from_u64(*memory_address),
                F::from_u64(*byte as u64),
                F::zero(),
                F::zero(),
            ],
            _ => unimplemented!(),
        }
    }
}

use pasta_curves::pallas::Base;
use std::convert::TryInto;

impl From<&bus_mapping::circuit_input_builder::ExecStep> for ExecutionResult {
    fn from(step: &bus_mapping::circuit_input_builder::ExecStep) -> Self {
        // TODO: convert error (circuit_input_builder.rs)
        assert!(step.error.is_none());
        if step.op.is_dup() {
            return ExecutionResult::DUP;
        }
        if step.op.is_push() {
            return ExecutionResult::PUSH;
        }
        if step.op.is_swap() {
            return ExecutionResult::SWAP;
        }
        match step.op {
            OpcodeId::ADD => ExecutionResult::ADD,
            OpcodeId::SUB => ExecutionResult::ADD,
            OpcodeId::EQ => ExecutionResult::LT,
            OpcodeId::GT => ExecutionResult::LT,
            OpcodeId::LT => ExecutionResult::LT,
            OpcodeId::SIGNEXTEND => ExecutionResult::SIGNEXTEND,
            OpcodeId::STOP => ExecutionResult::STOP,
            OpcodeId::AND => ExecutionResult::AND,
            OpcodeId::XOR => ExecutionResult::AND,
            OpcodeId::OR => ExecutionResult::AND,
            OpcodeId::POP => ExecutionResult::POP,
            OpcodeId::PUSH32 => ExecutionResult::PUSH,
            OpcodeId::BYTE => ExecutionResult::BYTE,
            OpcodeId::MLOAD => ExecutionResult::MLOAD,
            OpcodeId::MSTORE => ExecutionResult::MLOAD,
            OpcodeId::MSTORE8 => ExecutionResult::MLOAD,
            OpcodeId::JUMPDEST => ExecutionResult::JUMPDEST,
            OpcodeId::PC => ExecutionResult::PC,
            _ => unimplemented!("invalid opcode {:?}", step.op),
        }
    }
}

impl From<&bus_mapping::bytecode::Bytecode> for Bytecode {
    fn from(b: &bus_mapping::bytecode::Bytecode) -> Self {
        Bytecode::new(b.to_bytes())
    }
}

fn step_convert(
    prev: Option<&bus_mapping::circuit_input_builder::ExecStep>,
    step: &bus_mapping::circuit_input_builder::ExecStep,
    ops_len: (usize, usize, usize),
) -> ExecStep {
    let (stack_ops_len, memory_ops_len, _storage_ops_len) = ops_len;
    //println!("prev is {:#?}", prev);
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
                }
            })
            .collect(),
        execution_result: ExecutionResult::from(step),
        rw_counter: usize::from(step.gc),
        program_counter: usize::from(step.pc) as u64,
        stack_pointer: 1024 - step.stack_size,
        gas_left: step.gas_left.0,
        gas_cost: step.gas_cost.as_u64(),
        opcode: Some(step.op),
        // geth increases memory size before making trace,
        // so the memory size in ExecStep is not what we expect to see.
        // We have to use the memory size of previous step as correct memory
        // size before each step
        memory_size: match prev {
            None => 0,
            Some(prev_step) => (prev_step.memory_size as u64) / 32, /* memory size in word */
        },
        ..Default::default()
    };
    result
}

fn tx_convert(
    randomness: Base,
    bytecode: &Bytecode,
    tx: &bus_mapping::circuit_input_builder::Transaction,
    ops_len: (usize, usize, usize),
) -> Transaction<Base> {
    let mut result: Transaction<Base> = Transaction::<Base> {
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
    result.calls = vec![Call {
        id: 1,
        is_root: true,
        is_create: tx.is_create(),
        opcode_source: RandomLinearCombination::random_linear_combine(
            bytecode.hash.to_le_bytes(),
            randomness,
        ),
    }];
    for idx in 0..tx.steps().len() {
        let cur_step = &tx.steps()[idx];
        let prev_step = if idx == 0 {
            None
        } else {
            Some(&tx.steps()[idx - 1])
        };
        result
            .steps
            .push(step_convert(prev_step, cur_step, ops_len));
    }
    result
}

pub fn block_convert(
    bytecode: &bus_mapping::bytecode::Bytecode,
    b: &bus_mapping::circuit_input_builder::Block,
) -> Block<Base> {
    let randomness = Base::rand();
    let bytecode = bytecode.into();

    // here stack_ops/memory_ops/etc are merged into a single array
    // in EVM circuit, we need gc-sorted ops
    let mut stack_ops = b.container.sorted_stack();
    stack_ops.sort_by_key(|s| usize::from(s.gc()));
    let mut memory_ops = b.container.sorted_memory();
    memory_ops.sort_by_key(|s| usize::from(s.gc()));
    let mut storage_ops = b.container.sorted_storage();
    storage_ops.sort_by_key(|s| usize::from(s.gc()));

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
        rw_counter: s.gc().into(),
        is_write: s.op().rw().is_write(),
        call_id: 1,
        stack_pointer: usize::from(*s.op().address()),
        value: *s.op().value(),
    }));
    block.rws.extend(memory_ops.iter().map(|s| Rw::Memory {
        rw_counter: s.gc().into(),
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

#[allow(clippy::needless_borrow)]
pub fn build_block_from_trace_code_at_start(
    bytecode: &bus_mapping::bytecode::Bytecode,
) -> Block<pasta_curves::pallas::Base> {
    let block =
        bus_mapping::mock::BlockData::new_single_tx_trace_code_at_start(
            &bytecode,
        )
        .unwrap();
    let mut builder =
        bus_mapping::circuit_input_builder::CircuitInputBuilder::new(
            block.eth_block.clone(),
            block.block_ctants.clone(),
        );
    builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

    block_convert(&bytecode, &builder.block)
}
