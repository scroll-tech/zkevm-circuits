use crate::{
    evm_circuit::{
        param::{STEP_HEIGHT, STEP_WIDTH},
        util::Cell,
        witness::{Call, ExecStep},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use halo2::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression},
};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExecutionResult {
    BeginTx,
    // Opcodes
    STOP,
    ADD, // ADD, SUB
    MUL,
    DIV,
    SDIV,
    MOD,
    SMOD,
    ADDMOD,
    MULMOD,
    EXP,
    SIGNEXTEND,
    LT,  // LT, GT, EQ
    SLT, // SLT, SGT
    ISZERO,
    AND, // AND, OR, XOR
    NOT,
    BYTE,
    SHL,
    SHR,
    SAR,
    SHA3,
    ADDRESS,
    BALANCE,
    ORIGIN,
    CALLER,
    CALLVALUE,
    CALLDATALOAD,
    CALLDATASIZE,
    CALLDATACOPY,
    CODESIZE,
    CODECOPY,
    GASPRICE,
    EXTCODESIZE,
    EXTCODECOPY,
    RETURNDATASIZE,
    RETURNDATACOPY,
    EXTCODEHASH,
    BLOCKHASH,
    COINBASE,
    TIMESTAMP,
    NUMBER,
    DIFFICULTY,
    GASLIMIT,
    CHAINID,
    SELFBALANCE,
    BASEFEE,
    POP,
    MLOAD, // MLOAD, MSTORE, MSTORE8
    SLOAD,
    SSTORE,
    JUMP,
    JUMPI,
    PC,
    MSIZE,
    GAS,
    JUMPDEST,
    PUSH, // PUSH1, PUSH2, ..., PUSH32
    DUP,  // DUP1, DUP2, ..., DUP16
    SWAP, // SWAP1, SWAP2, ..., SWAP16
    LOG,  // LOG1, LOG2, ..., LOG5
    CREATE,
    CALL,
    CALLCODE,
    RETURN,
    DELEGATECALL,
    CREATE2,
    STATICCALL,
    REVERT,
    SELFDESTRUCT,
    // Errors
    ErrorInvalidOpcode,
    ErrorStackOverflow,
    ErrorStackUnderflow,
    ErrorWriteProtection,
    ErrorDepth,
    ErrorInsufficientBalance,
    ErrorContractAddressCollision,
    ErrorMaxCodeSizeExceeded,
    ErrorInvalidCreationCode,
    ErrorReverted,
    ErrorInvalidJump,
    ErrorReturnDataOutOfBound,
    ErrorOutOfGasConstant,
    ErrorOutOfGasPureMemory,
    ErrorOutOfGasSHA3,
    ErrorOutOfGasCALLDATACOPY,
    ErrorOutOfGasCODECOPY,
    ErrorOutOfGasEXTCODECOPY,
    ErrorOutOfGasRETURNDATACOPY,
    ErrorOutOfGasLOG,
    ErrorOutOfGasCALL,
    ErrorOutOfGasCALLCODE,
    ErrorOutOfGasDELEGATECALL,
    ErrorOutOfGasCREATE2,
    ErrorOutOfGasSTATICCALL,
}

impl Default for ExecutionResult {
    fn default() -> Self {
        Self::STOP
    }
}

impl ExecutionResult {
    pub(crate) const fn as_u64(&self) -> u64 {
        *self as u64
    }

    pub(crate) fn iterator() -> impl Iterator<Item = Self> {
        [
            Self::BeginTx,
            Self::STOP,
            Self::ADD,
            Self::MUL,
            Self::DIV,
            Self::SDIV,
            Self::MOD,
            Self::SMOD,
            Self::ADDMOD,
            Self::MULMOD,
            Self::EXP,
            Self::SIGNEXTEND,
            Self::LT,
            Self::SLT,
            Self::ISZERO,
            Self::AND,
            Self::NOT,
            Self::BYTE,
            Self::SHL,
            Self::SHR,
            Self::SAR,
            Self::SHA3,
            Self::ADDRESS,
            Self::BALANCE,
            Self::ORIGIN,
            Self::CALLER,
            Self::CALLVALUE,
            Self::CALLDATALOAD,
            Self::CALLDATASIZE,
            Self::CALLDATACOPY,
            Self::CODESIZE,
            Self::CODECOPY,
            Self::GASPRICE,
            Self::EXTCODESIZE,
            Self::EXTCODECOPY,
            Self::RETURNDATASIZE,
            Self::RETURNDATACOPY,
            Self::EXTCODEHASH,
            Self::BLOCKHASH,
            Self::COINBASE,
            Self::TIMESTAMP,
            Self::NUMBER,
            Self::DIFFICULTY,
            Self::GASLIMIT,
            Self::CHAINID,
            Self::SELFBALANCE,
            Self::BASEFEE,
            Self::POP,
            Self::MLOAD,
            Self::SLOAD,
            Self::SSTORE,
            Self::JUMP,
            Self::JUMPI,
            Self::PC,
            Self::MSIZE,
            Self::GAS,
            Self::JUMPDEST,
            Self::PUSH,
            Self::DUP,
            Self::SWAP,
            Self::LOG,
            Self::CREATE,
            Self::CALL,
            Self::CALLCODE,
            Self::RETURN,
            Self::DELEGATECALL,
            Self::CREATE2,
            Self::STATICCALL,
            Self::REVERT,
            Self::SELFDESTRUCT,
            Self::ErrorInvalidOpcode,
            Self::ErrorStackOverflow,
            Self::ErrorStackUnderflow,
            Self::ErrorWriteProtection,
            Self::ErrorDepth,
            Self::ErrorInsufficientBalance,
            Self::ErrorContractAddressCollision,
            Self::ErrorMaxCodeSizeExceeded,
            Self::ErrorInvalidCreationCode,
            Self::ErrorReverted,
            Self::ErrorInvalidJump,
            Self::ErrorReturnDataOutOfBound,
            Self::ErrorOutOfGasConstant,
            Self::ErrorOutOfGasPureMemory,
            Self::ErrorOutOfGasSHA3,
            Self::ErrorOutOfGasCALLDATACOPY,
            Self::ErrorOutOfGasCODECOPY,
            Self::ErrorOutOfGasEXTCODECOPY,
            Self::ErrorOutOfGasRETURNDATACOPY,
            Self::ErrorOutOfGasLOG,
            Self::ErrorOutOfGasCALL,
            Self::ErrorOutOfGasCALLCODE,
            Self::ErrorOutOfGasDELEGATECALL,
            Self::ErrorOutOfGasCREATE2,
            Self::ErrorOutOfGasSTATICCALL,
        ]
        .iter()
        .copied()
    }

    pub(crate) fn amount() -> usize {
        Self::iterator().count()
    }

    pub(crate) fn responsible_opcodes(&self) -> Vec<OpcodeId> {
        match self {
            Self::STOP => vec![OpcodeId::STOP],
            Self::ADD => vec![OpcodeId::ADD, OpcodeId::SUB],
            Self::MUL => vec![OpcodeId::MUL],
            Self::DIV => vec![OpcodeId::DIV],
            Self::SDIV => vec![OpcodeId::SDIV],
            Self::MOD => vec![OpcodeId::MOD],
            Self::SMOD => vec![OpcodeId::SMOD],
            Self::ADDMOD => vec![OpcodeId::ADDMOD],
            Self::MULMOD => vec![OpcodeId::MULMOD],
            Self::EXP => vec![OpcodeId::EXP],
            Self::SIGNEXTEND => vec![OpcodeId::SIGNEXTEND],
            Self::LT => vec![OpcodeId::LT, OpcodeId::GT, OpcodeId::EQ],
            Self::SLT => vec![OpcodeId::SLT, OpcodeId::SGT],
            Self::ISZERO => vec![OpcodeId::ISZERO],
            Self::AND => vec![OpcodeId::AND, OpcodeId::OR, OpcodeId::XOR],
            Self::NOT => vec![OpcodeId::NOT],
            Self::BYTE => vec![OpcodeId::BYTE],
            Self::SHL => vec![OpcodeId::SHL],
            Self::SHR => vec![OpcodeId::SHR],
            Self::SAR => vec![OpcodeId::SAR],
            Self::SHA3 => vec![OpcodeId::SHA3],
            Self::ADDRESS => vec![OpcodeId::ADDRESS],
            Self::BALANCE => vec![OpcodeId::BALANCE],
            Self::ORIGIN => vec![OpcodeId::ORIGIN],
            Self::CALLER => vec![OpcodeId::CALLER],
            Self::CALLVALUE => vec![OpcodeId::CALLVALUE],
            Self::CALLDATALOAD => vec![OpcodeId::CALLDATALOAD],
            Self::CALLDATASIZE => vec![OpcodeId::CALLDATASIZE],
            Self::CALLDATACOPY => vec![OpcodeId::CALLDATACOPY],
            Self::CODESIZE => vec![OpcodeId::CODESIZE],
            Self::CODECOPY => vec![OpcodeId::CODECOPY],
            Self::GASPRICE => vec![OpcodeId::GASPRICE],
            Self::EXTCODESIZE => vec![OpcodeId::EXTCODESIZE],
            Self::EXTCODECOPY => vec![OpcodeId::EXTCODECOPY],
            Self::RETURNDATASIZE => vec![OpcodeId::RETURNDATASIZE],
            Self::RETURNDATACOPY => vec![OpcodeId::RETURNDATACOPY],
            Self::EXTCODEHASH => vec![OpcodeId::EXTCODEHASH],
            Self::BLOCKHASH => vec![OpcodeId::BLOCKHASH],
            Self::COINBASE => vec![OpcodeId::COINBASE],
            Self::TIMESTAMP => vec![OpcodeId::TIMESTAMP],
            Self::NUMBER => vec![OpcodeId::NUMBER],
            Self::DIFFICULTY => vec![OpcodeId::DIFFICULTY],
            Self::GASLIMIT => vec![OpcodeId::GASLIMIT],
            Self::CHAINID => vec![OpcodeId::CHAINID],
            Self::SELFBALANCE => vec![OpcodeId::SELFBALANCE],
            Self::BASEFEE => vec![OpcodeId::BASEFEE],
            Self::POP => vec![OpcodeId::POP],
            Self::MLOAD => {
                vec![OpcodeId::MLOAD, OpcodeId::MSTORE, OpcodeId::MSTORE8]
            }
            Self::SLOAD => vec![OpcodeId::SLOAD],
            Self::SSTORE => vec![OpcodeId::SSTORE],
            Self::JUMP => vec![OpcodeId::JUMP],
            Self::JUMPI => vec![OpcodeId::JUMPI],
            Self::PC => vec![OpcodeId::PC],
            Self::MSIZE => vec![OpcodeId::MSIZE],
            Self::GAS => vec![OpcodeId::GAS],
            Self::JUMPDEST => vec![OpcodeId::JUMPDEST],
            Self::PUSH => vec![
                OpcodeId::PUSH1,
                OpcodeId::PUSH2,
                OpcodeId::PUSH3,
                OpcodeId::PUSH4,
                OpcodeId::PUSH5,
                OpcodeId::PUSH6,
                OpcodeId::PUSH7,
                OpcodeId::PUSH8,
                OpcodeId::PUSH9,
                OpcodeId::PUSH10,
                OpcodeId::PUSH11,
                OpcodeId::PUSH12,
                OpcodeId::PUSH13,
                OpcodeId::PUSH14,
                OpcodeId::PUSH15,
                OpcodeId::PUSH16,
                OpcodeId::PUSH17,
                OpcodeId::PUSH18,
                OpcodeId::PUSH19,
                OpcodeId::PUSH20,
                OpcodeId::PUSH21,
                OpcodeId::PUSH22,
                OpcodeId::PUSH23,
                OpcodeId::PUSH24,
                OpcodeId::PUSH25,
                OpcodeId::PUSH26,
                OpcodeId::PUSH27,
                OpcodeId::PUSH28,
                OpcodeId::PUSH29,
                OpcodeId::PUSH30,
                OpcodeId::PUSH31,
                OpcodeId::PUSH32,
            ],
            Self::DUP => vec![
                OpcodeId::DUP1,
                OpcodeId::DUP2,
                OpcodeId::DUP3,
                OpcodeId::DUP4,
                OpcodeId::DUP5,
                OpcodeId::DUP6,
                OpcodeId::DUP7,
                OpcodeId::DUP8,
                OpcodeId::DUP9,
                OpcodeId::DUP10,
                OpcodeId::DUP11,
                OpcodeId::DUP12,
                OpcodeId::DUP13,
                OpcodeId::DUP14,
                OpcodeId::DUP15,
                OpcodeId::DUP16,
            ],
            Self::SWAP => vec![
                OpcodeId::SWAP1,
                OpcodeId::SWAP2,
                OpcodeId::SWAP3,
                OpcodeId::SWAP4,
                OpcodeId::SWAP5,
                OpcodeId::SWAP6,
                OpcodeId::SWAP7,
                OpcodeId::SWAP8,
                OpcodeId::SWAP9,
                OpcodeId::SWAP10,
                OpcodeId::SWAP11,
                OpcodeId::SWAP12,
                OpcodeId::SWAP13,
                OpcodeId::SWAP14,
                OpcodeId::SWAP15,
                OpcodeId::SWAP16,
            ],
            Self::LOG => vec![
                OpcodeId::LOG0,
                OpcodeId::LOG1,
                OpcodeId::LOG2,
                OpcodeId::LOG3,
                OpcodeId::LOG4,
            ],
            Self::CREATE => vec![OpcodeId::CREATE],
            Self::CALL => vec![OpcodeId::CALL],
            Self::CALLCODE => vec![OpcodeId::CALLCODE],
            Self::RETURN => vec![OpcodeId::RETURN],
            Self::DELEGATECALL => vec![OpcodeId::DELEGATECALL],
            Self::CREATE2 => vec![OpcodeId::CREATE2],
            Self::STATICCALL => vec![OpcodeId::STATICCALL],
            Self::REVERT => vec![OpcodeId::REVERT],
            Self::SELFDESTRUCT => vec![OpcodeId::SELFDESTRUCT],
            _ => vec![],
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StepState<F> {
    pub(crate) execution_result: Vec<Cell<F>>,
    pub(crate) rw_counter: Cell<F>,
    pub(crate) call_id: Cell<F>,
    pub(crate) is_root: Cell<F>,
    pub(crate) is_create: Cell<F>,
    pub(crate) opcode_source: Cell<F>,
    pub(crate) program_counter: Cell<F>,
    pub(crate) stack_pointer: Cell<F>,
    pub(crate) gas_left: Cell<F>,
    pub(crate) memory_size: Cell<F>,
    pub(crate) state_write_counter: Cell<F>,
}

#[derive(Clone, Debug)]
pub(crate) struct StepRow<F> {
    pub(crate) qs_byte_lookup: Cell<F>,
    pub(crate) cells: [Cell<F>; STEP_WIDTH],
}

#[derive(Clone, Debug)]
pub(crate) struct Step<F> {
    pub(crate) state: StepState<F>,
    pub(crate) rows: Vec<StepRow<F>>,
}

impl<F: FieldExt> Step<F> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        qs_byte_lookup: Column<Advice>,
        advices: [Column<Advice>; STEP_WIDTH],
        is_next_step: bool,
    ) -> Self {
        let state = {
            let mut cells =
                VecDeque::with_capacity(ExecutionResult::amount() + 10);
            meta.create_gate("Query state for step", |meta| {
                for idx in 0..cells.capacity() {
                    let column_idx = idx % STEP_WIDTH;
                    let rotation = idx / STEP_WIDTH
                        + if is_next_step { STEP_HEIGHT } else { 0 };
                    cells.push_back(Cell::new(
                        meta,
                        advices[column_idx],
                        rotation,
                    ));
                }

                vec![0.expr()]
            });

            StepState {
                execution_result: cells
                    .drain(..ExecutionResult::amount())
                    .collect(),
                rw_counter: cells.pop_front().unwrap(),
                call_id: cells.pop_front().unwrap(),
                is_root: cells.pop_front().unwrap(),
                is_create: cells.pop_front().unwrap(),
                opcode_source: cells.pop_front().unwrap(),
                program_counter: cells.pop_front().unwrap(),
                stack_pointer: cells.pop_front().unwrap(),
                gas_left: cells.pop_front().unwrap(),
                memory_size: cells.pop_front().unwrap(),
                state_write_counter: cells.pop_front().unwrap(),
            }
        };

        let mut rows = Vec::with_capacity(STEP_HEIGHT - 4);
        meta.create_gate("Query rows for step", |meta| {
            for rotation in 4..STEP_HEIGHT {
                let rotation =
                    rotation + if is_next_step { STEP_HEIGHT } else { 0 };
                rows.push(StepRow {
                    qs_byte_lookup: Cell::new(meta, qs_byte_lookup, rotation),
                    cells: advices
                        .map(|column| Cell::new(meta, column, rotation)),
                });
            }

            vec![0.expr()]
        });

        Self { state, rows }
    }

    pub(crate) fn q_execution_result(
        &self,
        execution_result: ExecutionResult,
    ) -> Expression<F> {
        self.state.execution_result[execution_result as usize].expr()
    }

    pub(crate) fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        for (idx, cell) in self.state.execution_result.iter().enumerate() {
            cell.assign(
                region,
                offset,
                Some(if idx == step.execution_result as usize {
                    F::one()
                } else {
                    F::zero()
                }),
            )?;
        }
        self.state.rw_counter.assign(
            region,
            offset,
            Some(F::from_u64(step.rw_counter as u64)),
        )?;
        self.state.call_id.assign(
            region,
            offset,
            Some(F::from_u64(call.id as u64)),
        )?;
        self.state.is_root.assign(
            region,
            offset,
            Some(F::from_u64(call.is_root as u64)),
        )?;
        self.state.is_create.assign(
            region,
            offset,
            Some(F::from_u64(call.is_create as u64)),
        )?;
        self.state.opcode_source.assign(
            region,
            offset,
            Some(call.opcode_source),
        )?;
        self.state.program_counter.assign(
            region,
            offset,
            Some(F::from_u64(step.program_counter as u64)),
        )?;
        self.state.stack_pointer.assign(
            region,
            offset,
            Some(F::from_u64(step.stack_pointer as u64)),
        )?;
        self.state.gas_left.assign(
            region,
            offset,
            Some(F::from_u64(step.gas_left)),
        )?;
        self.state.memory_size.assign(
            region,
            offset,
            Some(F::from_u64(step.memory_size as u64)),
        )?;
        self.state.state_write_counter.assign(
            region,
            offset,
            Some(F::from_u64(step.state_write_counter as u64)),
        )?;
        Ok(())
    }
}

pub(crate) type Preset<F> = (Cell<F>, F);
