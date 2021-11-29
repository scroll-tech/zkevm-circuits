use crate::{
    evm_circuit::{
        execution::bus_mapping_tmp,
        param::{STEP_HEIGHT, STEP_WIDTH},
        util::Cell,
    },
    util::Expr,
};
use halo2::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression},
};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ExecutionResult {
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
    AND,
    OR,
    XOR,
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
    pub(crate) fn amount() -> usize {
        Self::ErrorOutOfGasSTATICCALL as usize + 1
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
pub(crate) struct StepRow<F> {
    pub(crate) qs_byte_lookup: Cell<F>,
    pub(crate) cells: [Cell<F>; STEP_WIDTH],
}

#[derive(Clone)]
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
                VecDeque::with_capacity(ExecutionResult::amount() + 18);
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
        exec_trace: &bus_mapping_tmp::ExecTrace<F>,
        step_idx: usize,
    ) -> Result<(), Error> {
        let step = &exec_trace.steps[step_idx];
        let call = &exec_trace.calls[step.call_idx];

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
