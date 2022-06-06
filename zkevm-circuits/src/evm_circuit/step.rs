use super::util::{CachedRegion, CellManager, CellType};
use crate::{
    evm_circuit::{
        param::{MAX_STEP_HEIGHT, STEP_WIDTH},
        util::{Cell, RandomLinearCombination},
        witness::{Block, Call, CodeSource, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::ToLittleEndian;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression},
};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter)]
pub enum ExecutionState {
    // Internal state
    BeginTx,
    EndTx,
    EndBlock,
    CopyCodeToMemory,
    CopyToMemory,
    CopyToLog,
    // Opcode successful cases
    STOP,
    ADD_SUB,     // ADD, SUB
    MUL_DIV_MOD, // MUL, DIV, MOD
    SDIV,
    SMOD,
    ADDMOD,
    MULMOD,
    EXP,
    SIGNEXTEND,
    CMP,  // LT, GT, EQ
    SCMP, // SLT, SGT
    ISZERO,
    BITWISE, // AND, OR, XOR
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
    BLOCKCTXU64,  // TIMESTAMP, NUMBER, GASLIMIT
    BLOCKCTXU160, // COINBASE
    BLOCKCTXU256, // DIFFICULTY, BASEFEE
    CHAINID,
    SELFBALANCE,
    POP,
    MEMORY, // MLOAD, MSTORE, MSTORE8
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

    DUMMY,

    // Error cases
    ErrorInvalidOpcode,
    ErrorStackOverflow,
    ErrorStackUnderflow,
    ErrorWriteProtection,
    ErrorDepth,
    ErrorInsufficientBalance,
    ErrorContractAddressCollision,
    ErrorInvalidCreationCode,
    ErrorMaxCodeSizeExceeded,
    ErrorInvalidJump,
    ErrorReturnDataOutOfBound,
    ErrorOutOfGasConstant,
    ErrorOutOfGasStaticMemoryExpansion,
    ErrorOutOfGasDynamicMemoryExpansion,
    ErrorOutOfGasMemoryCopy,
    ErrorOutOfGasAccountAccess,
    ErrorOutOfGasCodeStore,
    ErrorOutOfGasLOG,
    ErrorOutOfGasEXP,
    ErrorOutOfGasSHA3,
    ErrorOutOfGasEXTCODECOPY,
    ErrorOutOfGasSLOAD,
    ErrorOutOfGasSSTORE,
    ErrorOutOfGasCALL,
    ErrorOutOfGasCALLCODE,
    ErrorOutOfGasDELEGATECALL,
    ErrorOutOfGasCREATE2,
    ErrorOutOfGasSTATICCALL,
    ErrorOutOfGasSELFDESTRUCT,
}

impl Default for ExecutionState {
    fn default() -> Self {
        Self::STOP
    }
}

impl ExecutionState {
    pub(crate) const fn as_u64(&self) -> u64 {
        *self as u64
    }

    pub(crate) fn amount() -> usize {
        Self::iter().count()
    }

    pub(crate) fn halts(&self) -> bool {
        matches!(
            self,
            Self::STOP
                | Self::RETURN
                | Self::REVERT
                | Self::SELFDESTRUCT
                | Self::ErrorInvalidOpcode
                | Self::ErrorStackOverflow
                | Self::ErrorStackUnderflow
                | Self::ErrorWriteProtection
                | Self::ErrorDepth
                | Self::ErrorInsufficientBalance
                | Self::ErrorContractAddressCollision
                | Self::ErrorInvalidCreationCode
                | Self::ErrorMaxCodeSizeExceeded
                | Self::ErrorInvalidJump
                | Self::ErrorReturnDataOutOfBound
                | Self::ErrorOutOfGasConstant
                | Self::ErrorOutOfGasStaticMemoryExpansion
                | Self::ErrorOutOfGasDynamicMemoryExpansion
                | Self::ErrorOutOfGasMemoryCopy
                | Self::ErrorOutOfGasAccountAccess
                | Self::ErrorOutOfGasCodeStore
                | Self::ErrorOutOfGasLOG
                | Self::ErrorOutOfGasEXP
                | Self::ErrorOutOfGasSHA3
                | Self::ErrorOutOfGasEXTCODECOPY
                | Self::ErrorOutOfGasSLOAD
                | Self::ErrorOutOfGasSSTORE
                | Self::ErrorOutOfGasCALL
                | Self::ErrorOutOfGasCALLCODE
                | Self::ErrorOutOfGasDELEGATECALL
                | Self::ErrorOutOfGasCREATE2
                | Self::ErrorOutOfGasSTATICCALL
                | Self::ErrorOutOfGasSELFDESTRUCT
        )
    }

    pub(crate) fn responsible_opcodes(&self) -> Vec<OpcodeId> {
        match self {
            Self::STOP => vec![OpcodeId::STOP],
            Self::ADD_SUB => vec![OpcodeId::ADD, OpcodeId::SUB],
            Self::MUL_DIV_MOD => vec![OpcodeId::MUL, OpcodeId::DIV, OpcodeId::MOD],
            Self::SDIV => vec![OpcodeId::SDIV],
            Self::SMOD => vec![OpcodeId::SMOD],
            Self::ADDMOD => vec![OpcodeId::ADDMOD],
            Self::MULMOD => vec![OpcodeId::MULMOD],
            Self::EXP => vec![OpcodeId::EXP],
            Self::SIGNEXTEND => vec![OpcodeId::SIGNEXTEND],
            Self::CMP => vec![OpcodeId::LT, OpcodeId::GT, OpcodeId::EQ],
            Self::SCMP => vec![OpcodeId::SLT, OpcodeId::SGT],
            Self::ISZERO => vec![OpcodeId::ISZERO],
            Self::BITWISE => vec![OpcodeId::AND, OpcodeId::OR, OpcodeId::XOR],
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
            Self::BLOCKCTXU64 => vec![OpcodeId::TIMESTAMP, OpcodeId::NUMBER, OpcodeId::GASLIMIT],
            Self::BLOCKCTXU160 => vec![OpcodeId::COINBASE],
            Self::BLOCKCTXU256 => vec![OpcodeId::DIFFICULTY, OpcodeId::BASEFEE],
            Self::CHAINID => vec![OpcodeId::CHAINID],
            Self::SELFBALANCE => vec![OpcodeId::SELFBALANCE],
            Self::POP => vec![OpcodeId::POP],
            Self::MEMORY => {
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
    /// The execution state for the step
    pub(crate) execution_state: Vec<Cell<F>>,
    /// The Read/Write counter
    pub(crate) rw_counter: Cell<F>,
    /// The unique identifier of call in the whole proof, using the
    /// `rw_counter` at the call step.
    pub(crate) call_id: Cell<F>,
    /// Whether the call is root call
    pub(crate) is_root: Cell<F>,
    /// Whether the call is a create call
    pub(crate) is_create: Cell<F>,
    /// Denotes the hash of the bytecode for the current call.
    /// In the case of a contract creation root call, this denotes the hash of
    /// the tx calldata.
    /// In the case of a contract creation internal call, this denotes the hash
    /// of the chunk of bytes from caller's memory that represent the
    /// contract init code.
    pub(crate) code_hash: Cell<F>,
    /// The program counter
    pub(crate) program_counter: Cell<F>,
    /// The stack pointer
    pub(crate) stack_pointer: Cell<F>,
    /// The amount of gas left
    pub(crate) gas_left: Cell<F>,
    /// Memory size in words (32 bytes)
    pub(crate) memory_word_size: Cell<F>,
    /// The counter for reversible writes
    pub(crate) reversible_write_counter: Cell<F>,
    /// The counter for log index
    pub(crate) log_id: Cell<F>,
}

#[derive(Clone, Debug)]
pub(crate) struct StepRow<F> {
    pub(crate) qs_byte_lookup: Cell<F>,
    pub(crate) cells: [Cell<F>; STEP_WIDTH],
}

#[derive(Clone, Debug)]
pub(crate) struct Step<F> {
    pub(crate) state: StepState<F>,
    pub(crate) cell_manager: CellManager<F>,
}

impl<F: FieldExt> Step<F> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; STEP_WIDTH],
        offset: usize,
    ) -> Self {
        let mut cell_manager = CellManager::new(meta, MAX_STEP_HEIGHT, &advices, offset);
        let state = {
            StepState {
                execution_state: cell_manager
                    .query_cells(CellType::Storage, ExecutionState::amount()),
                rw_counter: cell_manager.query_cell(CellType::Storage),
                call_id: cell_manager.query_cell(CellType::Storage),
                is_root: cell_manager.query_cell(CellType::Storage),
                is_create: cell_manager.query_cell(CellType::Storage),
                code_hash: cell_manager.query_cell(CellType::Storage),
                program_counter: cell_manager.query_cell(CellType::Storage),
                stack_pointer: cell_manager.query_cell(CellType::Storage),
                gas_left: cell_manager.query_cell(CellType::Storage),
                memory_word_size: cell_manager.query_cell(CellType::Storage),
                reversible_write_counter: cell_manager.query_cell(CellType::Storage),
                log_id: cell_manager.query_cell(CellType::Storage),
            }
        };
        Self {
            state,
            cell_manager,
        }
    }

    pub(crate) fn execution_state_selector(
        &self,
        execution_states: impl IntoIterator<Item = ExecutionState>,
    ) -> Expression<F> {
        execution_states
            .into_iter()
            .map(|execution_state| self.state.execution_state[execution_state as usize].expr())
            .reduce(|acc, expr| acc + expr)
            .expect("Select some ExecutionStates")
    }

    pub(crate) fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        for (idx, cell) in self.state.execution_state.iter().enumerate() {
            cell.assign(
                region,
                offset,
                Some(if idx == step.execution_state as usize {
                    F::one()
                } else {
                    F::zero()
                }),
            )?;
        }
        self.state
            .rw_counter
            .assign(region, offset, Some(F::from(step.rw_counter as u64)))?;
        self.state
            .call_id
            .assign(region, offset, Some(F::from(call.id as u64)))?;
        self.state
            .is_root
            .assign(region, offset, Some(F::from(call.is_root as u64)))?;
        self.state
            .is_create
            .assign(region, offset, Some(F::from(call.is_create as u64)))?;
        match call.code_source {
            CodeSource::Account(code_hash) => {
                self.state.code_hash.assign(
                    region,
                    offset,
                    Some(RandomLinearCombination::random_linear_combine(
                        code_hash.to_le_bytes(),
                        block.randomness,
                    )),
                )?;
            }
        }
        self.state.program_counter.assign(
            region,
            offset,
            Some(F::from(step.program_counter as u64)),
        )?;
        self.state.stack_pointer.assign(
            region,
            offset,
            Some(F::from(step.stack_pointer as u64)),
        )?;
        self.state
            .gas_left
            .assign(region, offset, Some(F::from(step.gas_left)))?;
        self.state.memory_word_size.assign(
            region,
            offset,
            Some(F::from(step.memory_word_size())),
        )?;
        self.state.reversible_write_counter.assign(
            region,
            offset,
            Some(F::from(step.reversible_write_counter as u64)),
        )?;
        self.state
            .log_id
            .assign(region, offset, Some(F::from(step.log_id as u64)))?;
        Ok(())
    }
}
