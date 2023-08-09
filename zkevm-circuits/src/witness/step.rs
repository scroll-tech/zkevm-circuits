use bus_mapping::{
    circuit_input_builder,
    error::{
        ContractAddressCollisionError, DepthError, ExecError, InsufficientBalanceError,
        NonceUintOverflowError, OogError,
    },
    evm::OpcodeId,
    operation,
    precompile::{PrecompileAuxData, PrecompileCalls},
};

use crate::{
    evm_circuit::{
        param::{N_BYTES_WORD, STACK_CAPACITY},
        step::ExecutionState,
    },
    table::RwTableTag,
};

/// Step executed in a transaction
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecStep {
    /// The index in the Transaction calls
    pub call_index: usize,
    /// The indices in the RW trace incurred in this step
    pub rw_indices: Vec<(RwTableTag, usize)>,
    /// Number of rw operations performed via a copy event in this step.
    pub copy_rw_counter_delta: u64,
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
    /// The counter for reversible writes at the beginning of the step
    pub reversible_write_counter: usize,
    /// The number of reversible writes from this step
    pub reversible_write_counter_delta: usize,
    /// The counter for log index within tx
    pub log_id: usize,
    /// The opcode corresponds to the step
    pub opcode: Option<OpcodeId>,
    /// The block number in which this step exists.
    pub block_num: u64,
    /// Aux data used for precompiles
    pub aux_data: Option<PrecompileAuxData>,
}

impl ExecStep {
    /// The memory size in word **before** this step
    pub fn memory_word_size(&self) -> u64 {
        // EVM always pads the memory size to word size
        // https://github.com/ethereum/go-ethereum/blob/master/core/vm/interpreter.go#L212-L216
        // Thus, the memory size must be a multiple of 32 bytes.
        assert_eq!(self.memory_size % N_BYTES_WORD as u64, 0);
        self.memory_size / N_BYTES_WORD as u64
    }
}

impl From<&ExecError> for ExecutionState {
    fn from(error: &ExecError) -> Self {
        match error {
            ExecError::InvalidOpcode => ExecutionState::ErrorInvalidOpcode,
            ExecError::StackOverflow | ExecError::StackUnderflow => ExecutionState::ErrorStack,
            ExecError::WriteProtection => ExecutionState::ErrorWriteProtection,
            ExecError::Depth(depth_err) => match depth_err {
                DepthError::Call => ExecutionState::CALL_OP,
                DepthError::Create => ExecutionState::CREATE,
                DepthError::Create2 => ExecutionState::CREATE2,
            },
            ExecError::InsufficientBalance(insuff_balance_err) => match insuff_balance_err {
                InsufficientBalanceError::Call => ExecutionState::CALL_OP,
                InsufficientBalanceError::Create => ExecutionState::CREATE,
                InsufficientBalanceError::Create2 => ExecutionState::CREATE2,
            },
            ExecError::ContractAddressCollision(contract_addr_collision_err) => {
                match contract_addr_collision_err {
                    ContractAddressCollisionError::Create => ExecutionState::CREATE,
                    ContractAddressCollisionError::Create2 => ExecutionState::CREATE2,
                }
            }
            ExecError::NonceUintOverflow(nonce_overflow_err) => match nonce_overflow_err {
                NonceUintOverflowError::Create => ExecutionState::CREATE,
                NonceUintOverflowError::Create2 => ExecutionState::CREATE2,
            },
            ExecError::InvalidCreationCode => ExecutionState::ErrorInvalidCreationCode,
            ExecError::InvalidJump => ExecutionState::ErrorInvalidJump,
            ExecError::ReturnDataOutOfBounds => ExecutionState::ErrorReturnDataOutOfBound,
            ExecError::CodeStoreOutOfGas | ExecError::MaxCodeSizeExceeded => {
                ExecutionState::ErrorCodeStore
            }
            ExecError::PrecompileFailed => ExecutionState::ErrorPrecompileFailed,
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
                OogError::CodeStore => ExecutionState::ErrorCodeStore,
                OogError::Log => ExecutionState::ErrorOutOfGasLOG,
                OogError::Exp => ExecutionState::ErrorOutOfGasEXP,
                OogError::Sha3 => ExecutionState::ErrorOutOfGasSHA3,
                OogError::Call => ExecutionState::ErrorOutOfGasCall,
                OogError::SloadSstore => ExecutionState::ErrorOutOfGasSloadSstore,
                OogError::Create => ExecutionState::ErrorOutOfGasCREATE,
                OogError::SelfDestruct => ExecutionState::ErrorOutOfGasSELFDESTRUCT,
            },
        }
    }
}

impl From<&circuit_input_builder::ExecStep> for ExecutionState {
    fn from(step: &circuit_input_builder::ExecStep) -> Self {
        if let Some(error) = step.error.as_ref() {
            log::debug!("step err {:?}", error);
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

                macro_rules! dummy {
                    ($name:expr) => {{
                        log::warn!("{:?} is implemented with DummyGadget", $name);
                        $name
                    }};
                }

                match op {
                    OpcodeId::ADD | OpcodeId::SUB => ExecutionState::ADD_SUB,
                    OpcodeId::ADDMOD => ExecutionState::ADDMOD,
                    OpcodeId::ADDRESS => ExecutionState::ADDRESS,
                    OpcodeId::BALANCE => ExecutionState::BALANCE,
                    OpcodeId::MUL | OpcodeId::DIV | OpcodeId::MOD => ExecutionState::MUL_DIV_MOD,
                    OpcodeId::MULMOD => ExecutionState::MULMOD,
                    OpcodeId::SDIV | OpcodeId::SMOD => ExecutionState::SDIV_SMOD,
                    OpcodeId::EQ | OpcodeId::LT | OpcodeId::GT => ExecutionState::CMP,
                    OpcodeId::SLT | OpcodeId::SGT => ExecutionState::SCMP,
                    OpcodeId::SIGNEXTEND => ExecutionState::SIGNEXTEND,
                    OpcodeId::STOP => ExecutionState::STOP,
                    OpcodeId::AND => ExecutionState::BITWISE,
                    OpcodeId::XOR => ExecutionState::BITWISE,
                    OpcodeId::OR => ExecutionState::BITWISE,
                    OpcodeId::NOT => ExecutionState::NOT,
                    OpcodeId::EXP => ExecutionState::EXP,
                    OpcodeId::POP => ExecutionState::POP,
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
                    OpcodeId::EXTCODESIZE => ExecutionState::EXTCODESIZE,
                    OpcodeId::BLOCKHASH => ExecutionState::BLOCKHASH,
                    OpcodeId::TIMESTAMP | OpcodeId::NUMBER | OpcodeId::GASLIMIT => {
                        ExecutionState::BLOCKCTXU64
                    }
                    OpcodeId::COINBASE => ExecutionState::BLOCKCTXU160,
                    OpcodeId::DIFFICULTY | OpcodeId::BASEFEE => ExecutionState::BLOCKCTXU256,
                    OpcodeId::GAS => ExecutionState::GAS,
                    OpcodeId::SAR => ExecutionState::SAR,
                    OpcodeId::SELFBALANCE => ExecutionState::SELFBALANCE,
                    OpcodeId::SHA3 => ExecutionState::SHA3,
                    OpcodeId::SHL | OpcodeId::SHR => ExecutionState::SHL_SHR,
                    OpcodeId::SLOAD => ExecutionState::SLOAD,
                    OpcodeId::SSTORE => ExecutionState::SSTORE,
                    OpcodeId::CALLDATASIZE => ExecutionState::CALLDATASIZE,
                    OpcodeId::CALLDATACOPY => ExecutionState::CALLDATACOPY,
                    OpcodeId::CHAINID => ExecutionState::CHAINID,
                    OpcodeId::ISZERO => ExecutionState::ISZERO,
                    OpcodeId::CALL
                    | OpcodeId::CALLCODE
                    | OpcodeId::DELEGATECALL
                    | OpcodeId::STATICCALL => ExecutionState::CALL_OP,
                    OpcodeId::ORIGIN => ExecutionState::ORIGIN,
                    OpcodeId::CODECOPY => ExecutionState::CODECOPY,
                    OpcodeId::CALLDATALOAD => ExecutionState::CALLDATALOAD,
                    OpcodeId::CODESIZE => ExecutionState::CODESIZE,
                    OpcodeId::EXTCODECOPY => ExecutionState::EXTCODECOPY,
                    OpcodeId::RETURN | OpcodeId::REVERT => ExecutionState::RETURN_REVERT,
                    OpcodeId::RETURNDATASIZE => ExecutionState::RETURNDATASIZE,
                    OpcodeId::RETURNDATACOPY => ExecutionState::RETURNDATACOPY,
                    OpcodeId::CREATE => ExecutionState::CREATE,
                    OpcodeId::CREATE2 => ExecutionState::CREATE2,
                    // dummy ops
                    OpcodeId::SELFDESTRUCT => dummy!(ExecutionState::SELFDESTRUCT),
                    _ => unimplemented!("unimplemented opcode {:?}", op),
                }
            }
            circuit_input_builder::ExecState::Precompile(precompile) => match precompile {
                PrecompileCalls::Ecrecover => ExecutionState::PrecompileEcrecover,
                PrecompileCalls::Sha256 => ExecutionState::PrecompileSha256,
                PrecompileCalls::Ripemd160 => ExecutionState::PrecompileRipemd160,
                PrecompileCalls::Identity => ExecutionState::PrecompileIdentity,
                PrecompileCalls::Modexp => ExecutionState::PrecompileBigModExp,
                PrecompileCalls::Bn128Add => ExecutionState::PrecompileBn256Add,
                PrecompileCalls::Bn128Mul => ExecutionState::PrecompileBn256ScalarMul,
                PrecompileCalls::Bn128Pairing => ExecutionState::PrecompileBn256Pairing,
                PrecompileCalls::Blake2F => ExecutionState::PrecompileBlake2f,
            },
            circuit_input_builder::ExecState::BeginTx => ExecutionState::BeginTx,
            circuit_input_builder::ExecState::EndTx => ExecutionState::EndTx,
            circuit_input_builder::ExecState::EndBlock => ExecutionState::EndBlock,
        }
    }
}

pub(super) fn step_convert(step: &circuit_input_builder::ExecStep, block_num: u64) -> ExecStep {
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
                    operation::Target::CallContext => RwTableTag::CallContext,
                    operation::Target::TxReceipt => RwTableTag::TxReceipt,
                    operation::Target::TxLog => RwTableTag::TxLog,
                    operation::Target::Start => RwTableTag::Start,
                };
                (tag, x.as_usize())
            })
            .collect(),
        copy_rw_counter_delta: step.copy_rw_counter_delta,
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
        reversible_write_counter_delta: step.reversible_write_counter_delta,
        log_id: step.log_id,
        block_num,
        aux_data: step.aux_data.clone(),
    }
}
