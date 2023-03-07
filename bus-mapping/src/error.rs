//! Error module for the bus-mapping crate

use core::fmt::{Display, Formatter, Result as FmtResult};
use eth_types::{evm_types::OpcodeId, Address, GethExecStep, Word, H256};
use ethers_providers::ProviderError;
use std::error::Error as StdError;

use crate::geth_errors::{
    GETH_ERR_GAS_UINT_OVERFLOW, GETH_ERR_OUT_OF_GAS, GETH_ERR_STACK_OVERFLOW,
    GETH_ERR_STACK_UNDERFLOW,
};

/// Error type for any BusMapping related failure.
#[derive(Debug)]
pub enum Error {
    /// Serde de/serialization error.
    SerdeError(serde_json::error::Error),
    /// JSON-RPC related error.
    JSONRpcError(ProviderError),
    /// OpcodeId is not a call type.
    OpcodeIdNotCallType,
    /// Account not found in the StateDB
    AccountNotFound(Address),
    /// Storage key not found in the StateDB
    StorageKeyNotFound(Address, Word),
    /// Address not found in the CodeDB,
    AddressNotFound(Address),
    /// Code not found in the CodeDB
    CodeNotFound(H256),
    /// Unable to figure out error at a [`GethExecStep`]
    UnexpectedExecStepError(&'static str, GethExecStep),
    /// Invalid [`eth_types::GethExecTrace`] due to an invalid/unexpected value
    /// in it.
    InvalidGethExecTrace(&'static str),
    /// Invalid [`GethExecStep`] due to an invalid/unexpected value in it.
    InvalidGethExecStep(&'static str, GethExecStep),
    /// Eth type related error.
    EthTypeError(eth_types::Error),
    /// EVM Execution error
    ExecutionError(ExecError),
    /// Internal Code error
    InternalError(&'static str),
}

impl From<eth_types::Error> for Error {
    fn from(err: eth_types::Error) -> Self {
        Error::EthTypeError(err)
    }
}

impl From<ProviderError> for Error {
    fn from(err: ProviderError) -> Self {
        Error::JSONRpcError(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self)
    }
}

impl StdError for Error {}

/// Out of Gas errors by opcode
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OogError {
    /// Out of Gas for opcodes which have non-zero constant gas cost
    Constant,
    /// Out of Gas for MLOAD, MSTORE, MSTORE8, which have static memory
    /// expansion gas cost
    StaticMemoryExpansion,
    /// Out of Gas for CREATE, RETURN, REVERT, which have dynamic memory
    /// expansion gas cost
    DynamicMemoryExpansion,
    /// Out of Gas for CALLDATACOPY, CODECOPY, EXTCODECOPY, RETURNDATACOPY,
    /// which copy a specified chunk of memory
    MemoryCopy,
    /// Out of Gas for BALANCE, EXTCODESIZE, EXTCODEHASH, which possibly touch
    /// an extra account
    AccountAccess,
    /// Out of Gas for RETURN which has code storing gas cost when it's is
    /// creation
    CodeStore,
    /// Out of Gas for LOG0, LOG1, LOG2, LOG3, LOG4
    Log,
    /// Out of Gas for EXP
    Exp,
    /// Out of Gas for SHA3
    Sha3,
    /// Out of Gas for SLOAD and SSTORE
    SloadSstore,
    /// Out of Gas for CALL, CALLCODE, DELEGATECALL and STATICCALL
    Call,
    /// Out of Gas for CREATE2
    Create2,
    /// Out of Gas for SELFDESTRUCT
    SelfDestruct,
}

/// EVM Execution Error
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecError {
    /// Invalid Opcode
    InvalidOpcode,
    /// For opcodes who push more than pop
    StackOverflow,
    /// For opcodes which pop, DUP and SWAP, which peek deeper element directly
    StackUnderflow,
    /// Out of Gas
    OutOfGas(OogError),
    /// For SSTORE, LOG0, LOG1, LOG2, LOG3, LOG4, CREATE, CALL, CREATE2,
    /// SELFDESTRUCT
    WriteProtection,
    /// For CALL, CALLCODE, DELEGATECALL, STATICCALL
    Depth,
    /// For CALL, CALLCODE
    InsufficientBalance,
    /// For CREATE, CREATE2
    ContractAddressCollision,
    /// contract must not begin with 0xef due to EIP #3541 EVM Object Format
    /// (EOF)
    InvalidCreationCode,
    /// For JUMP, JUMPI
    InvalidJump,
    /// For RETURNDATACOPY
    ReturnDataOutOfBounds,
    /// For RETURN in a CREATE, CREATE2
    CodeStoreOutOfGas,
    /// For RETURN in a CREATE, CREATE2
    MaxCodeSizeExceeded,
    /// For CALL, CALLCODE, DELEGATECALL, STATICCALL
    PrecompileFailed,
}

// TODO: Move to impl block.
pub(crate) fn get_step_reported_error(op: &OpcodeId, error: &str) -> ExecError {
    if error == GETH_ERR_OUT_OF_GAS || error == GETH_ERR_GAS_UINT_OVERFLOW {
        // NOTE: We report a GasUintOverflow error as an OutOfGas error
        let oog_err = match op {
            OpcodeId::MLOAD | OpcodeId::MSTORE | OpcodeId::MSTORE8 => {
                OogError::StaticMemoryExpansion
            }
            OpcodeId::CREATE | OpcodeId::RETURN | OpcodeId::REVERT => {
                OogError::DynamicMemoryExpansion
            }
            OpcodeId::CALLDATACOPY
            | OpcodeId::CODECOPY
            | OpcodeId::EXTCODECOPY
            | OpcodeId::RETURNDATACOPY => OogError::MemoryCopy,
            OpcodeId::BALANCE | OpcodeId::EXTCODESIZE | OpcodeId::EXTCODEHASH => {
                OogError::AccountAccess
            }
            OpcodeId::LOG0 | OpcodeId::LOG1 | OpcodeId::LOG2 | OpcodeId::LOG3 | OpcodeId::LOG4 => {
                OogError::Log
            }
            OpcodeId::EXP => OogError::Exp,
            OpcodeId::SHA3 => OogError::Sha3,
            OpcodeId::CALL | OpcodeId::CALLCODE | OpcodeId::DELEGATECALL | OpcodeId::STATICCALL => {
                OogError::Call
            }
            OpcodeId::SLOAD | OpcodeId::SSTORE => OogError::SloadSstore,
            OpcodeId::CREATE2 => OogError::Create2,
            OpcodeId::SELFDESTRUCT => OogError::SelfDestruct,
            _ => OogError::Constant,
        };
        ExecError::OutOfGas(oog_err)
    } else if error.starts_with(GETH_ERR_STACK_OVERFLOW) {
        ExecError::StackOverflow
    } else if error.starts_with(GETH_ERR_STACK_UNDERFLOW) {
        ExecError::StackUnderflow
    } else {
        panic!("Unknown GethExecStep.error: {}", error);
    }
}
