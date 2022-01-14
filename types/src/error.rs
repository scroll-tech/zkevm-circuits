//! Error module for the bus-mapping crate

use crate::eth_types::{Address, GethExecStep, Word};
use core::fmt::{Display, Formatter, Result as FmtResult};
use ethers_providers::ProviderError;
use std::error::Error as StdError;

/// Error type for any BusMapping related failure.
#[derive(Debug)]
pub enum Error {
    /// Error while parsing an `Instruction/Opcode`.
    OpcodeParsing,
    /// Error while parsing a `MemoryAddress`.
    MemAddressParsing,
    /// Error while parsing a `StackAddress`.
    StackAddressParsing,
    /// Error while trying to convert to an incorrect `OpcodeId`.
    InvalidOpConversion,
    /// Serde de/serialization error.
    SerdeError(serde_json::error::Error),
    /// Error while trying to access an invalid/empty Stack location.
    InvalidStackPointer,
    /// Error while trying to access an invalid/empty Memory location.
    InvalidMemoryPointer,
    /// Error while trying to access an invalid/empty Storage key.
    InvalidStorageKey,
    /// Error when an EvmWord is too big to be converted into a
    /// `MemoryAddress`.
    WordToMemAddr,
    /// Error while generating a trace.
    TracingError,
    /// JSON-RPC related error.
    JSONRpcError(ProviderError),
    /// OpcodeId is not a call type.
    OpcodeIdNotCallType,
    /// Account not found in the StateDB
    AccountNotFound(Address),
    /// Storage key not found in the StateDB
    StorageKeyNotFound(Address, Word),
    /// Unable to figure out error at a [`GethExecStep`]
    UnexpectedExecStepError(&'static str, Box<GethExecStep>),
    /// Invalid [`GethExecStep`] due to an invalid/unexpected value in it.
    InvalidGethExecStep(&'static str, Box<GethExecStep>),
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

/// Error type for a failure while parsig an Ethereum Address.
#[derive(Debug)]
pub enum EthAddressParsingError {
    /// Hex string containing the Ethereum Address is not 20*2 characters
    BadLength,
    /// Hex decoding error
    Hex(hex::FromHexError),
}
