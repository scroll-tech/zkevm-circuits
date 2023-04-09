//! Error module for the eth-types crate

use core::fmt::{Display, Formatter, Result as FmtResult};
use std::error::Error as StdError;

/// Error type for any BusMapping related failure.
#[derive(Debug)]
pub enum Error {
    /// Serde de/serialization error.
    SerdeError(serde_json::error::Error),
    /// Error while generating a trace.
    TracingError(String),
    /// Block is missing information about number or base_fee
    IncompleteBlock,
    /// Denotes that the byte in the bytecode does not match with any Opcode ID.
    InvalidOpcodeIdByte(u8),
    /// Error while parsing an `Instruction/Opcode`.
    OpcodeParsing(String),
    /// Error while parsing a `MemoryAddress`.
    MemAddressParsing,
    /// Error while parsing a `StackAddress`.
    StackAddressParsing,
    /// Error while trying to convert to an incorrect `OpcodeId`.
    InvalidOpConversion,
    /// Error while trying to access an invalid/empty Stack location.
    InvalidStackPointer,
    /// Error while trying to access an invalid/empty Memory location.
    InvalidMemoryPointer,
    /// Error while trying to access an invalid/empty Storage key.
    InvalidStorageKey,
    /// Error when an EvmWord is too big to be converted into a
    /// `MemoryAddress`.
    WordToMemAddr,
    /// Signature parsing error.
    Signature(libsecp256k1::Error),
}

impl From<libsecp256k1::Error> for Error {
    fn from(err: libsecp256k1::Error) -> Self {
        Error::Signature(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{:?}", self)
    }
}

impl StdError for Error {}

/// Error type for a failure while parsing an Ethereum Address.
#[derive(Debug)]
pub enum EthAddressParsingError {
    /// Hex string containing the Ethereum Address is not 20*2 characters
    BadLength,
    /// Hex decoding error
    Hex(hex::FromHexError),
}
