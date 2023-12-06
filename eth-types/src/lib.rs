//! Ethereum and Evm types used to deserialize responses from web3 / geth.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Temporary until we have more of the crate implemented.
#![allow(dead_code)]
#![allow(incomplete_features)]
// We want to have UPPERCASE idents sometimes.
#![allow(non_snake_case)]
#![allow(incomplete_features)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
// GasCost is used as type parameter
#![feature(adt_const_params)]
#![feature(lazy_cell)]
#![deny(missing_docs)]
//#![deny(unsafe_code)] Allowed now until we find a
// better way to handle downcasting from Operation into it's variants.
#![allow(clippy::upper_case_acronyms)] // Too pedantic

#[macro_use]
pub mod macros;
#[macro_use]
pub mod error;
#[macro_use]
pub mod bytecode;
pub mod evm_types;
pub mod geth_types;
pub mod l2_types;
pub mod sign_types;

pub use bytecode::Bytecode;
pub use error::Error;
use halo2_base::utils::ScalarField;
use halo2_proofs::halo2curves::{bn256::Fr, group::ff::PrimeField};

use crate::evm_types::{Gas, GasCost, OpcodeId, ProgramCounter};
use ethers_core::types;
pub use ethers_core::{
    abi::ethereum_types::{BigEndianHash, U512},
    types::{
        transaction::{eip2930::AccessList, response::Transaction},
        Address, Block, Bytes, Signature, H160, H256, H64, U256, U64,
    },
};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::{
    collections::HashMap,
    fmt,
    fmt::{Display, Formatter},
    str::FromStr,
    sync::LazyLock,
};

#[cfg(feature = "enable-memory")]
use crate::evm_types::Memory;
#[cfg(feature = "enable-stack")]
use crate::evm_types::Stack;
#[cfg(feature = "enable-storage")]
use crate::evm_types::Storage;

/// Trait used to reduce verbosity with the declaration of the [`Field`]
/// trait and its repr.
pub trait Field:
    PrimeField<Repr = [u8; 32]> + hash_circuit::hash::Hashable + std::convert::From<Fr> + ScalarField
{
    /// Re-expose zero element as a function
    fn zero() -> Self {
        Self::ZERO
    }

    /// Re-expose one element as a function
    fn one() -> Self {
        Self::ONE
    }

    /// Expose the lower 128 bits
    fn get_lower_128(&self) -> u128 {
        u128::from_le_bytes(self.to_repr().as_ref()[..16].try_into().unwrap())
    }
}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

// Impl custom `Field` trait for BN256 Fq to be used and consistent with the
// rest of the workspace.
// impl Field for Fq {}

/// Trait used to define types that can be converted to a 256 bit scalar value.
pub trait ToScalar<F> {
    /// Convert the type to a scalar value.
    fn to_scalar(&self) -> Option<F>;
}

/// Trait used to convert a type to a [`Word`].
pub trait ToWord {
    /// Convert the type to a [`Word`].
    fn to_word(&self) -> Word;
}

/// Trait used to convert a type to a [`Address`].
pub trait ToAddress {
    /// Convert the type to a [`Address`].
    fn to_address(&self) -> Address;
}

/// Trait used do convert a scalar value to a 32 byte array in big endian.
pub trait ToBigEndian {
    /// Convert the value to a 32 byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32];
}

/// Trait used to convert a scalar value to a 32 byte array in little endian.
pub trait ToLittleEndian {
    /// Convert the value to a 32 byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32];
}

/// Trait used to convert a scalar value to a 16x u16 array in little endian.
pub trait ToU16LittleEndian {
    /// Convert the value to a 16x u16 array in little endian.
    fn to_le_u16_array(&self) -> [u16; 16];
}

// We use our own declaration of another U256 in order to implement a custom
// deserializer that can parse U256 when returned by structLogs fields in geth
// debug_trace* methods, which don't contain the `0x` prefix.
#[allow(clippy::all)]
mod uint_types {
    uint::construct_uint! {
        /// 256-bit unsigned integer.
        pub struct DebugU256(4);
    }
}
pub use uint_types::DebugU256;

impl<'de> Deserialize<'de> for DebugU256 {
    fn deserialize<D>(deserializer: D) -> Result<DebugU256, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DebugU256::from_str(&s).map_err(de::Error::custom)
    }
}

impl<F: Field> ToScalar<F> for DebugU256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl ToBigEndian for DebugU256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToWord for DebugU256 {
    fn to_word(&self) -> Word {
        U256(self.0)
    }
}

/// Ethereum Word (256 bits).
pub type Word = U256;

impl ToBigEndian for U256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToLittleEndian for U256 {
    /// Encode the value as byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        bytes
    }
}

impl ToU16LittleEndian for U256 {
    /// Encode the value as 16x u16 array in little endian.
    ///
    /// eg. 0xaabb_ccdd_eeff_0011_2233_4455_6677_8899_bbaa_ddcc_ffee_1100_3322_5544_7766_9988
    /// -> [
    ///     0x9988, 0x7766, 0x5544, 0x3322, 0x1100, 0xffee, 0xddcc, 0xbbaa,
    ///     0x8899, 0x6677, 0x4455, 0x2233, 0x0011, 0xeeff, 0xccdd, 0xaabb,
    ///   ]
    fn to_le_u16_array(&self) -> [u16; 16] {
        let mut u16_array: [u16; 16] = [0; 16];
        for (idx, u64_cell) in self.0.into_iter().enumerate() {
            u16_array[idx * 4] = (u64_cell & 0xffff) as u16;
            u16_array[idx * 4 + 1] = ((u64_cell >> 16) & 0xffff) as u16;
            u16_array[idx * 4 + 2] = ((u64_cell >> 32) & 0xffff) as u16;
            u16_array[idx * 4 + 3] = ((u64_cell >> 48) & 0xffff) as u16;
        }
        u16_array
    }
}

impl<F: Field> ToScalar<F> for U256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl ToAddress for U256 {
    fn to_address(&self) -> Address {
        Address::from_slice(&self.to_be_bytes()[12..])
    }
}

/// Ethereum Hash (256 bits).
pub type Hash = types::H256;

impl ToWord for Hash {
    fn to_word(&self) -> Word {
        Word::from(self.as_bytes())
    }
}

impl ToWord for Address {
    fn to_word(&self) -> Word {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        Word::from(bytes)
    }
}

impl ToWord for bool {
    fn to_word(&self) -> Word {
        if *self {
            Word::one()
        } else {
            Word::zero()
        }
    }
}

impl ToWord for u64 {
    fn to_word(&self) -> Word {
        Word::from(*self)
    }
}

impl ToWord for u128 {
    fn to_word(&self) -> Word {
        Word::from(*self)
    }
}

impl ToWord for usize {
    fn to_word(&self) -> Word {
        u64::try_from(*self)
            .expect("usize bigger than u64")
            .to_word()
    }
}

impl ToWord for i32 {
    fn to_word(&self) -> Word {
        let value = Word::from(self.unsigned_abs() as u64);
        if self.is_negative() {
            value.overflowing_neg().0
        } else {
            value
        }
    }
}

impl ToWord for Word {
    fn to_word(&self) -> Word {
        *self
    }
}

impl<F: Field> ToScalar<F> for Address {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        bytes.reverse();
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for bool {
    fn to_scalar(&self) -> Option<F> {
        self.to_word().to_scalar()
    }
}

impl<F: Field> ToScalar<F> for u64 {
    fn to_scalar(&self) -> Option<F> {
        Some(F::from(*self))
    }
}

impl<F: Field> ToScalar<F> for usize {
    fn to_scalar(&self) -> Option<F> {
        u64::try_from(*self).ok().map(F::from)
    }
}

/// Code hash related
/// the empty keccak code hash
pub static KECCAK_CODE_HASH_EMPTY: LazyLock<Hash> = LazyLock::new(|| {
    Hash::from_str("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap()
});
/// the empty poseidon code hash
pub static POSEIDON_CODE_HASH_EMPTY: LazyLock<Hash> = LazyLock::new(|| {
    Hash::from_str("0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864").unwrap()
});
/// Struct used to define the storage proof
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct StorageProof {
    /// Storage key
    pub key: U256,
    /// Storage Value
    pub value: U256,
    /// Storage proof: rlp-encoded trie nodes from root to value.
    pub proof: Vec<Bytes>,
}

/// Struct used to define the result of `eth_getProof` call
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EIP1186ProofResponse {
    /// Account address
    pub address: Address,
    /// The balance of the account
    pub balance: U256,
    /// The keccak hash of the code of the account
    #[serde(default)]
    pub keccak_code_hash: H256,
    /// The poseidon hash of the code of the account
    #[serde(alias = "poseidonCodeHash")]
    pub code_hash: H256,
    /// Size of the code, i.e. code length
    #[serde(default)]
    pub code_size: U256,
    /// The nonce of the account
    pub nonce: U256,
    /// SHA3 of the StorageRoot
    pub storage_hash: H256,
    /// Array of rlp-serialized MerkleTree-Nodes
    pub account_proof: Vec<Bytes>,
    /// Array of storage-entries as requested
    pub storage_proof: Vec<StorageProof>,
}

#[derive(Deserialize)]
#[doc(hidden)]
struct GethExecStepInternal {
    pc: ProgramCounter,
    op: OpcodeId,
    gas: Gas,
    #[serde(default)]
    refund: Gas,
    #[serde(rename = "gasCost")]
    gas_cost: GasCost,
    depth: u16,
    error: Option<GethExecError>,
    // stack is in hex 0x prefixed
    #[cfg(feature = "enable-stack")]
    #[serde(default)]
    stack: Vec<DebugU256>,
    // memory is in chunks of 32 bytes, in hex
    #[cfg(feature = "enable-memory")]
    #[serde(default)]
    memory: Vec<DebugU256>,
    // storage is hex -> hex
    #[cfg(feature = "enable-storage")]
    #[serde(default)]
    storage: HashMap<DebugU256, DebugU256>,
}

/// The execution step type returned by geth RPC debug_trace* methods.
/// Corresponds to `StructLogRes` in `go-ethereum/internal/ethapi/api.go`.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[doc(hidden)]
pub struct GethExecStep {
    pub pc: ProgramCounter,
    pub op: OpcodeId,
    pub gas: Gas,
    pub gas_cost: GasCost,
    pub refund: Gas,
    pub depth: u16,
    pub error: Option<GethExecError>,
    // stack is in hex 0x prefixed
    #[cfg(feature = "enable-stack")]
    pub stack: Stack,
    // memory is in chunks of 32 bytes, in hex
    #[cfg(feature = "enable-memory")]
    pub memory: Memory,
    // storage is hex -> hex
    #[cfg(feature = "enable-storage")]
    pub storage: Storage,
}

/// Errors of StructLogger Result from Geth
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum GethExecError {
    /// out of gas
    OutOfGas,
    /// contract creation code storage out of gas
    CodeStoreOutOfGas,
    /// max call depth exceeded
    Depth,
    /// insufficient balance for transfer
    InsufficientBalance,
    /// contract address collision
    ContractAddressCollision,
    /// execution reverted
    ExecutionReverted,
    /// max initcode size exceeded
    MaxInitCodeSizeExceeded,
    /// max code size exceeded
    MaxCodeSizeExceeded,
    /// invalid jump destination
    InvalidJump,
    /// write protection
    WriteProtection,
    /// return data out of bounds
    ReturnDataOutOfBounds,
    /// gas uint64 overflow
    GasUintOverflow,
    /// invalid code: must not begin with 0xef
    InvalidCode,
    /// nonce uint64 overflow
    NonceUintOverflow,
    /// stack underflow
    StackUnderflow {
        /// stack length
        stack_len: u64,
        /// required length
        required: u64,
    },
    /// stack limit reached
    StackOverflow {
        /// stack length
        stack_len: u64,
        /// stack limit
        limit: u64,
    },
    /// invalid opcode
    InvalidOpcode(OpcodeId),
}

impl GethExecError {
    /// Returns the error as a string constant.
    pub fn error(self) -> &'static str {
        match self {
            GethExecError::OutOfGas => "out of gas",
            GethExecError::CodeStoreOutOfGas => "contract creation code storage out of gas",
            GethExecError::Depth => "max call depth exceeded",
            GethExecError::InsufficientBalance => "insufficient balance for transfer",
            GethExecError::ContractAddressCollision => "contract address collision",
            GethExecError::ExecutionReverted => "execution reverted",
            GethExecError::MaxInitCodeSizeExceeded => "max initcode size exceeded",
            GethExecError::MaxCodeSizeExceeded => "max code size exceeded",
            GethExecError::InvalidJump => "invalid jump destination",
            GethExecError::WriteProtection => "write protection",
            GethExecError::ReturnDataOutOfBounds => "return data out of bounds",
            GethExecError::GasUintOverflow => "gas uint64 overflow",
            GethExecError::InvalidCode => "invalid code: must not begin with 0xef",
            GethExecError::NonceUintOverflow => "nonce uint64 overflow",
            GethExecError::StackUnderflow { .. } => "stack underflow",
            GethExecError::StackOverflow { .. } => "stack limit reached",
            GethExecError::InvalidOpcode(_) => "invalid opcode",
        }
    }
}

impl Display for GethExecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            GethExecError::StackUnderflow {
                stack_len,
                required,
            } => {
                write!(f, "stack underflow ({stack_len} <=> {required})")
            }
            GethExecError::StackOverflow { stack_len, limit } => {
                write!(f, "stack limit reached {stack_len} ({limit})")
            }
            GethExecError::InvalidOpcode(op) => {
                write!(f, "invalid opcode: {op}")
            }
            _ => f.write_str(self.error()),
        }
    }
}

impl Serialize for GethExecError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // We serialize the error as a string constant.
        serializer.serialize_str(self.error())
    }
}

impl<'de> Deserialize<'de> for GethExecError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GethExecErrorVisitor;

        static STACK_UNDERFLOW_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"^stack underflow \((\d+) <=> (\d+)\)$").unwrap());
        static STACK_OVERFLOW_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"^stack limit reached (\d+) \((\d+)\)$").unwrap());

        impl<'de> de::Visitor<'de> for GethExecErrorVisitor {
            type Value = GethExecError;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                write!(formatter, "a geth struct logger error string constant")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let e = match v {
                    "out of gas" => GethExecError::OutOfGas,
                    "contract creation code storage out of gas" => GethExecError::CodeStoreOutOfGas,
                    "max call depth exceeded" => GethExecError::Depth,
                    "insufficient balance for transfer" => GethExecError::InsufficientBalance,
                    "contract address collision" => GethExecError::ContractAddressCollision,
                    "execution reverted" => GethExecError::ExecutionReverted,
                    "max initcode size exceeded" => GethExecError::MaxInitCodeSizeExceeded,
                    "max code size exceeded" => GethExecError::MaxCodeSizeExceeded,
                    "invalid jump destination" => GethExecError::InvalidJump,
                    "write protection" => GethExecError::WriteProtection,
                    "return data out of bounds" => GethExecError::ReturnDataOutOfBounds,
                    "gas uint64 overflow" => GethExecError::GasUintOverflow,
                    "invalid code: must not begin with 0xef" => GethExecError::InvalidCode,
                    "nonce uint64 overflow" => GethExecError::NonceUintOverflow,
                    _ if v.starts_with("stack underflow") => {
                        let caps = STACK_UNDERFLOW_RE.captures(v).unwrap();
                        let stack_len = caps.get(1).unwrap().as_str().parse::<u64>().unwrap();
                        let required = caps.get(2).unwrap().as_str().parse::<u64>().unwrap();
                        GethExecError::StackUnderflow {
                            stack_len,
                            required,
                        }
                    }
                    _ if v.starts_with("stack limit reached") => {
                        let caps = STACK_OVERFLOW_RE.captures(v).unwrap();
                        let stack_len = caps.get(1).unwrap().as_str().parse::<u64>().unwrap();
                        let limit = caps.get(2).unwrap().as_str().parse::<u64>().unwrap();
                        GethExecError::StackOverflow { stack_len, limit }
                    }
                    _ if v.starts_with("invalid opcode") => v
                        .strip_prefix("invalid opcode: ")
                        .map(|s| OpcodeId::from_str(s).unwrap())
                        .map(GethExecError::InvalidOpcode)
                        .unwrap(),
                    _ => return Err(E::invalid_value(de::Unexpected::Str(v), &self)),
                };
                Ok(e)
            }
        }

        deserializer.deserialize_str(GethExecErrorVisitor)
    }
}

// Wrapper over u8 that provides formats the byte in hex for [`fmt::Debug`].
pub(crate) struct DebugByte(pub(crate) u8);

impl fmt::Debug for DebugByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:02x}", self.0))
    }
}

// Wrapper over Word reference that provides formats the word in hex for
// [`fmt::Debug`].
pub(crate) struct DebugWord<'a>(pub(crate) &'a Word);

impl<'a> fmt::Debug for DebugWord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("0x{:x}", self.0))
    }
}

impl fmt::Debug for GethExecStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("Step");
        f.field("pc", &format_args!("0x{:04x}", self.pc.0))
            .field("op", &self.op)
            .field("gas", &format_args!("{}", self.gas.0))
            .field("gas_cost", &format_args!("{}", self.gas_cost.0))
            .field("refund", &format_args!("{}", self.refund.0))
            .field("depth", &self.depth)
            .field("error", &self.error);
        #[cfg(feature = "enable-stack")]
        f.field("stack", &self.stack);
        #[cfg(feature = "enable-memory")]
        f.field("memory", &self.memory);
        #[cfg(feature = "enable-storage")]
        f.field("storage", &self.storage);
        f.finish()
    }
}

impl<'de> Deserialize<'de> for GethExecStep {
    fn deserialize<D>(deserializer: D) -> Result<GethExecStep, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = GethExecStepInternal::deserialize(deserializer)?;
        Ok(Self {
            pc: s.pc,
            op: s.op,
            gas: s.gas,
            refund: s.refund,
            gas_cost: s.gas_cost,
            depth: s.depth,
            error: s.error,
            #[cfg(feature = "enable-stack")]
            stack: Stack(s.stack.iter().map(|dw| dw.to_word()).collect::<Vec<Word>>()),
            #[cfg(feature = "enable-memory")]
            memory: Memory::from(
                s.memory
                    .iter()
                    .map(|dw| dw.to_word())
                    .collect::<Vec<Word>>(),
            ),
            #[cfg(feature = "enable-storage")]
            storage: Storage(
                s.storage
                    .iter()
                    .map(|(k, v)| (k.to_word(), v.to_word()))
                    .collect(),
            ),
        })
    }
}

/// Helper type built to deal with the weird `result` field added between
/// `GethExecutionTrace`s in `debug_traceBlockByHash` and
/// `debug_traceBlockByNumber` Geth JSON-RPC calls.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[doc(hidden)]
pub struct ResultGethExecTraces(pub Vec<ResultGethExecTrace>);

/// Helper type built to deal with the weird `result` field added between
/// `GethExecutionTrace`s in `debug_traceBlockByHash` and
/// `debug_traceBlockByNumber` Geth JSON-RPC calls.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[doc(hidden)]
pub struct ResultGethExecTrace {
    pub result: GethExecTrace,
}

/// The execution trace type returned by geth RPC debug_trace* methods.
/// Corresponds to `ExecutionResult` in `go-ethereum/internal/ethapi/api.go`.
/// The deserialization truncates the memory of each step in `struct_logs` to
/// the memory size before the expansion, so that it corresponds to the memory
/// before the step is executed.
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
pub struct GethExecTrace {
    /// L1 fee
    #[serde(default)]
    pub l1_fee: u64,
    /// Used gas
    pub gas: Gas,
    /// True when the transaction has failed.
    pub failed: bool,
    /// Return value of execution which is a hex encoded byte array
    #[serde(rename = "returnValue")]
    pub return_value: String,
    /// Vector of geth execution steps of the trace.
    #[serde(rename = "structLogs")]
    pub struct_logs: Vec<GethExecStep>,
    #[serde(
        rename = "accountAfter",
        default,
        deserialize_with = "parse_account_after"
    )]
    /// List of accounts' (coinbase etc) status AFTER execution
    /// Only viable for scroll mode
    pub account_after: Vec<crate::l2_types::AccountProofWrapper>,
}

fn parse_account_after<'de, D>(d: D) -> Result<Vec<crate::l2_types::AccountProofWrapper>, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(d).map(|x: Option<_>| x.unwrap_or_default())
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[doc(hidden)]
pub struct ResultGethPrestateTraces(pub Vec<ResultGethPrestateTrace>);

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[doc(hidden)]
pub struct ResultGethPrestateTrace {
    #[serde(rename = "txHash", default)]
    pub tx_hash: H256,
    pub result: HashMap<Address, GethPrestateTrace>,
}

/// The prestate trace returned by geth RPC debug_trace* methods.
#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GethPrestateTrace {
    /// balance
    pub balance: Option<U256>,
    /// nonce
    pub nonce: Option<u64>,
    /// code
    pub code: Option<Bytes>,
    /// storage
    pub storage: Option<HashMap<U256, U256>>,
}

#[macro_export]
/// Create an [`Address`] from a hex string.  Panics on invalid input.
macro_rules! address {
    ($addr_hex:expr) => {{
        use std::str::FromStr;
        $crate::Address::from_str(&$addr_hex).expect("invalid hex Address")
    }};
}

#[macro_export]
/// Create a [`Word`] from a hex string.  Panics on invalid input.
macro_rules! word {
    ($word_hex:expr) => {
        $crate::Word::from_str_radix(&$word_hex, 16).expect("invalid hex Word")
    };
}

#[macro_export]
/// Create a [`Word`] to [`Word`] HashMap from pairs of hex strings.  Panics on
/// invalid input.
macro_rules! word_map {
    () => {
        std::collections::HashMap::new()
    };
    ($($key_hex:expr => $value_hex:expr),*) => {
        {
            std::collections::HashMap::from_iter([(
                    $(word!($key_hex), word!($value_hex)),*
            )])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm_types::{opcode_ids::OpcodeId, stack::Stack};

    #[cfg(feature = "enable-memory")]
    use crate::evm_types::memory::Memory;

    #[test]
    fn test_to_u16_array() {
        assert_eq!(
            U256::from_str("0xaabbccddeeff00112233445566778899bbaaddccffee11003322554477669988")
                .unwrap()
                .to_le_u16_array(),
            [
                0x9988, 0x7766, 0x5544, 0x3322, 0x1100, 0xffee, 0xddcc, 0xbbaa, 0x8899, 0x6677,
                0x4455, 0x2233, 0x0011, 0xeeff, 0xccdd, 0xaabb
            ]
        );
    }

    #[test]
    fn deserialize_geth_exec_trace2() {
        let trace_json = r#"
  {
    "gas": 26809,
    "failed": false,
    "returnValue": "",
    "structLogs": [
      {
        "pc": 0,
        "op": "PUSH1",
        "gas": 22705,
        "gasCost": 3,
        "refund": 0,
        "depth": 1,
        "stack": []
      },
      {
        "pc": 163,
        "op": "SLOAD",
        "gas": 5217,
        "gasCost": 2100,
        "refund": 0,
        "depth": 1,
        "stack": [
          "0x1003e2d2",
          "0x2a",
          "0x0"
        ],
        "storage": {
          "0000000000000000000000000000000000000000000000000000000000000000": "000000000000000000000000000000000000000000000000000000000000006f"
        },
        "memory": [
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000080"
        ]
      },
      {
        "pc": 189,
        "op": "KECCAK256",
        "gas": 178805,
        "gasCost": 42,
        "refund": 0,
        "depth": 1,
        "stack": [
            "0x3635c9adc5dea00000",
            "0x40",
            "0x0"
        ],
        "memory": [
            "000000000000000000000000b8f67472dcc25589672a61905f7fd63f09e5d470",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000000000a0",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000003635c9adc5dea00000",
            "00000000000000000000000000000000000000000000003635c9adc5dea00000"
        ]
      }
    ]
  }
        "#;
        let trace: GethExecTrace =
            serde_json::from_str(trace_json).expect("json-deserialize GethExecTrace");
        assert_eq!(
            trace,
            GethExecTrace {
                l1_fee: 0,
                gas: Gas(26809),
                failed: false,
                return_value: "".to_owned(),
                account_after: Vec::new(),
                struct_logs: vec![
                    GethExecStep {
                        pc: ProgramCounter(0),
                        op: OpcodeId::PUSH1,
                        gas: Gas(22705),
                        refund: Gas(0),
                        gas_cost: GasCost(3),
                        depth: 1,
                        error: None,
                        #[cfg(feature = "enable-stack")]
                        stack: Stack::new(),
                        #[cfg(feature = "enable-storage")]
                        storage: Storage(word_map!()),
                        #[cfg(feature = "enable-memory")]
                        memory: Memory::new(),
                    },
                    GethExecStep {
                        pc: ProgramCounter(163),
                        op: OpcodeId::SLOAD,
                        gas: Gas(5217),
                        refund: Gas(0),
                        gas_cost: GasCost(2100),
                        depth: 1,
                        error: None,
                        #[cfg(feature = "enable-stack")]
                        stack: Stack(vec![word!("0x1003e2d2"), word!("0x2a"), word!("0x0")]),
                        #[cfg(feature = "enable-storage")]
                        storage: Storage(word_map!("0x0" => "0x6f")),
                        #[cfg(feature = "enable-memory")]
                        memory: Memory::from(vec![word!("0x0"), word!("0x0"), word!("0x080")]),
                    },
                    GethExecStep {
                        pc: ProgramCounter(189),
                        op: OpcodeId::SHA3,
                        gas: Gas(178805),
                        refund: Gas(0),
                        gas_cost: GasCost(42),
                        depth: 1,
                        error: None,
                        #[cfg(feature = "enable-stack")]
                        stack: Stack(vec![
                            word!("0x3635c9adc5dea00000"),
                            word!("0x40"),
                            word!("0x0")
                        ]),
                        #[cfg(feature = "enable-storage")]
                        storage: Storage(word_map!()),
                        #[cfg(feature = "enable-memory")]
                        memory: Memory::from(vec![
                            word!(
                                "000000000000000000000000b8f67472dcc25589672a61905f7fd63f09e5d470"
                            ),
                            word!(
                                "0000000000000000000000000000000000000000000000000000000000000000"
                            ),
                            word!(
                                "00000000000000000000000000000000000000000000000000000000000000a0"
                            ),
                            word!(
                                "0000000000000000000000000000000000000000000000000000000000000000"
                            ),
                            word!(
                                "00000000000000000000000000000000000000000000003635c9adc5dea00000"
                            ),
                            word!(
                                "00000000000000000000000000000000000000000000003635c9adc5dea00000"
                            ),
                        ]),
                    }
                ],
            }
        );
    }
}

#[cfg(test)]
mod eth_types_test {
    use super::*;
    use crate::{Error, Word};
    use std::str::FromStr;

    #[test]
    fn address() {
        // Test from_str
        assert_eq!(
            Address::from_str("0x9a0C63EBb78B35D7c209aFbD299B056098b5439b").unwrap(),
            Address::from([
                154, 12, 99, 235, 183, 139, 53, 215, 194, 9, 175, 189, 41, 155, 5, 96, 152, 181,
                67, 155
            ])
        );
        assert_eq!(
            Address::from_str("9a0C63EBb78B35D7c209aFbD299B056098b5439b").unwrap(),
            Address::from([
                154, 12, 99, 235, 183, 139, 53, 215, 194, 9, 175, 189, 41, 155, 5, 96, 152, 181,
                67, 155
            ])
        );

        // Test from_str Errors
        assert_eq!(
            &format!(
                "{:?}",
                Address::from_str("0x9a0C63EBb78B35D7c209aFbD299B056098b543")
            ),
            "Err(Invalid input length)",
        );
        assert_eq!(
            &format!(
                "{:?}",
                Address::from_str("0x9a0C63EBb78B35D7c209aFbD299B056098b543XY")
            ),
            "Err(Invalid character 'X' at position 38)",
        );

        // Test to_word
        assert_eq!(
            Address::from_str("0x0000000000000000000000000000000000000001")
                .unwrap()
                .to_word(),
            Word::from(1u32),
        )
    }

    #[test]
    fn word_bytes_serialization_trip() -> Result<(), Error> {
        let first_usize = 64536usize;
        // Parsing on both ways works.
        assert_eq!(
            Word::from_little_endian(&first_usize.to_le_bytes()),
            Word::from_big_endian(&first_usize.to_be_bytes())
        );
        let addr = Word::from_little_endian(&first_usize.to_le_bytes());
        assert_eq!(addr, Word::from(first_usize));

        // Little endian export
        let mut le_obtained_usize = [0u8; 32];
        addr.to_little_endian(&mut le_obtained_usize);
        let mut le_array = [0u8; 8];
        le_array.copy_from_slice(&le_obtained_usize[0..8]);

        // Big endian export
        let mut be_array = [0u8; 8];
        let be_obtained_usize = addr.to_be_bytes();
        be_array.copy_from_slice(&be_obtained_usize[24..32]);

        assert_eq!(first_usize, usize::from_le_bytes(le_array));
        assert_eq!(first_usize, usize::from_be_bytes(be_array));

        Ok(())
    }

    #[test]
    fn word_from_str() -> Result<(), Error> {
        let word_str = "000000000000000000000000000000000000000000000000000c849c24f39248";

        let word_from_u128 = Word::from(3523505890234952u128);
        let word_from_str = Word::from_str(word_str).unwrap();

        assert_eq!(word_from_u128, word_from_str);
        Ok(())
    }

    #[test]
    fn creation_tx_into_tx_req() -> Result<(), Error> {
        let tx = &geth_types::Transaction {
            to: None,
            ..Default::default()
        };

        let req: ethers_core::types::TransactionRequest = tx.into();
        assert_eq!(req.to, None);
        Ok(())
    }
}
