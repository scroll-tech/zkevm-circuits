//! Ethereum types used to deserialize responses from web3 / geth.

use crate::evm::{memory::Memory, stack::Stack, storage::Storage};
use crate::evm::{Gas, GasCost, OpcodeId, ProgramCounter};
use ethers_core::types;
pub use ethers_core::types::{
    transaction::response::Transaction, Address, Block, Bytes, H160, H256,
    U256, U64,
};
use pasta_curves::arithmetic::FieldExt;
use serde::{de, Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

/// Trait used to define types that can be converted to a 256 bit scalar value.
pub trait ToScalar<F: FieldExt> {
    /// Convert the type to a scalar value.
    fn to_scalar(&self) -> Option<F>;
}

/// Trait used to convert a type to a [`Word`].
pub trait ToWord {
    /// Convert the type to a [`Word`].
    fn to_word(&self) -> Word;
}

/// Trait uset do convert a scalar value to a 32 byte array in big endian.
pub trait ToBigEndian {
    /// Convert the value to a 32 byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32];
}

/// Trait uset do convert a scalar value to a 32 byte array in little endian.
pub trait ToLittleEndian {
    /// Convert the value to a 32 byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32];
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

impl Serialize for DebugU256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = format!("{:#x}", self);
        if s == "0x00" {
            serializer.serialize_str("0x0")
        } else {
            serializer.serialize_str(&s)
        }
    }
}

impl<F: FieldExt> ToScalar<F> for DebugU256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_bytes(&bytes).into()
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

impl<F: FieldExt> ToScalar<F> for U256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_bytes(&bytes).into()
    }
}

/// Ethereum Hash (160 bits).
pub type Hash = types::H256;

impl ToWord for Address {
    fn to_word(&self) -> Word {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        Word::from(bytes)
    }
}

impl<F: FieldExt> ToScalar<F> for Address {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        F::from_bytes(&bytes).into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[doc(hidden)]
struct GethExecStepInternal {
    pc: ProgramCounter,
    op: OpcodeId,
    gas: Gas,
    #[serde(alias = "gasCost")]
    gas_cost: GasCost,
    depth: u16,
    error: Option<String>,
    // stack is in hex 0x prefixed
    stack: Vec<DebugU256>,
    // memory is in chunks of 32 bytes, in hex
    #[serde(default)]
    memory: Vec<DebugU256>,
    // storage is hex -> hex
    #[serde(default)]
    storage: HashMap<DebugU256, DebugU256>,
}

/// The execution step type returned by geth RPC debug_trace* methods.
/// Corresponds to `StructLogRes` in `go-ethereum/internal/ethapi/api.go`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct GethExecStep {
    pub pc: ProgramCounter,
    pub op: OpcodeId,
    pub gas: Gas,
    pub gas_cost: GasCost,
    pub depth: u16,
    pub error: Option<String>,
    // stack is in hex 0x prefixed
    pub stack: Stack,
    // memory is in chunks of 32 bytes, in hex
    pub memory: Memory,
    // storage is hex -> hex
    pub storage: Storage,
}

impl From<GethExecStep> for GethExecStepInternal {
    fn from(step: GethExecStep) -> Self {
        GethExecStepInternal {
            pc: step.pc,
            op: step.op,
            gas: step.gas,
            gas_cost: step.gas_cost,
            depth: step.depth,
            error: step.error,
            stack: step
                .stack
                .0
                .iter()
                .map(|stack_elem| DebugU256(stack_elem.0))
                .collect(),
            memory: step
                .memory
                .0
                .chunks(32)
                .map(DebugU256::from_big_endian)
                .collect(),
            storage: step
                .storage
                .0
                .iter()
                .map(|(k, v)| (DebugU256(k.0), DebugU256(v.0)))
                .collect(),
        }
    }
}

// TODO: Tried `#[serde(into = "IntoType")]` feature but doesn't seem to work.
// Double check.
impl Serialize for GethExecStep {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as a `GethExecStepInternal`
        let internal = GethExecStepInternal::from(self.clone());
        internal.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GethExecStep {
    fn deserialize<D>(deserializer: D) -> Result<GethExecStep, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = GethExecStepInternal::deserialize(deserializer)?;
        Ok(GethExecStep {
            pc: s.pc,
            op: s.op,
            gas: s.gas,
            gas_cost: s.gas_cost,
            depth: s.depth,
            error: s.error,
            stack: Stack(
                s.stack.iter().map(|dw| dw.to_word()).collect::<Vec<Word>>(),
            ),
            memory: Memory::from(
                s.memory
                    .iter()
                    .map(|dw| dw.to_word())
                    .collect::<Vec<Word>>(),
            ),
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
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[doc(hidden)]
pub(crate) struct ResultGethExecTraces(pub(crate) Vec<ResultGethExecTrace>);

/// Helper type built to deal with the weird `result` field added between
/// `GethExecutionTrace`s in `debug_traceBlockByHash` and
/// `debug_traceBlockByNumber` Geth JSON-RPC calls.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[doc(hidden)]
pub(crate) struct ResultGethExecTrace {
    pub(crate) result: GethExecTrace,
}

/// The execution trace type returned by geth RPC debug_trace* methods.
/// Corresponds to `ExecutionResult` in `go-ethereum/internal/ethapi/api.go`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[doc(hidden)]
pub struct GethExecTrace {
    pub gas: Gas,
    pub failed: bool,
    // return_value is a hex encoded byte array
    #[serde(alias = "structLogs")]
    pub struct_logs: Vec<GethExecStep>,
}

#[macro_export]
/// Create an [`Address`] from a hex string.  Panics on invalid input.
macro_rules! address {
    ($addr_hex:expr) => {{
        use std::str::FromStr;
        $crate::eth_types::Address::from_str(&$addr_hex)
            .expect("invalid hex Address")
    }};
}

#[macro_export]
/// Create a [`Word`] from a hex string.  Panics on invalid input.
macro_rules! word {
    ($word_hex:expr) => {
        $crate::eth_types::Word::from_str_radix(&$word_hex, 16)
            .expect("invalid hex Word")
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
            use std::iter::FromIterator;
            std::collections::HashMap::from_iter([(
                    $(word!($key_hex), word!($value_hex)),*
            )])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::opcodes::ids::OpcodeId;
    use crate::evm::{memory::Memory, stack::Stack};

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
        "depth": 1,
        "stack": []
      },
      {
        "pc": 163,
        "op": "SLOAD",
        "gas": 5217,
        "gasCost": 2100,
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
      }
    ]
  }
        "#;
        let trace: GethExecTrace = serde_json::from_str(trace_json)
            .expect("json-deserialize GethExecTrace");
        assert_eq!(
            trace,
            GethExecTrace {
                gas: Gas(26809),
                failed: false,
                struct_logs: vec![
                    GethExecStep {
                        pc: ProgramCounter(0),
                        op: OpcodeId::PUSH1,
                        gas: Gas(22705),
                        gas_cost: GasCost(3),
                        depth: 1,
                        error: None,
                        stack: Stack::new(),
                        storage: Storage(word_map!()),
                        memory: Memory::new(),
                    },
                    GethExecStep {
                        pc: ProgramCounter(163),
                        op: OpcodeId::SLOAD,
                        gas: Gas(5217),
                        gas_cost: GasCost(2100),
                        depth: 1,
                        error: None,
                        stack: Stack(vec![
                            word!("0x1003e2d2"),
                            word!("0x2a"),
                            word!("0x0")
                        ]),
                        storage: Storage(word_map!("0x0" => "0x6f")),
                        memory: Memory::from(vec![
                            word!("0x0"),
                            word!("0x0"),
                            word!("0x080")
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
    use crate::eth_types::Word;
    use crate::Error;
    use std::str::FromStr;

    #[test]
    fn address() {
        // Test from_str
        assert_eq!(
            Address::from_str("0x9a0C63EBb78B35D7c209aFbD299B056098b5439b")
                .unwrap(),
            Address::from([
                154, 12, 99, 235, 183, 139, 53, 215, 194, 9, 175, 189, 41, 155,
                5, 96, 152, 181, 67, 155
            ])
        );
        assert_eq!(
            Address::from_str("9a0C63EBb78B35D7c209aFbD299B056098b5439b")
                .unwrap(),
            Address::from([
                154, 12, 99, 235, 183, 139, 53, 215, 194, 9, 175, 189, 41, 155,
                5, 96, 152, 181, 67, 155
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
        let word_str =
            "000000000000000000000000000000000000000000000000000c849c24f39248";

        let word_from_u128 = Word::from(3523505890234952u128);
        let word_from_str = Word::from_str(word_str).unwrap();

        assert_eq!(word_from_u128, word_from_str);
        Ok(())
    }
}
