//! Doc this
use crate::{error::Error, evm_types::GasCost};
use core::fmt::Debug;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{de, Deserialize, Serialize};
use std::str::FromStr;

/// Opcode enum. One-to-one corresponding to an `u8` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Hash)]
pub enum OpcodeId {
    /// `STOP`
    STOP,
    /// `ADD`
    ADD,
    /// `MUL`
    MUL,
    /// `SUB`
    SUB,
    /// `DIV`
    DIV,
    /// `SDIV`
    SDIV,
    /// `MOD`
    MOD,
    /// `SMOD`
    SMOD,
    /// `ADDMOD`
    ADDMOD,
    /// `MULMOD`
    MULMOD,
    /// `EXP`
    EXP,
    /// `SIGNEXTEND`
    SIGNEXTEND,
    /// `LT`
    LT,
    /// `GT`
    GT,
    /// `SLT`
    SLT,
    /// `SGT`
    SGT,
    /// `EQ`
    EQ,
    /// `ISZERO`
    ISZERO,
    /// `AND`
    AND,
    /// `OR`
    OR,
    /// `XOR`
    XOR,
    /// `NOT`
    NOT,
    /// `BYTE`
    BYTE,

    /// `CALLDATALOAD`
    CALLDATALOAD,
    /// `CALLDATASIZE`
    CALLDATASIZE,
    /// `CALLDATACOPY`
    CALLDATACOPY,
    /// `CODESIZE`
    CODESIZE,
    /// `CODECOPY`
    CODECOPY,

    /// `SHL`
    SHL,
    /// `SHR`
    SHR,
    /// `SAR`
    SAR,

    /// `POP`
    POP,
    /// `MLOAD`
    MLOAD,
    /// `MSTORE`
    MSTORE,
    /// `MSTORE8`
    MSTORE8,
    /// `JUMP`
    JUMP,
    /// `JUMPI`
    JUMPI,
    /// `PC`
    PC,
    /// `MSIZE`
    MSIZE,
    /// `JUMPDEST`
    JUMPDEST,

    // PUSHn
    /// `PUSH1`
    PUSH1,
    /// `PUSH2`
    PUSH2,
    /// `PUSH3`
    PUSH3,
    /// `PUSH4`
    PUSH4,
    /// `PUSH5`
    PUSH5,
    /// `PUSH6`
    PUSH6,
    /// `PUSH7`
    PUSH7,
    /// `PUSH8`
    PUSH8,
    /// `PUSH9`
    PUSH9,
    /// `PUSH10`
    PUSH10,
    /// `PUSH11`
    PUSH11,
    /// `PUSH12`
    PUSH12,
    /// `PUSH13`
    PUSH13,
    /// `PUSH14`
    PUSH14,
    /// `PUSH15`
    PUSH15,
    /// `PUSH16`
    PUSH16,
    /// `PUSH17`
    PUSH17,
    /// `PUSH18`
    PUSH18,
    /// `PUSH19`
    PUSH19,
    /// `PUSH20`
    PUSH20,
    /// `PUSH21`
    PUSH21,
    /// `PUSH22`
    PUSH22,
    /// `PUSH23`
    PUSH23,
    /// `PUSH24`
    PUSH24,
    /// `PUSH25`
    PUSH25,
    /// `PUSH26`
    PUSH26,
    /// `PUSH27`
    PUSH27,
    /// `PUSH28`
    PUSH28,
    /// `PUSH29`
    PUSH29,
    /// `PUSH30`
    PUSH30,
    /// `PUSH31`
    PUSH31,
    /// `PUSH32`
    PUSH32,

    // DUPn
    /// `DUP1`
    DUP1,
    /// `DUP2`
    DUP2,
    /// `DUP3`
    DUP3,
    /// `DUP4`
    DUP4,
    /// `DUP5`
    DUP5,
    /// `DUP6`
    DUP6,
    /// `DUP7`
    DUP7,
    /// `DUP8`
    DUP8,
    /// `DUP9`
    DUP9,
    /// `DUP10`
    DUP10,
    /// `DUP11`
    DUP11,
    /// `DUP12`
    DUP12,
    /// `DUP13`
    DUP13,
    /// `DUP14`
    DUP14,
    /// `DUP15`
    DUP15,
    /// `DUP16`
    DUP16,

    // SWAPn
    /// `SWAP1`
    SWAP1,
    /// `SWAP2`
    SWAP2,
    /// `SWAP3`
    SWAP3,
    /// `SWAP4`
    SWAP4,
    /// `SWAP5`
    SWAP5,
    /// `SWAP6`
    SWAP6,
    /// `SWAP7`
    SWAP7,
    /// `SWAP8`
    SWAP8,
    /// `SWAP9`
    SWAP9,
    /// `SWAP10`
    SWAP10,
    /// `SWAP11`
    SWAP11,
    /// `SWAP12`
    SWAP12,
    /// `SWAP13`
    SWAP13,
    /// `SWAP14`
    SWAP14,
    /// `SWAP15`
    SWAP15,
    /// `SWAP16`
    SWAP16,

    /// `RETURN`
    RETURN,
    /// `REVERT`
    REVERT,

    /// Invalid opcode
    INVALID(u8),

    // External opcodes
    /// `SHA3`
    SHA3,
    /// `ADDRESS`
    ADDRESS,
    /// `BALANCE`
    BALANCE,
    /// `ORIGIN`
    ORIGIN,
    /// `CALLER`
    CALLER,
    /// `CALLVALUE`
    CALLVALUE,
    /// `GASPRICE`
    GASPRICE,
    /// `EXTCODESIZE`
    EXTCODESIZE,
    /// `EXTCODECOPY`
    EXTCODECOPY,
    /// `EXTCODEHASH`
    EXTCODEHASH,
    /// `RETURNDATASIZE`
    RETURNDATASIZE,
    /// `RETURNDATACOPY`
    RETURNDATACOPY,
    /// `BLOCKHASH`
    BLOCKHASH,
    /// `COINBASE`
    COINBASE,
    /// `TIMESTAMP`
    TIMESTAMP,
    /// `NUMBER`
    NUMBER,
    /// `DIFFICULTY`
    DIFFICULTY,
    /// `GASLIMIT`
    GASLIMIT,
    /// `CHAINID`
    CHAINID,
    /// `SELFBALANCE`
    SELFBALANCE,
    /// `BASEFEE`
    BASEFEE,
    /// `SLOAD`
    SLOAD,
    /// `SSTORE`
    SSTORE,
    /// `GAS`
    GAS,

    // LOGn
    /// `LOG0`
    LOG0,
    /// `LOG1`
    LOG1,
    /// `LOG2`
    LOG2,
    /// `LOG3`
    LOG3,
    /// `LOG4`
    LOG4,

    /// `CREATE`
    CREATE,
    /// `CREATE2`
    CREATE2,
    /// `CALL`
    CALL,
    /// `CALLCODE`
    CALLCODE,
    /// `DELEGATECALL`
    DELEGATECALL,
    /// `STATICCALL`
    STATICCALL,
    /// `SELFDESTRUCT`
    SELFDESTRUCT,
}

impl OpcodeId {
    /// Returns `true` if the `OpcodeId` is a `PUSHn`.
    pub fn is_push(&self) -> bool {
        self.as_u8() >= Self::PUSH1.as_u8() && self.as_u8() <= Self::PUSH32.as_u8()
    }

    /// Returns `true` if the `OpcodeId` is a `DUPn`.
    pub fn is_dup(&self) -> bool {
        self.as_u8() >= Self::DUP1.as_u8() && self.as_u8() <= Self::DUP16.as_u8()
    }

    /// Returns `true` if the `OpcodeId` is a `SWAPn`.
    pub fn is_swap(&self) -> bool {
        self.as_u8() >= Self::SWAP1.as_u8() && self.as_u8() <= Self::SWAP16.as_u8()
    }
}

impl OpcodeId {
    /// Returns the `OpcodeId` as a `u8`.
    pub const fn as_u8(&self) -> u8 {
        match self {
            OpcodeId::STOP => 0x00u8,
            OpcodeId::ADD => 0x01u8,
            OpcodeId::MUL => 0x02u8,
            OpcodeId::SUB => 0x03u8,
            OpcodeId::DIV => 0x04u8,
            OpcodeId::SDIV => 0x05u8,
            OpcodeId::MOD => 0x06u8,
            OpcodeId::SMOD => 0x07u8,
            OpcodeId::ADDMOD => 0x08u8,
            OpcodeId::MULMOD => 0x09u8,
            OpcodeId::EXP => 0x0au8,
            OpcodeId::SIGNEXTEND => 0x0bu8,
            OpcodeId::LT => 0x10u8,
            OpcodeId::GT => 0x11u8,
            OpcodeId::SLT => 0x12u8,
            OpcodeId::SGT => 0x13u8,
            OpcodeId::EQ => 0x14u8,
            OpcodeId::ISZERO => 0x15u8,
            OpcodeId::AND => 0x16u8,
            OpcodeId::OR => 0x17u8,
            OpcodeId::XOR => 0x18u8,
            OpcodeId::NOT => 0x19u8,
            OpcodeId::BYTE => 0x1au8,
            OpcodeId::CALLDATALOAD => 0x35u8,
            OpcodeId::CALLDATASIZE => 0x36u8,
            OpcodeId::CALLDATACOPY => 0x37u8,
            OpcodeId::CODESIZE => 0x38u8,
            OpcodeId::CODECOPY => 0x39u8,
            OpcodeId::SHL => 0x1bu8,
            OpcodeId::SHR => 0x1cu8,
            OpcodeId::SAR => 0x1du8,
            OpcodeId::POP => 0x50u8,
            OpcodeId::MLOAD => 0x51u8,
            OpcodeId::MSTORE => 0x52u8,
            OpcodeId::MSTORE8 => 0x53u8,
            OpcodeId::JUMP => 0x56u8,
            OpcodeId::JUMPI => 0x57u8,
            OpcodeId::PC => 0x58u8,
            OpcodeId::MSIZE => 0x59u8,
            OpcodeId::JUMPDEST => 0x5bu8,
            OpcodeId::PUSH1 => 0x60u8,
            OpcodeId::PUSH2 => 0x61u8,
            OpcodeId::PUSH3 => 0x62u8,
            OpcodeId::PUSH4 => 0x63u8,
            OpcodeId::PUSH5 => 0x64u8,
            OpcodeId::PUSH6 => 0x65u8,
            OpcodeId::PUSH7 => 0x66u8,
            OpcodeId::PUSH8 => 0x67u8,
            OpcodeId::PUSH9 => 0x68u8,
            OpcodeId::PUSH10 => 0x69u8,
            OpcodeId::PUSH11 => 0x6au8,
            OpcodeId::PUSH12 => 0x6bu8,
            OpcodeId::PUSH13 => 0x6cu8,
            OpcodeId::PUSH14 => 0x6du8,
            OpcodeId::PUSH15 => 0x6eu8,
            OpcodeId::PUSH16 => 0x6fu8,
            OpcodeId::PUSH17 => 0x70u8,
            OpcodeId::PUSH18 => 0x71u8,
            OpcodeId::PUSH19 => 0x72u8,
            OpcodeId::PUSH20 => 0x73u8,
            OpcodeId::PUSH21 => 0x74u8,
            OpcodeId::PUSH22 => 0x75u8,
            OpcodeId::PUSH23 => 0x76u8,
            OpcodeId::PUSH24 => 0x77u8,
            OpcodeId::PUSH25 => 0x78u8,
            OpcodeId::PUSH26 => 0x79u8,
            OpcodeId::PUSH27 => 0x7au8,
            OpcodeId::PUSH28 => 0x7bu8,
            OpcodeId::PUSH29 => 0x7cu8,
            OpcodeId::PUSH30 => 0x7du8,
            OpcodeId::PUSH31 => 0x7eu8,
            OpcodeId::PUSH32 => 0x7fu8,
            OpcodeId::DUP1 => 0x80u8,
            OpcodeId::DUP2 => 0x81u8,
            OpcodeId::DUP3 => 0x82u8,
            OpcodeId::DUP4 => 0x83u8,
            OpcodeId::DUP5 => 0x84u8,
            OpcodeId::DUP6 => 0x85u8,
            OpcodeId::DUP7 => 0x86u8,
            OpcodeId::DUP8 => 0x87u8,
            OpcodeId::DUP9 => 0x88u8,
            OpcodeId::DUP10 => 0x89u8,
            OpcodeId::DUP11 => 0x8au8,
            OpcodeId::DUP12 => 0x8bu8,
            OpcodeId::DUP13 => 0x8cu8,
            OpcodeId::DUP14 => 0x8du8,
            OpcodeId::DUP15 => 0x8eu8,
            OpcodeId::DUP16 => 0x8fu8,
            OpcodeId::SWAP1 => 0x90u8,
            OpcodeId::SWAP2 => 0x91u8,
            OpcodeId::SWAP3 => 0x92u8,
            OpcodeId::SWAP4 => 0x93u8,
            OpcodeId::SWAP5 => 0x94u8,
            OpcodeId::SWAP6 => 0x95u8,
            OpcodeId::SWAP7 => 0x96u8,
            OpcodeId::SWAP8 => 0x97u8,
            OpcodeId::SWAP9 => 0x98u8,
            OpcodeId::SWAP10 => 0x99u8,
            OpcodeId::SWAP11 => 0x9au8,
            OpcodeId::SWAP12 => 0x9bu8,
            OpcodeId::SWAP13 => 0x9cu8,
            OpcodeId::SWAP14 => 0x9du8,
            OpcodeId::SWAP15 => 0x9eu8,
            OpcodeId::SWAP16 => 0x9fu8,
            OpcodeId::RETURN => 0xf3u8,
            OpcodeId::REVERT => 0xfdu8,
            OpcodeId::INVALID(b) => *b,
            OpcodeId::SHA3 => 0x20u8,
            OpcodeId::ADDRESS => 0x30u8,
            OpcodeId::BALANCE => 0x31u8,
            OpcodeId::ORIGIN => 0x32u8,
            OpcodeId::CALLER => 0x33u8,
            OpcodeId::CALLVALUE => 0x34u8,
            OpcodeId::GASPRICE => 0x3au8,
            OpcodeId::EXTCODESIZE => 0x3bu8,
            OpcodeId::EXTCODECOPY => 0x3cu8,
            OpcodeId::EXTCODEHASH => 0x3fu8,
            OpcodeId::RETURNDATASIZE => 0x3du8,
            OpcodeId::RETURNDATACOPY => 0x3eu8,
            OpcodeId::BLOCKHASH => 0x40u8,
            OpcodeId::COINBASE => 0x41u8,
            OpcodeId::TIMESTAMP => 0x42u8,
            OpcodeId::NUMBER => 0x43u8,
            OpcodeId::DIFFICULTY => 0x44u8,
            OpcodeId::GASLIMIT => 0x45u8,
            OpcodeId::CHAINID => 0x46u8,
            OpcodeId::SELFBALANCE => 0x47u8,
            OpcodeId::BASEFEE => 0x48u8,
            OpcodeId::SLOAD => 0x54u8,
            OpcodeId::SSTORE => 0x55u8,
            OpcodeId::GAS => 0x5au8,
            OpcodeId::LOG0 => 0xa0u8,
            OpcodeId::LOG1 => 0xa1u8,
            OpcodeId::LOG2 => 0xa2u8,
            OpcodeId::LOG3 => 0xa3u8,
            OpcodeId::LOG4 => 0xa4u8,
            OpcodeId::CREATE => 0xf0u8,
            OpcodeId::CREATE2 => 0xf5u8,
            OpcodeId::CALL => 0xf1u8,
            OpcodeId::CALLCODE => 0xf2u8,
            OpcodeId::DELEGATECALL => 0xf4u8,
            OpcodeId::STATICCALL => 0xfau8,
            OpcodeId::SELFDESTRUCT => 0xffu8,
        }
    }

    /// Returns the `OpcodeId` as a `u64`.
    pub const fn as_u64(&self) -> u64 {
        self.as_u8() as u64
    }

    /// Returns the constant gas cost of `OpcodeId`
    pub const fn constant_gas_cost(&self) -> GasCost {
        match self {
            OpcodeId::STOP => GasCost::ZERO,
            OpcodeId::ADD => GasCost::FASTEST,
            OpcodeId::MUL => GasCost::FAST,
            OpcodeId::SUB => GasCost::FASTEST,
            OpcodeId::DIV => GasCost::FAST,
            OpcodeId::SDIV => GasCost::FAST,
            OpcodeId::MOD => GasCost::FAST,
            OpcodeId::SMOD => GasCost::FAST,
            OpcodeId::ADDMOD => GasCost::MID,
            OpcodeId::MULMOD => GasCost::MID,
            OpcodeId::EXP => GasCost::SLOW,
            OpcodeId::SIGNEXTEND => GasCost::FAST,
            OpcodeId::LT => GasCost::FASTEST,
            OpcodeId::GT => GasCost::FASTEST,
            OpcodeId::SLT => GasCost::FASTEST,
            OpcodeId::SGT => GasCost::FASTEST,
            OpcodeId::EQ => GasCost::FASTEST,
            OpcodeId::ISZERO => GasCost::FASTEST,
            OpcodeId::AND => GasCost::FASTEST,
            OpcodeId::OR => GasCost::FASTEST,
            OpcodeId::XOR => GasCost::FASTEST,
            OpcodeId::NOT => GasCost::FASTEST,
            OpcodeId::BYTE => GasCost::FASTEST,
            OpcodeId::SHL => GasCost::FASTEST,
            OpcodeId::SHR => GasCost::FASTEST,
            OpcodeId::SAR => GasCost::FASTEST,
            OpcodeId::SHA3 => GasCost::SHA3,
            OpcodeId::ADDRESS => GasCost::QUICK,
            OpcodeId::BALANCE => GasCost::WARM_ACCESS,
            OpcodeId::ORIGIN => GasCost::QUICK,
            OpcodeId::CALLER => GasCost::QUICK,
            OpcodeId::CALLVALUE => GasCost::QUICK,
            OpcodeId::CALLDATALOAD => GasCost::FASTEST,
            OpcodeId::CALLDATASIZE => GasCost::QUICK,
            OpcodeId::CALLDATACOPY => GasCost::FASTEST,
            OpcodeId::CODESIZE => GasCost::QUICK,
            OpcodeId::CODECOPY => GasCost::FASTEST,
            OpcodeId::GASPRICE => GasCost::QUICK,
            OpcodeId::EXTCODESIZE => GasCost::WARM_ACCESS,
            OpcodeId::EXTCODECOPY => GasCost::WARM_ACCESS,
            OpcodeId::RETURNDATASIZE => GasCost::QUICK,
            OpcodeId::RETURNDATACOPY => GasCost::FASTEST,
            OpcodeId::EXTCODEHASH => GasCost::WARM_ACCESS,
            OpcodeId::BLOCKHASH => GasCost::EXT,
            OpcodeId::COINBASE => GasCost::QUICK,
            OpcodeId::TIMESTAMP => GasCost::QUICK,
            OpcodeId::NUMBER => GasCost::QUICK,
            OpcodeId::DIFFICULTY => GasCost::QUICK,
            OpcodeId::GASLIMIT => GasCost::QUICK,
            OpcodeId::CHAINID => GasCost::QUICK,
            OpcodeId::SELFBALANCE => GasCost::FAST,
            OpcodeId::BASEFEE => GasCost::QUICK,
            OpcodeId::POP => GasCost::QUICK,
            OpcodeId::MLOAD => GasCost::FASTEST,
            OpcodeId::MSTORE => GasCost::FASTEST,
            OpcodeId::MSTORE8 => GasCost::FASTEST,
            OpcodeId::SLOAD => GasCost::ZERO,
            OpcodeId::SSTORE => GasCost::ZERO,
            OpcodeId::JUMP => GasCost::MID,
            OpcodeId::JUMPI => GasCost::SLOW,
            OpcodeId::PC => GasCost::QUICK,
            OpcodeId::MSIZE => GasCost::QUICK,
            OpcodeId::GAS => GasCost::QUICK,
            OpcodeId::JUMPDEST => GasCost::ONE,
            OpcodeId::PUSH1 => GasCost::FASTEST,
            OpcodeId::PUSH2 => GasCost::FASTEST,
            OpcodeId::PUSH3 => GasCost::FASTEST,
            OpcodeId::PUSH4 => GasCost::FASTEST,
            OpcodeId::PUSH5 => GasCost::FASTEST,
            OpcodeId::PUSH6 => GasCost::FASTEST,
            OpcodeId::PUSH7 => GasCost::FASTEST,
            OpcodeId::PUSH8 => GasCost::FASTEST,
            OpcodeId::PUSH9 => GasCost::FASTEST,
            OpcodeId::PUSH10 => GasCost::FASTEST,
            OpcodeId::PUSH11 => GasCost::FASTEST,
            OpcodeId::PUSH12 => GasCost::FASTEST,
            OpcodeId::PUSH13 => GasCost::FASTEST,
            OpcodeId::PUSH14 => GasCost::FASTEST,
            OpcodeId::PUSH15 => GasCost::FASTEST,
            OpcodeId::PUSH16 => GasCost::FASTEST,
            OpcodeId::PUSH17 => GasCost::FASTEST,
            OpcodeId::PUSH18 => GasCost::FASTEST,
            OpcodeId::PUSH19 => GasCost::FASTEST,
            OpcodeId::PUSH20 => GasCost::FASTEST,
            OpcodeId::PUSH21 => GasCost::FASTEST,
            OpcodeId::PUSH22 => GasCost::FASTEST,
            OpcodeId::PUSH23 => GasCost::FASTEST,
            OpcodeId::PUSH24 => GasCost::FASTEST,
            OpcodeId::PUSH25 => GasCost::FASTEST,
            OpcodeId::PUSH26 => GasCost::FASTEST,
            OpcodeId::PUSH27 => GasCost::FASTEST,
            OpcodeId::PUSH28 => GasCost::FASTEST,
            OpcodeId::PUSH29 => GasCost::FASTEST,
            OpcodeId::PUSH30 => GasCost::FASTEST,
            OpcodeId::PUSH31 => GasCost::FASTEST,
            OpcodeId::PUSH32 => GasCost::FASTEST,
            OpcodeId::DUP1 => GasCost::FASTEST,
            OpcodeId::DUP2 => GasCost::FASTEST,
            OpcodeId::DUP3 => GasCost::FASTEST,
            OpcodeId::DUP4 => GasCost::FASTEST,
            OpcodeId::DUP5 => GasCost::FASTEST,
            OpcodeId::DUP6 => GasCost::FASTEST,
            OpcodeId::DUP7 => GasCost::FASTEST,
            OpcodeId::DUP8 => GasCost::FASTEST,
            OpcodeId::DUP9 => GasCost::FASTEST,
            OpcodeId::DUP10 => GasCost::FASTEST,
            OpcodeId::DUP11 => GasCost::FASTEST,
            OpcodeId::DUP12 => GasCost::FASTEST,
            OpcodeId::DUP13 => GasCost::FASTEST,
            OpcodeId::DUP14 => GasCost::FASTEST,
            OpcodeId::DUP15 => GasCost::FASTEST,
            OpcodeId::DUP16 => GasCost::FASTEST,
            OpcodeId::SWAP1 => GasCost::FASTEST,
            OpcodeId::SWAP2 => GasCost::FASTEST,
            OpcodeId::SWAP3 => GasCost::FASTEST,
            OpcodeId::SWAP4 => GasCost::FASTEST,
            OpcodeId::SWAP5 => GasCost::FASTEST,
            OpcodeId::SWAP6 => GasCost::FASTEST,
            OpcodeId::SWAP7 => GasCost::FASTEST,
            OpcodeId::SWAP8 => GasCost::FASTEST,
            OpcodeId::SWAP9 => GasCost::FASTEST,
            OpcodeId::SWAP10 => GasCost::FASTEST,
            OpcodeId::SWAP11 => GasCost::FASTEST,
            OpcodeId::SWAP12 => GasCost::FASTEST,
            OpcodeId::SWAP13 => GasCost::FASTEST,
            OpcodeId::SWAP14 => GasCost::FASTEST,
            OpcodeId::SWAP15 => GasCost::FASTEST,
            OpcodeId::SWAP16 => GasCost::FASTEST,
            OpcodeId::LOG0 => GasCost::ZERO,
            OpcodeId::LOG1 => GasCost::ZERO,
            OpcodeId::LOG2 => GasCost::ZERO,
            OpcodeId::LOG3 => GasCost::ZERO,
            OpcodeId::LOG4 => GasCost::ZERO,
            OpcodeId::CREATE => GasCost::CREATE,
            OpcodeId::CALL => GasCost::WARM_ACCESS,
            OpcodeId::CALLCODE => GasCost::WARM_ACCESS,
            OpcodeId::RETURN => GasCost::ZERO,
            OpcodeId::DELEGATECALL => GasCost::WARM_ACCESS,
            OpcodeId::CREATE2 => GasCost::CREATE,
            OpcodeId::STATICCALL => GasCost::WARM_ACCESS,
            OpcodeId::REVERT => GasCost::ZERO,
            OpcodeId::INVALID(_) => GasCost::ZERO,
            OpcodeId::SELFDESTRUCT => GasCost::SELFDESTRUCT,
        }
    }
}

impl TryFrom<u8> for OpcodeId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x00u8 => OpcodeId::STOP,
            0x01u8 => OpcodeId::ADD,
            0x02u8 => OpcodeId::MUL,
            0x03u8 => OpcodeId::SUB,
            0x04u8 => OpcodeId::DIV,
            0x05u8 => OpcodeId::SDIV,
            0x06u8 => OpcodeId::MOD,
            0x07u8 => OpcodeId::SMOD,
            0x08u8 => OpcodeId::ADDMOD,
            0x09u8 => OpcodeId::MULMOD,
            0x0au8 => OpcodeId::EXP,
            0x0bu8 => OpcodeId::SIGNEXTEND,
            0x10u8 => OpcodeId::LT,
            0x11u8 => OpcodeId::GT,
            0x12u8 => OpcodeId::SLT,
            0x13u8 => OpcodeId::SGT,
            0x14u8 => OpcodeId::EQ,
            0x15u8 => OpcodeId::ISZERO,
            0x16u8 => OpcodeId::AND,
            0x17u8 => OpcodeId::OR,
            0x18u8 => OpcodeId::XOR,
            0x19u8 => OpcodeId::NOT,
            0x1au8 => OpcodeId::BYTE,
            0x35u8 => OpcodeId::CALLDATALOAD,
            0x36u8 => OpcodeId::CALLDATASIZE,
            0x37u8 => OpcodeId::CALLDATACOPY,
            0x38u8 => OpcodeId::CODESIZE,
            0x39u8 => OpcodeId::CODECOPY,
            0x1bu8 => OpcodeId::SHL,
            0x1cu8 => OpcodeId::SHR,
            0x1du8 => OpcodeId::SAR,
            0x50u8 => OpcodeId::POP,
            0x51u8 => OpcodeId::MLOAD,
            0x52u8 => OpcodeId::MSTORE,
            0x53u8 => OpcodeId::MSTORE8,
            0x56u8 => OpcodeId::JUMP,
            0x57u8 => OpcodeId::JUMPI,
            0x58u8 => OpcodeId::PC,
            0x59u8 => OpcodeId::MSIZE,
            0x5bu8 => OpcodeId::JUMPDEST,
            0x60u8 => OpcodeId::PUSH1,
            0x61u8 => OpcodeId::PUSH2,
            0x62u8 => OpcodeId::PUSH3,
            0x63u8 => OpcodeId::PUSH4,
            0x64u8 => OpcodeId::PUSH5,
            0x65u8 => OpcodeId::PUSH6,
            0x66u8 => OpcodeId::PUSH7,
            0x67u8 => OpcodeId::PUSH8,
            0x68u8 => OpcodeId::PUSH9,
            0x69u8 => OpcodeId::PUSH10,
            0x6au8 => OpcodeId::PUSH11,
            0x6bu8 => OpcodeId::PUSH12,
            0x6cu8 => OpcodeId::PUSH13,
            0x6du8 => OpcodeId::PUSH14,
            0x6eu8 => OpcodeId::PUSH15,
            0x6fu8 => OpcodeId::PUSH16,
            0x70u8 => OpcodeId::PUSH17,
            0x71u8 => OpcodeId::PUSH18,
            0x72u8 => OpcodeId::PUSH19,
            0x73u8 => OpcodeId::PUSH20,
            0x74u8 => OpcodeId::PUSH21,
            0x75u8 => OpcodeId::PUSH22,
            0x76u8 => OpcodeId::PUSH23,
            0x77u8 => OpcodeId::PUSH24,
            0x78u8 => OpcodeId::PUSH25,
            0x79u8 => OpcodeId::PUSH26,
            0x7au8 => OpcodeId::PUSH27,
            0x7bu8 => OpcodeId::PUSH28,
            0x7cu8 => OpcodeId::PUSH29,
            0x7du8 => OpcodeId::PUSH30,
            0x7eu8 => OpcodeId::PUSH31,
            0x7fu8 => OpcodeId::PUSH32,
            0x80u8 => OpcodeId::DUP1,
            0x81u8 => OpcodeId::DUP2,
            0x82u8 => OpcodeId::DUP3,
            0x83u8 => OpcodeId::DUP4,
            0x84u8 => OpcodeId::DUP5,
            0x85u8 => OpcodeId::DUP6,
            0x86u8 => OpcodeId::DUP7,
            0x87u8 => OpcodeId::DUP8,
            0x88u8 => OpcodeId::DUP9,
            0x89u8 => OpcodeId::DUP10,
            0x8au8 => OpcodeId::DUP11,
            0x8bu8 => OpcodeId::DUP12,
            0x8cu8 => OpcodeId::DUP13,
            0x8du8 => OpcodeId::DUP14,
            0x8eu8 => OpcodeId::DUP15,
            0x8fu8 => OpcodeId::DUP16,
            0x90u8 => OpcodeId::SWAP1,
            0x91u8 => OpcodeId::SWAP2,
            0x92u8 => OpcodeId::SWAP3,
            0x93u8 => OpcodeId::SWAP4,
            0x94u8 => OpcodeId::SWAP5,
            0x95u8 => OpcodeId::SWAP6,
            0x96u8 => OpcodeId::SWAP7,
            0x97u8 => OpcodeId::SWAP8,
            0x98u8 => OpcodeId::SWAP9,
            0x99u8 => OpcodeId::SWAP10,
            0x9au8 => OpcodeId::SWAP11,
            0x9bu8 => OpcodeId::SWAP12,
            0x9cu8 => OpcodeId::SWAP13,
            0x9du8 => OpcodeId::SWAP14,
            0x9eu8 => OpcodeId::SWAP15,
            0x9fu8 => OpcodeId::SWAP16,
            0xf3u8 => OpcodeId::RETURN,
            0xfdu8 => OpcodeId::REVERT,
            0xfeu8 => OpcodeId::INVALID(value),
            0x20u8 => OpcodeId::SHA3,
            0x30u8 => OpcodeId::ADDRESS,
            0x31u8 => OpcodeId::BALANCE,
            0x32u8 => OpcodeId::ORIGIN,
            0x33u8 => OpcodeId::CALLER,
            0x34u8 => OpcodeId::CALLVALUE,
            0x3au8 => OpcodeId::GASPRICE,
            0x3bu8 => OpcodeId::EXTCODESIZE,
            0x3cu8 => OpcodeId::EXTCODECOPY,
            0x3fu8 => OpcodeId::EXTCODEHASH,
            0x3du8 => OpcodeId::RETURNDATASIZE,
            0x3eu8 => OpcodeId::RETURNDATACOPY,
            0x40u8 => OpcodeId::BLOCKHASH,
            0x41u8 => OpcodeId::COINBASE,
            0x42u8 => OpcodeId::TIMESTAMP,
            0x43u8 => OpcodeId::NUMBER,
            0x44u8 => OpcodeId::DIFFICULTY,
            0x45u8 => OpcodeId::GASLIMIT,
            0x46u8 => OpcodeId::CHAINID,
            0x47u8 => OpcodeId::SELFBALANCE,
            0x48u8 => OpcodeId::BASEFEE,
            0x54u8 => OpcodeId::SLOAD,
            0x55u8 => OpcodeId::SSTORE,
            0x5au8 => OpcodeId::GAS,
            0xa0u8 => OpcodeId::LOG0,
            0xa1u8 => OpcodeId::LOG1,
            0xa2u8 => OpcodeId::LOG2,
            0xa3u8 => OpcodeId::LOG3,
            0xa4u8 => OpcodeId::LOG4,
            0xf0u8 => OpcodeId::CREATE,
            0xf5u8 => OpcodeId::CREATE2,
            0xf1u8 => OpcodeId::CALL,
            0xf2u8 => OpcodeId::CALLCODE,
            0xf4u8 => OpcodeId::DELEGATECALL,
            0xfau8 => OpcodeId::STATICCALL,
            0xffu8 => OpcodeId::SELFDESTRUCT,
            b => return Err(Error::InvalidOpcodeIdByte(b)),
        })
    }
}

impl FromStr for OpcodeId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "STOP" => OpcodeId::STOP,
            "ADD" => OpcodeId::ADD,
            "MUL" => OpcodeId::MUL,
            "SUB" => OpcodeId::SUB,
            "DIV" => OpcodeId::DIV,
            "SDIV" => OpcodeId::SDIV,
            "MOD" => OpcodeId::MOD,
            "SMOD" => OpcodeId::SMOD,
            "ADDMOD" => OpcodeId::ADDMOD,
            "MULMOD" => OpcodeId::MULMOD,
            "EXP" => OpcodeId::EXP,
            "SIGNEXTEND" => OpcodeId::SIGNEXTEND,
            "LT" => OpcodeId::LT,
            "GT" => OpcodeId::GT,
            "SLT" => OpcodeId::SLT,
            "SGT" => OpcodeId::SGT,
            "EQ" => OpcodeId::EQ,
            "ISZERO" => OpcodeId::ISZERO,
            "AND" => OpcodeId::AND,
            "OR" => OpcodeId::OR,
            "XOR" => OpcodeId::XOR,
            "NOT" => OpcodeId::NOT,
            "BYTE" => OpcodeId::BYTE,
            "CALLDATALOAD" => OpcodeId::CALLDATALOAD,
            "CALLDATASIZE" => OpcodeId::CALLDATASIZE,
            "CALLDATACOPY" => OpcodeId::CALLDATACOPY,
            "CODESIZE" => OpcodeId::CODESIZE,
            "CODECOPY" => OpcodeId::CODECOPY,
            "SHL" => OpcodeId::SHL,
            "SHR" => OpcodeId::SHR,
            "SAR" => OpcodeId::SAR,
            "POP" => OpcodeId::POP,
            "MLOAD" => OpcodeId::MLOAD,
            "MSTORE" => OpcodeId::MSTORE,
            "MSTORE8" => OpcodeId::MSTORE8,
            "JUMP" => OpcodeId::JUMP,
            "JUMPI" => OpcodeId::JUMPI,
            "PC" => OpcodeId::PC,
            "MSIZE" => OpcodeId::MSIZE,
            "JUMPDEST" => OpcodeId::JUMPDEST,
            "PUSH1" => OpcodeId::PUSH1,
            "PUSH2" => OpcodeId::PUSH2,
            "PUSH3" => OpcodeId::PUSH3,
            "PUSH4" => OpcodeId::PUSH4,
            "PUSH5" => OpcodeId::PUSH5,
            "PUSH6" => OpcodeId::PUSH6,
            "PUSH7" => OpcodeId::PUSH7,
            "PUSH8" => OpcodeId::PUSH8,
            "PUSH9" => OpcodeId::PUSH9,
            "PUSH10" => OpcodeId::PUSH10,
            "PUSH11" => OpcodeId::PUSH11,
            "PUSH12" => OpcodeId::PUSH12,
            "PUSH13" => OpcodeId::PUSH13,
            "PUSH14" => OpcodeId::PUSH14,
            "PUSH15" => OpcodeId::PUSH15,
            "PUSH16" => OpcodeId::PUSH16,
            "PUSH17" => OpcodeId::PUSH17,
            "PUSH18" => OpcodeId::PUSH18,
            "PUSH19" => OpcodeId::PUSH19,
            "PUSH20" => OpcodeId::PUSH20,
            "PUSH21" => OpcodeId::PUSH21,
            "PUSH22" => OpcodeId::PUSH22,
            "PUSH23" => OpcodeId::PUSH23,
            "PUSH24" => OpcodeId::PUSH24,
            "PUSH25" => OpcodeId::PUSH25,
            "PUSH26" => OpcodeId::PUSH26,
            "PUSH27" => OpcodeId::PUSH27,
            "PUSH28" => OpcodeId::PUSH28,
            "PUSH29" => OpcodeId::PUSH29,
            "PUSH30" => OpcodeId::PUSH30,
            "PUSH31" => OpcodeId::PUSH31,
            "PUSH32" => OpcodeId::PUSH32,
            "DUP1" => OpcodeId::DUP1,
            "DUP2" => OpcodeId::DUP2,
            "DUP3" => OpcodeId::DUP3,
            "DUP4" => OpcodeId::DUP4,
            "DUP5" => OpcodeId::DUP5,
            "DUP6" => OpcodeId::DUP6,
            "DUP7" => OpcodeId::DUP7,
            "DUP8" => OpcodeId::DUP8,
            "DUP9" => OpcodeId::DUP9,
            "DUP10" => OpcodeId::DUP10,
            "DUP11" => OpcodeId::DUP11,
            "DUP12" => OpcodeId::DUP12,
            "DUP13" => OpcodeId::DUP13,
            "DUP14" => OpcodeId::DUP14,
            "DUP15" => OpcodeId::DUP15,
            "DUP16" => OpcodeId::DUP16,
            "SWAP1" => OpcodeId::SWAP1,
            "SWAP2" => OpcodeId::SWAP2,
            "SWAP3" => OpcodeId::SWAP3,
            "SWAP4" => OpcodeId::SWAP4,
            "SWAP5" => OpcodeId::SWAP5,
            "SWAP6" => OpcodeId::SWAP6,
            "SWAP7" => OpcodeId::SWAP7,
            "SWAP8" => OpcodeId::SWAP8,
            "SWAP9" => OpcodeId::SWAP9,
            "SWAP10" => OpcodeId::SWAP10,
            "SWAP11" => OpcodeId::SWAP11,
            "SWAP12" => OpcodeId::SWAP12,
            "SWAP13" => OpcodeId::SWAP13,
            "SWAP14" => OpcodeId::SWAP14,
            "SWAP15" => OpcodeId::SWAP15,
            "SWAP16" => OpcodeId::SWAP16,
            "RETURN" => OpcodeId::RETURN,
            "REVERT" => OpcodeId::REVERT,
            "INVALID" => OpcodeId::INVALID(0xfe),
            "SHA3" | "KECCAK256" => OpcodeId::SHA3,
            "ADDRESS" => OpcodeId::ADDRESS,
            "BALANCE" => OpcodeId::BALANCE,
            "SELFBALANCE" => OpcodeId::SELFBALANCE,
            "ORIGIN" => OpcodeId::ORIGIN,
            "CALLER" => OpcodeId::CALLER,
            "CALLVALUE" => OpcodeId::CALLVALUE,
            "GASPRICE" => OpcodeId::GASPRICE,
            "EXTCODESIZE" => OpcodeId::EXTCODESIZE,
            "EXTCODECOPY" => OpcodeId::EXTCODECOPY,
            "EXTCODEHASH" => OpcodeId::EXTCODEHASH,
            "RETURNDATASIZE" => OpcodeId::RETURNDATASIZE,
            "RETURNDATACOPY" => OpcodeId::RETURNDATACOPY,
            "BLOCKHASH" => OpcodeId::BLOCKHASH,
            "COINBASE" => OpcodeId::COINBASE,
            "TIMESTAMP" => OpcodeId::TIMESTAMP,
            "NUMBER" => OpcodeId::NUMBER,
            "DIFFICULTY" => OpcodeId::DIFFICULTY,
            "GASLIMIT" => OpcodeId::GASLIMIT,
            "SLOAD" => OpcodeId::SLOAD,
            "SSTORE" => OpcodeId::SSTORE,
            "GAS" => OpcodeId::GAS,
            "LOG0" => OpcodeId::LOG0,
            "LOG1" => OpcodeId::LOG1,
            "LOG2" => OpcodeId::LOG2,
            "LOG3" => OpcodeId::LOG3,
            "LOG4" => OpcodeId::LOG4,
            "CREATE" => OpcodeId::CREATE,
            "CREATE2" => OpcodeId::CREATE2,
            "CALL" => OpcodeId::CALL,
            "CALLCODE" => OpcodeId::CALLCODE,
            "DELEGATECALL" => OpcodeId::DELEGATECALL,
            "STATICCALL" => OpcodeId::STATICCALL,
            "SELFDESTRUCT" => OpcodeId::SELFDESTRUCT,
            "CHAINID" => OpcodeId::CHAINID,
            "BASEFEE" => OpcodeId::BASEFEE,
            _ => {
                // Parse an invalid opcode value as reported by geth
                lazy_static! {
                    static ref RE: Regex = Regex::new("opcode 0x([[:xdigit:]]{1,2}) not defined")
                        .expect("invalid regex");
                }
                if let Some(cap) = RE.captures(s) {
                    if let Some(byte_hex) = cap.get(1).map(|m| m.as_str()) {
                        return Ok(OpcodeId::INVALID(
                            u8::from_str_radix(byte_hex, 16).expect("invalid hex byte from regex"),
                        ));
                    }
                }
                return Err(Error::OpcodeParsing);
            }
        })
    }
}

impl<'de> Deserialize<'de> for OpcodeId {
    fn deserialize<D>(deserializer: D) -> Result<OpcodeId, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        OpcodeId::from_str(&s).map_err(de::Error::custom)
    }
}
