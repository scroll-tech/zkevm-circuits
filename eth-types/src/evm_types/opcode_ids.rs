//! Doc this
use crate::{error::Error, evm_types::GasCost};
use core::fmt::Debug;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{de, Deserialize, Serialize};
use std::str::FromStr;
use std::{fmt, matches};
use strum_macros::EnumIter;

/// Opcode enum. One-to-one corresponding to an `u8` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Hash, EnumIter)]
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

    /// ..
    pub fn is_call_with_value(&self) -> bool {
        matches!(self, Self::CALL | Self::CALLCODE)
    }

    /// ..
    pub fn is_call_without_value(&self) -> bool {
        matches!(self, Self::DELEGATECALL | Self::STATICCALL)
    }

    /// Returns `true` if the `OpcodeId` is a `DUPn`.
    pub fn is_dup(&self) -> bool {
        self.as_u8() >= Self::DUP1.as_u8() && self.as_u8() <= Self::DUP16.as_u8()
    }

    /// Returns `true` if the `OpcodeId` is a `SWAPn`.
    pub fn is_swap(&self) -> bool {
        self.as_u8() >= Self::SWAP1.as_u8() && self.as_u8() <= Self::SWAP16.as_u8()
    }

    /// Returns `true` if the `OpcodeId` is a `LOGn`.
    pub fn is_log(&self) -> bool {
        self.as_u8() >= Self::LOG0.as_u8() && self.as_u8() <= Self::LOG4.as_u8()
    }

    /// Returns `true` if the `OpcodeId` is a CALL-like.
    pub fn is_call(&self) -> bool {
        matches!(
            self,
            OpcodeId::CREATE
                | OpcodeId::CALL
                | OpcodeId::CALLCODE
                | OpcodeId::DELEGATECALL
                | OpcodeId::STATICCALL
        )
    }

    /// Returns `true` if the `OpcodeId` is a CREATE-like.
    pub fn is_create(&self) -> bool {
        matches!(self, OpcodeId::CREATE | Self::CREATE2)
    }

    /// Returns `true` if the `OpcodeId` is a `CALL` or `CREATE` related .
    pub fn is_call_or_create(&self) -> bool {
        self.is_call() || self.is_create()
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

    /// Returns invalid stack pointers of `OpcodeId`
    pub fn invalid_stack_ptrs(&self) -> Vec<u32> {
        let (min_stack_ptr, max_stack_ptr): (u32, u32) = match self {
            // `min_stack_pointer` 0 means stack overflow never happen, for example, `OpcodeId::ADD`
            // can only encounter underflow error, but never encounter overflow error.
            // `max_stack_pointer` means max stack poniter for op code normally run. for example,
            // `OpcodeId::ADD` 's max stack pointer is 1022, when actual sp > 1022, will
            // encounter underflow error.
            OpcodeId::STOP => (0, 1024),
            OpcodeId::ADD => (0, 1022),
            OpcodeId::MUL => (0, 1022),
            OpcodeId::SUB => (0, 1022),
            OpcodeId::DIV => (0, 1022),
            OpcodeId::SDIV => (0, 1022),
            OpcodeId::MOD => (0, 1022),
            OpcodeId::SMOD => (0, 1022),
            OpcodeId::ADDMOD => (0, 1021),
            OpcodeId::MULMOD => (0, 1021),
            OpcodeId::EXP => (0, 1022),
            OpcodeId::SIGNEXTEND => (0, 1022),
            OpcodeId::LT => (0, 1022),
            OpcodeId::GT => (0, 1022),
            OpcodeId::SLT => (0, 1022),
            OpcodeId::SGT => (0, 1022),
            OpcodeId::EQ => (0, 1022),
            OpcodeId::ISZERO => (0, 1023),
            OpcodeId::AND => (0, 1022),
            OpcodeId::OR => (0, 1022),
            OpcodeId::XOR => (0, 1022),
            OpcodeId::NOT => (0, 1023),
            OpcodeId::BYTE => (0, 1022),
            OpcodeId::SHL => (0, 1022),
            OpcodeId::SHR => (0, 1022),
            OpcodeId::SAR => (0, 1022),
            OpcodeId::SHA3 => (0, 1022),
            OpcodeId::ADDRESS => (1, 1024),
            OpcodeId::BALANCE => (0, 1023),
            OpcodeId::ORIGIN => (1, 1024),
            OpcodeId::CALLER => (1, 1024),
            OpcodeId::CALLVALUE => (1, 1024),
            OpcodeId::CALLDATALOAD => (0, 1023),
            OpcodeId::CALLDATASIZE => (1, 1024),
            OpcodeId::CALLDATACOPY => (0, 1021),
            OpcodeId::CODESIZE => (1, 1024),
            OpcodeId::CODECOPY => (0, 1021),
            OpcodeId::GASPRICE => (1, 1024),
            OpcodeId::EXTCODESIZE => (0, 1023),
            OpcodeId::EXTCODECOPY => (0, 1020),
            OpcodeId::RETURNDATASIZE => (1, 1024),
            OpcodeId::RETURNDATACOPY => (0, 1021),
            OpcodeId::EXTCODEHASH => (0, 1023),
            OpcodeId::BLOCKHASH => (0, 1023),
            OpcodeId::COINBASE => (1, 1024),
            OpcodeId::TIMESTAMP => (1, 1024),
            OpcodeId::NUMBER => (1, 1024),
            OpcodeId::DIFFICULTY => (1, 1024),
            OpcodeId::GASLIMIT => (1, 1024),
            OpcodeId::CHAINID => (1, 1024),
            OpcodeId::SELFBALANCE => (1, 1024),
            OpcodeId::BASEFEE => (1, 1024),
            OpcodeId::POP => (0, 1023),
            OpcodeId::MLOAD => (0, 1023),
            OpcodeId::MSTORE => (0, 1022),
            OpcodeId::MSTORE8 => (0, 1022),
            OpcodeId::SLOAD => (0, 1023),
            OpcodeId::SSTORE => (0, 1022),
            OpcodeId::JUMP => (0, 1023),
            OpcodeId::JUMPI => (0, 1022),
            OpcodeId::PC => (1, 1024),
            OpcodeId::MSIZE => (1, 1024),
            OpcodeId::GAS => (1, 1024),
            OpcodeId::JUMPDEST => (0, 1024),
            OpcodeId::PUSH1 => (1, 1024),
            OpcodeId::PUSH2 => (1, 1024),
            OpcodeId::PUSH3 => (1, 1024),
            OpcodeId::PUSH4 => (1, 1024),
            OpcodeId::PUSH5 => (1, 1024),
            OpcodeId::PUSH6 => (1, 1024),
            OpcodeId::PUSH7 => (1, 1024),
            OpcodeId::PUSH8 => (1, 1024),
            OpcodeId::PUSH9 => (1, 1024),
            OpcodeId::PUSH10 => (1, 1024),
            OpcodeId::PUSH11 => (1, 1024),
            OpcodeId::PUSH12 => (1, 1024),
            OpcodeId::PUSH13 => (1, 1024),
            OpcodeId::PUSH14 => (1, 1024),
            OpcodeId::PUSH15 => (1, 1024),
            OpcodeId::PUSH16 => (1, 1024),
            OpcodeId::PUSH17 => (1, 1024),
            OpcodeId::PUSH18 => (1, 1024),
            OpcodeId::PUSH19 => (1, 1024),
            OpcodeId::PUSH20 => (1, 1024),
            OpcodeId::PUSH21 => (1, 1024),
            OpcodeId::PUSH22 => (1, 1024),
            OpcodeId::PUSH23 => (1, 1024),
            OpcodeId::PUSH24 => (1, 1024),
            OpcodeId::PUSH25 => (1, 1024),
            OpcodeId::PUSH26 => (1, 1024),
            OpcodeId::PUSH27 => (1, 1024),
            OpcodeId::PUSH28 => (1, 1024),
            OpcodeId::PUSH29 => (1, 1024),
            OpcodeId::PUSH30 => (1, 1024),
            OpcodeId::PUSH31 => (1, 1024),
            OpcodeId::PUSH32 => (1, 1024),
            OpcodeId::DUP1 => (1, 1023),
            OpcodeId::DUP2 => (1, 1022),
            OpcodeId::DUP3 => (1, 1021),
            OpcodeId::DUP4 => (1, 1020),
            OpcodeId::DUP5 => (1, 1019),
            OpcodeId::DUP6 => (1, 1018),
            OpcodeId::DUP7 => (1, 1017),
            OpcodeId::DUP8 => (1, 1016),
            OpcodeId::DUP9 => (1, 1015),
            OpcodeId::DUP10 => (1, 1014),
            OpcodeId::DUP11 => (1, 1013),
            OpcodeId::DUP12 => (1, 1012),
            OpcodeId::DUP13 => (1, 1011),
            OpcodeId::DUP14 => (1, 1010),
            OpcodeId::DUP15 => (1, 1009),
            OpcodeId::DUP16 => (1, 1008),
            OpcodeId::SWAP1 => (0, 1022),
            OpcodeId::SWAP2 => (0, 1021),
            OpcodeId::SWAP3 => (0, 1020),
            OpcodeId::SWAP4 => (0, 1019),
            OpcodeId::SWAP5 => (0, 1018),
            OpcodeId::SWAP6 => (0, 1017),
            OpcodeId::SWAP7 => (0, 1016),
            OpcodeId::SWAP8 => (0, 1015),
            OpcodeId::SWAP9 => (0, 1014),

            OpcodeId::SWAP10 => (0, 1013),
            OpcodeId::SWAP11 => (0, 1012),
            OpcodeId::SWAP12 => (0, 1011),
            OpcodeId::SWAP13 => (0, 1010),
            OpcodeId::SWAP14 => (0, 1009),
            OpcodeId::SWAP15 => (0, 1008),
            OpcodeId::SWAP16 => (0, 1007),
            OpcodeId::LOG0 => (0, 1022),
            OpcodeId::LOG1 => (0, 1021),
            OpcodeId::LOG2 => (0, 1020),
            OpcodeId::LOG3 => (0, 1019),
            OpcodeId::LOG4 => (0, 1018),
            OpcodeId::CREATE => (0, 1021),
            OpcodeId::CALL => (0, 1017),
            OpcodeId::CALLCODE => (0, 1017),
            OpcodeId::RETURN => (0, 1022),
            OpcodeId::DELEGATECALL => (0, 1018),
            OpcodeId::CREATE2 => (0, 1020),
            OpcodeId::STATICCALL => (0, 1018),
            OpcodeId::REVERT => (0, 1022),
            OpcodeId::SELFDESTRUCT => (0, 1023),
            _ => (0, 0),
        };

        debug_assert!(max_stack_ptr <= 1024);

        (0..min_stack_ptr)
            // Range (1025..=1024) is valid and it should be converted to an empty vector.
            .chain(max_stack_ptr.checked_add(1).unwrap()..=1024)
            .collect()
    }

    /// Returns `true` if the `OpcodeId` has memory access
    pub const fn has_memory_access(&self) -> bool {
        matches!(
            self,
            OpcodeId::MLOAD
                | OpcodeId::MSTORE
                | OpcodeId::MSTORE8
                | OpcodeId::CALLDATACOPY
                | OpcodeId::RETURNDATACOPY
                | OpcodeId::CODECOPY
                | OpcodeId::EXTCODECOPY
        )
    }

    /// Returns PUSHn opcode from parameter n.
    pub fn push_n(n: u8) -> Result<Self, Error> {
        if (1..=32).contains(&n) {
            Ok(OpcodeId::from(OpcodeId::PUSH1.as_u8() + n - 1))
        } else {
            Err(Error::InvalidOpConversion)
        }
    }

    /// If operation has postfix returns it, otherwise None.
    pub fn postfix(&self) -> Option<u8> {
        if self.is_push() {
            Some(self.as_u8() - OpcodeId::PUSH1.as_u8() + 1)
        } else if self.is_dup() {
            Some(self.as_u8() - OpcodeId::DUP1.as_u8() + 1)
        } else if self.is_swap() {
            Some(self.as_u8() - OpcodeId::SWAP1.as_u8() + 1)
        } else if self.is_log() {
            Some(self.as_u8() - OpcodeId::LOG0.as_u8())
        } else {
            None
        }
    }

    /// Returns number of bytes used by immediate data. This is > 0 only for
    /// push opcodes.
    pub fn data_len(&self) -> usize {
        if self.is_push() {
            (self.as_u8() - OpcodeId::PUSH1.as_u8() + 1) as usize
        } else {
            0
        }
    }

    /// Returns the all valid opcodes.
    pub fn valid_opcodes() -> Vec<Self> {
        (u8::MIN..=u8::MAX).fold(vec![], |mut acc, val| {
            if !matches!(val.into(), Self::INVALID(_)) {
                acc.push(val.into());
            }
            acc
        })
    }

    /// Returns the all invalid opcodes.
    pub fn invalid_opcodes() -> Vec<Self> {
        (u8::MIN..=u8::MAX).fold(vec![], |mut acc, val| {
            if matches!(val.into(), Self::INVALID(_)) {
                acc.push(Self::INVALID(val));
            }
            acc
        })
    }
}

impl From<u8> for OpcodeId {
    fn from(value: u8) -> Self {
        match value {
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
            b => OpcodeId::INVALID(b),
        }
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
            "PUSH0" => OpcodeId::INVALID(0x5f),
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
                return Err(Error::OpcodeParsing(s.to_string()));
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

impl fmt::Display for OpcodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod opcode_ids_tests {
    use super::*;

    #[test]
    fn push_n() {
        assert!(matches!(OpcodeId::push_n(1), Ok(OpcodeId::PUSH1)));
        assert!(matches!(OpcodeId::push_n(10), Ok(OpcodeId::PUSH10)));
        assert!(matches!(
            OpcodeId::push_n(100),
            Err(Error::InvalidOpConversion)
        ));
        assert!(matches!(
            OpcodeId::push_n(0),
            Err(Error::InvalidOpConversion)
        ));
    }

    #[test]
    fn postfix() {
        assert_eq!(OpcodeId::PUSH1.postfix(), Some(1));
        assert_eq!(OpcodeId::PUSH10.postfix(), Some(10));
        assert_eq!(OpcodeId::LOG2.postfix(), Some(2));
        assert_eq!(OpcodeId::CALLCODE.postfix(), None);
    }

    #[test]
    fn data_len() {
        assert_eq!(OpcodeId::PUSH1.data_len(), 1);
        assert_eq!(OpcodeId::PUSH10.data_len(), 10);
        assert_eq!(OpcodeId::LOG2.data_len(), 0);
        assert_eq!(OpcodeId::CALLCODE.data_len(), 0);
    }
}
