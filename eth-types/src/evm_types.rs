//! Evm types needed for parsing instruction sets as well

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod gas_utils;
pub mod memory;
pub mod opcode_ids;
pub mod stack;
pub mod storage;

pub use {
    memory::{Memory, MemoryAddress},
    opcode_ids::OpcodeId,
    stack::{Stack, StackAddress},
    storage::Storage,
};

/// Wrapper type over `usize` which represents the program counter of the Evm.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ProgramCounter(pub usize);

impl fmt::Debug for ProgramCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("0x{:06x}", self.0))
    }
}

impl From<ProgramCounter> for usize {
    fn from(addr: ProgramCounter) -> usize {
        addr.0
    }
}

impl From<usize> for ProgramCounter {
    fn from(pc: usize) -> Self {
        ProgramCounter(pc)
    }
}

impl ProgramCounter {
    /// Increase Self by one
    pub fn inc(&mut self) {
        self.0 += 1;
    }

    /// Increase Self by one and return the value before the increase.
    pub fn inc_pre(&mut self) -> Self {
        let pre = *self;
        self.inc();
        pre
    }
}

/// Defines the gas left to operate.
#[derive(Default, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Gas(pub u64);

impl fmt::Debug for Gas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

/// Quotient for max refund of gas used
pub const MAX_REFUND_QUOTIENT_OF_GAS_USED: usize = 5;
/// Gas stipend when CALL or CALLCODE is attached with value.
pub const GAS_STIPEND_CALL_WITH_VALUE: u64 = 2300;

/// Defines the gas consumption.
#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GasCost(pub u64);

impl fmt::Debug for GasCost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl GasCost {
    /// Constant cost for free step
    pub const ZERO: Self = Self(0);
    /// Constant cost for jumpdest step, only takes one gas
    pub const ONE: Self = Self(1);
    /// Constant cost for quick step
    pub const QUICK: Self = Self(2);
    /// Constant cost for fastest step
    pub const FASTEST: Self = Self(3);
    /// Constant cost for fast step
    pub const FAST: Self = Self(5);
    /// Constant cost for mid step
    pub const MID: Self = Self(8);
    /// Constant cost for slow step
    pub const SLOW: Self = Self(10);
    /// Constant cost for ext step
    pub const EXT: Self = Self(20);
    /// Constant cost for SHA3
    pub const SHA3: Self = Self(30);
    /// Constant cost for SELFDESTRUCT
    pub const SELFDESTRUCT: Self = Self(5000);
    /// Constant cost for CREATE and CREATE2
    pub const CREATE: Self = Self(32000);
    /// Constant cost for copying every word
    pub const COPY: Self = Self(3);
    /// Constant cost for copying every word, specifically in the case of SHA3
    /// opcode.
    pub const COPY_SHA3: Self = Self(6);
    /// Constant cost for accessing account or storage key
    pub const WARM_ACCESS: Self = Self(100);
    /// Constant cost for a cold SLOAD
    pub const COLD_SLOAD: Self = Self(2100);
    /// Constant cost for a cold account access
    pub const COLD_ACCOUNT_ACCESS: Self = Self(2600);
    /// SSTORE reentrancy sentry
    pub const SSTORE_SENTRY: Self = Self(2300);
    /// Constant cost for a storage set
    pub const SSTORE_SET: Self = Self(20000);
    /// Constant cost for a storage reset
    pub const SSTORE_RESET: Self = Self(2900);
    /// Constant cost for a storage clear. EIP-3529 changed it to 4800 from
    /// 15000.
    pub const SSTORE_CLEARS_SCHEDULE: Self = Self(4800);
    /// Constant cost for a non-creation transaction
    pub const TX: Self = Self(21000);
    /// Constant cost for a creation transaction
    pub const CREATION_TX: Self = Self(53000);
    /// Constant cost for calling with non-zero value
    pub const CALL_WITH_VALUE: Self = Self(9000);
    /// Constant cost for turning empty account into non-empty account
    pub const NEW_ACCOUNT: Self = Self(25000);
    /// Cost per byte of deploying a new contract
    pub const CODE_DEPOSIT_BYTE_COST: Self = Self(200);
    /// Denominator of quadratic part of memory expansion gas cost
    pub const MEMORY_EXPANSION_QUAD_DENOMINATOR: Self = Self(512);
    /// Coefficient of linear part of memory expansion gas cost
    pub const MEMORY_EXPANSION_LINEAR_COEFF: Self = Self(3);
    /// Constant gas for LOG[0-4] op codes
    pub const LOG: Self = Self(375);
    /// Times ceil exponent byte size for the EXP instruction, EIP-158 changed
    /// it from 10 to 50.
    pub const EXP_BYTE_TIMES: Self = Self(50);
}

impl GasCost {
    /// Returns the `GasCost` as a `u64`.
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns the `GasCost` as a `usize`.
    #[inline]
    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl From<u8> for GasCost {
    fn from(cost: u8) -> Self {
        GasCost(cost as u64)
    }
}

impl From<u64> for GasCost {
    fn from(cost: u64) -> Self {
        GasCost(cost)
    }
}
