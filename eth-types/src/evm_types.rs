//! Evm types needed for parsing instruction sets as well

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod block_utils;
pub mod gas_utils;
pub mod memory;
pub mod opcode_ids;
pub mod stack;
pub mod storage;

pub use memory::{Memory, MemoryAddress};
pub use opcode_ids::OpcodeId;
pub use stack::{Stack, StackAddress};
pub use storage::Storage;

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

/// Maximum bytecode size to permit for a contract.
pub const MAX_CODE_SIZE: u64 = 24576;
/// This constant ((2^32 - 1) * 32) is the highest number that can be used without overflowing the
/// square operation of gas calculation.
/// <https://github.com/ethereum/go-ethereum/blob/e6b6a8b738069ad0579f6798ee59fde93ed13b43/core/vm/gas_table.go#L38>
pub const MAX_EXPANDED_MEMORY_ADDRESS: u64 = 0x1FFFFFFFE0;
/// Quotient for max refund of gas used
pub const MAX_REFUND_QUOTIENT_OF_GAS_USED: usize = 5;
/// Gas stipend when CALL or CALLCODE is attached with value.
pub const GAS_STIPEND_CALL_WITH_VALUE: u64 = 2300;

#[cfg(feature = "shanghai")]
mod gas_create {
    // For EIP-3860, there are 2 special gas cost constraints in geth
    // [gasCreate2Eip3860](https://github.com/ethereum/go-ethereum/blob/eb83e7c54021573eaceb14236af3a7a8c64f6027/core/vm/gas_table.go#L321)
    // (similar for CREATE).
    // 1. size <= 49152 (MaxInitCodeSize)
    // 2. gasCost = memoryGasCost + (2 + 6) * ((size + 31) / 32) should not
    //    overflow for Uint64.
    // No need to constrain the second condition, since the maximum gas cost
    // cannot overflow for Uint64 (36028809887100925 calculated by
    // `memorySize = 0x1FFFFFFFE0` and `size = 49152`) if the first condition is
    // satisfied.

    /// Maximum init code size to permit in a creation transaction and create instructions.
    pub const MAX_INIT_CODE_SIZE: u64 = 2 * super::MAX_CODE_SIZE;
    /// Once per word of the init code when creating a contract.
    pub const INIT_CODE_WORD_GAS: u64 = 2;
    /// Gas per code word for CREATE.
    pub const CREATE_GAS_PER_CODE_WORD: u64 = INIT_CODE_WORD_GAS;
    /// Gas per code word for CREATE2.
    pub const CREATE2_GAS_PER_CODE_WORD: u64 = INIT_CODE_WORD_GAS + super::GasCost::COPY_SHA3.0;
}
#[cfg(not(feature = "shanghai"))]
mod gas_create {
    /// Maximum init code size (0x1FFFFFFFE0) if not EIP-3860.
    pub use super::MAX_EXPANDED_MEMORY_ADDRESS as MAX_INIT_CODE_SIZE;
    /// Gas per code word for CREATE if not EIP-3860.
    pub const CREATE_GAS_PER_CODE_WORD: u64 = 0;
    /// Gas per code word for CREATE2 if not EIP-3860.
    pub const CREATE2_GAS_PER_CODE_WORD: u64 = super::GasCost::COPY_SHA3.0;
}
pub use gas_create::*;

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
    /// Base gas price for precompile call: Elliptic curve recover
    pub const PRECOMPILE_ECRECOVER_BASE: Self = Self(3000);
    /// Base gas price for precompile call: SHA256
    pub const PRECOMPILE_SHA256_BASE: Self = Self(60);
    /// Per-word gas price for SHA256
    pub const PRECOMPILE_SHA256_PER_WORD: Self = Self(12);
    /// Base gas price for precompile call: RIPEMD160
    pub const PRECOMPILE_RIPEMD160_BASE: Self = Self(600);
    /// Per-word gas price for RIPEMD160
    pub const PRECOMPILE_RIPEMD160_PER_WORD: Self = Self(120);
    /// Base gas price for precompile call: Identity
    pub const PRECOMPILE_IDENTITY_BASE: Self = Self(15);
    /// Per-word gas price for Identity
    pub const PRECOMPILE_IDENTITY_PER_WORD: Self = Self(3);
    /// Base gas price for precompile call: BN256 point addition
    pub const PRECOMPILE_BN256ADD: Self = Self(150);
    /// Base gas price for precompile call: BN256 scalar multiplication
    pub const PRECOMPILE_BN256MUL: Self = Self(6000);
    /// Base gas price for precompile call: BN256 pairing per point
    pub const PRECOMPILE_BN256PAIRING: Self = Self(45000);
    /// Base gas price for precompile call: MODEXP
    pub const PRECOMPILE_MODEXP: Self = Self(0);
    /// Base gas price for precompile call: BLAKE2F
    pub const PRECOMPILE_BLAKE2F: Self = Self(0);
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
