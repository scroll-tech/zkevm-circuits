use super::table::Table;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::EvmCircuit;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::{Circuit, ConstraintSystem};
use std::collections::HashMap;

// Step dimension
pub(crate) const STEP_WIDTH: usize = 140;
/// Step height
pub const MAX_STEP_HEIGHT: usize = 21;
/// The height of the state of a step, used by gates that connect two
/// consecutive steps. We target 1, which is also convenient for padding with
/// EndBlock steps.
pub(crate) const STEP_STATE_HEIGHT: usize = 1;

/// Number of Advice Phase2 columns in the EVM circuit
pub(crate) const N_PHASE2_COLUMNS: usize = 4;

/// Number of Advice Phase1 columns in the EVM circuit
pub(crate) const N_PHASE1_COLUMNS: usize =
    STEP_WIDTH - EVM_LOOKUP_COLS - N_PHASE2_COLUMNS - N_COPY_COLUMNS - N_BYTE_LOOKUPS;

// Number of copy columns
pub(crate) const N_COPY_COLUMNS: usize = 2;

pub(crate) const N_BYTE_LOOKUPS: usize = 24;

/// Amount of lookup columns in the EVM circuit dedicated to lookups.
pub(crate) const EVM_LOOKUP_COLS: usize = FIXED_TABLE_LOOKUPS
    + TX_TABLE_LOOKUPS
    + RW_TABLE_LOOKUPS
    + BYTECODE_TABLE_LOOKUPS
    + BLOCK_TABLE_LOOKUPS
    + COPY_TABLE_LOOKUPS
    + KECCAK_TABLE_LOOKUPS
    + EXP_TABLE_LOOKUPS;

/// Lookups done per row.
pub(crate) const LOOKUP_CONFIG: &[(Table, usize)] = &[
    (Table::Fixed, FIXED_TABLE_LOOKUPS),
    (Table::Tx, TX_TABLE_LOOKUPS),
    (Table::Rw, RW_TABLE_LOOKUPS),
    (Table::Bytecode, BYTECODE_TABLE_LOOKUPS),
    (Table::Block, BLOCK_TABLE_LOOKUPS),
    (Table::Copy, COPY_TABLE_LOOKUPS),
    (Table::Keccak, KECCAK_TABLE_LOOKUPS),
    (Table::Exp, EXP_TABLE_LOOKUPS),
];

/// Fixed Table lookups done in EVMCircuit
pub const FIXED_TABLE_LOOKUPS: usize = 8;

/// Tx Table lookups done in EVMCircuit
pub const TX_TABLE_LOOKUPS: usize = 4;

/// Rw Table lookups done in EVMCircuit
pub const RW_TABLE_LOOKUPS: usize = 8;

/// Bytecode Table lookups done in EVMCircuit
pub const BYTECODE_TABLE_LOOKUPS: usize = 4;

/// Block Table lookups done in EVMCircuit
pub const BLOCK_TABLE_LOOKUPS: usize = 1;

/// Copy Table lookups done in EVMCircuit
pub const COPY_TABLE_LOOKUPS: usize = 1;

/// Keccak Table lookups done in EVMCircuit
pub const KECCAK_TABLE_LOOKUPS: usize = 1;

/// Exp Table lookups done in EVMCircuit
pub const EXP_TABLE_LOOKUPS: usize = 1;

/// Maximum number of bytes that an integer can fit in field without wrapping
/// around.
pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

// Number of bytes an EVM word has.
pub(crate) const N_BYTES_WORD: usize = 32;

// Number of bytes an u64 has.
pub(crate) const N_BYTES_U64: usize = 8;

pub(crate) const N_BYTES_ACCOUNT_ADDRESS: usize = 20;

// Number of bytes that will be used of the memory address and size.
// If any of the other more signficant bytes are used it will always result in
// an out-of-gas error.
pub(crate) const N_BYTES_MEMORY_ADDRESS: usize = 5;
pub(crate) const N_BYTES_MEMORY_WORD_SIZE: usize = 4;

pub(crate) const STACK_CAPACITY: usize = 1024;

// Number of bytes that will be used of prorgam counter. Although the maximum
// size of execution bytecode could be at most 128kB due to the size limit of a
// transaction, which could be covered by 3 bytes, we still support program
// counter to u64 as go-ethereum in case transaction size is allowed larger in
// the future.
pub(crate) const N_BYTES_PROGRAM_COUNTER: usize = N_BYTES_U64;

// Number of bytes that will be used for a tx's gas field.
pub(crate) const N_BYTES_GAS: usize = N_BYTES_U64;

// Number of bytes that will be used for call data's size.
pub(crate) const N_BYTES_CALLDATASIZE: usize = N_BYTES_U64;

lazy_static::lazy_static! {
    // Step slot height in evm circuit
    pub(crate) static ref EXECUTION_STATE_HEIGHT_MAP : HashMap<ExecutionState, usize> = get_step_height_map();
}
fn get_step_height_map() -> HashMap<ExecutionState, usize> {
    let mut meta = ConstraintSystem::<Fr>::default();
    let circuit = EvmCircuit::configure(&mut meta);

    circuit.0.execution.height_map
}
