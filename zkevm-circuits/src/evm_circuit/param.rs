use crate::evm_circuit::{step::ExecutionState, EvmCircuit};
use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem},
};
use std::{collections::HashMap, sync::LazyLock};

// Step dimension
pub(crate) const STEP_WIDTH: usize = 121;
/// Step height
pub const MAX_STEP_HEIGHT: usize = 21;
/// The height of the state of a step, used by gates that connect two
/// consecutive steps. We target 1, which is also convenient for padding with
/// EndBlock steps.
pub(crate) const STEP_STATE_HEIGHT: usize = 1;

/// Number of Advice Phase2 columns in the EVM circuit
pub(crate) const N_PHASE2_COLUMNS: usize = 7;

/// Number of Advice Phase3 columns, used by Bus ports.
pub const N_PHASE3_COLUMNS: usize = 12;

/// Number of Advice Phase1 columns in the EVM circuit
pub(crate) const N_PHASE1_COLUMNS: usize =
    STEP_WIDTH - N_PHASE3_COLUMNS - N_PHASE2_COLUMNS - N_COPY_COLUMNS - N_BYTE_LOOKUPS;

// Number of copy columns
pub(crate) const N_COPY_COLUMNS: usize = 2;
// Number of copy columns for phase2
pub(crate) const N_PHASE2_COPY_COLUMNS: usize = 1;

pub(crate) const N_BYTE_LOOKUPS: usize = 26;

/// Maximum number of bytes that an integer can fit in field without wrapping
/// around.
pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

// Number of bytes an EVM word has.
pub(crate) const N_BYTES_WORD: usize = 32;

pub(crate) const N_BYTES_EC_PAIR: usize = 192;

// Number of bytes an u64 has.
pub(crate) const N_BYTES_U64: usize = 8;

// Number of bits a u8 has.
pub(crate) const N_BITS_U8: usize = 8;

pub(crate) const N_BYTES_ACCOUNT_ADDRESS: usize = 20;

// Number of bytes that will be used of the memory address and size.
// If any of the other more signficant bytes are used it will always result in
// an out-of-gas error.
pub(crate) const N_BYTES_MEMORY_ADDRESS: usize = 5;
pub(crate) const N_BYTES_MEMORY_WORD_SIZE: usize = 4;

/// The size of a chunk of memory that is accessed at once in RW lookups.
pub(crate) const N_BYTES_MEMORY_CHUNK: usize = N_BYTES_WORD;

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

// Step slot height in evm circuit
pub(crate) static EXECUTION_STATE_HEIGHT_MAP: LazyLock<HashMap<ExecutionState, usize>> =
    LazyLock::new(get_step_height_map);

fn get_step_height_map() -> HashMap<ExecutionState, usize> {
    let mut meta = ConstraintSystem::<Fr>::default();
    let circuit = EvmCircuit::configure(&mut meta);

    circuit.0.execution.height_map
}
