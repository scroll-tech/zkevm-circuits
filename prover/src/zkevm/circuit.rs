use eth_types::l2_types::BlockTrace;
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::CircuitExt;
use zkevm_circuits::witness;

#[cfg(feature = "scroll")]
mod l2_builder;
#[cfg(feature = "scroll")]
use l2_builder as builder;
#[cfg(not(feature = "scroll"))]
mod l1_builder;
#[cfg(not(feature = "scroll"))]
use l1_builder as builder;
mod super_circuit;
pub use self::builder::{
    block_traces_to_witness_block, block_traces_to_witness_block_with_updated_state,
    calculate_row_usage_of_trace, calculate_row_usage_of_witness_block, check_batch_capacity,
    get_super_circuit_params, normalize_withdraw_proof, validite_block_traces,
};
pub use super_circuit::SuperCircuit;

////// params for Super Circuit of degree = 20 ////////////
pub const MAX_TXS: usize = 100;
pub const MAX_INNER_BLOCKS: usize = 100;
pub const MAX_EXP_STEPS: usize = 10_000;
pub const MAX_CALLDATA: usize = 350_000;
pub const MAX_RLP_ROWS: usize = 800_000;
pub const MAX_BYTECODE: usize = 600_000;
pub const MAX_MPT_ROWS: usize = 1_000_000;
pub const MAX_KECCAK_ROWS: usize = 1_000_000;
pub const MAX_POSEIDON_ROWS: usize = 1_000_000;
pub const MAX_VERTICLE_ROWS: usize = 1_000_000;
pub const MAX_RWS: usize = 1_000_000;
pub const MAX_PRECOMPILE_EC_ADD: usize = 50;
pub const MAX_PRECOMPILE_EC_MUL: usize = 50;
pub const MAX_PRECOMPILE_EC_PAIRING: usize = 2;

/// A target circuit trait is a wrapper of inner circuit, with convenient APIs for building
/// circuits from traces.
pub trait TargetCircuit {
    /// The actual inner circuit that implements Circuit trait.
    type Inner: CircuitExt<Fr>;

    /// Name tag of the circuit.
    /// This tag will be used as a key to index the circuit.
    /// It is therefore important that the name is unique.
    fn name() -> String;

    /// Generate a dummy circuit with an empty trace.
    /// This is useful for generating vk and pk.
    fn dummy_inner_circuit() -> Self::Inner
    where
        Self: Sized,
    {
        Self::from_block_traces(&[]).unwrap().0
    }

    /// Build the inner circuit and the instances from a traces
    fn from_block_trace(block_trace: &BlockTrace) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        Self::from_block_traces(std::slice::from_ref(block_trace))
    }

    /// Build the inner circuit and the instances from a list of traces
    fn from_block_traces(block_traces: &[BlockTrace]) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_traces_to_witness_block(block_traces)?;
        Self::from_witness_block(&witness_block)
    }

    /// Build the inner circuit and the instances from the witness block
    fn from_witness_block(
        witness_block: &witness::Block<Fr>,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized;

    fn estimate_rows(block_traces: &[BlockTrace]) -> anyhow::Result<usize> {
        let witness_block = block_traces_to_witness_block(block_traces)?;
        Ok(Self::estimate_rows_from_witness_block(&witness_block))
    }

    fn estimate_rows_from_witness_block(_witness_block: &witness::Block<Fr>) -> usize {
        0
    }

    fn public_input_len() -> usize {
        0
    }
}
