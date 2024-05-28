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
    block_trace_to_witness_block, block_traces_to_witness_block,
    block_traces_to_witness_block_with_updated_state, calculate_row_usage_of_witness_block,
    print_chunk_stats, validite_block_traces,
};
pub use super_circuit::SuperCircuit;

pub use zkevm_circuits::super_circuit::params::{MAX_CALLDATA, MAX_INNER_BLOCKS, MAX_TXS};

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
        Self::from_block_traces(vec![]).unwrap().0
    }

    /// Build the inner circuit and the instances from a traces
    fn from_block_trace(block_trace: BlockTrace) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        Self::from_block_traces(vec![block_trace])
    }

    /// Build the inner circuit and the instances from a list of traces
    fn from_block_traces(
        block_traces: Vec<BlockTrace>,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let witness_block = block_traces_to_witness_block(block_traces)?;
        Self::from_witness_block(&witness_block)
    }

    /// Build the inner circuit and the instances from the witness block
    fn from_witness_block(
        witness_block: &witness::Block,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized;

    fn estimate_block_rows(block_trace: BlockTrace) -> anyhow::Result<usize> {
        let witness_block = block_trace_to_witness_block(block_trace)?;
        Ok(Self::estimate_rows_from_witness_block(&witness_block))
    }

    fn estimate_rows(block_traces: Vec<BlockTrace>) -> anyhow::Result<usize> {
        let witness_block = block_traces_to_witness_block(block_traces)?;
        Ok(Self::estimate_rows_from_witness_block(&witness_block))
    }

    fn estimate_rows_from_witness_block(_witness_block: &witness::Block) -> usize {
        0
    }

    fn public_input_len() -> usize {
        0
    }
}
