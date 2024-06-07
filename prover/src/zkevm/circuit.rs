use builder::dummy_witness_block;
use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::CircuitExt;
use zkevm_circuits::witness;

mod builder;
mod super_circuit;
pub use self::builder::{
    block_traces_to_witness_block, calculate_row_usage_of_witness_block, finalize_builder,
    print_chunk_stats, validite_block_traces,
};
pub use super_circuit::SuperCircuit;

pub use zkevm_circuits::super_circuit::params::{MAX_CALLDATA, MAX_INNER_BLOCKS, MAX_TXS};

/// A target circuit trait is a wrapper of inner circuit, with convenient APIs for building
/// circuits from traces.
pub trait TargetCircuit {
    /// The actual inner circuit that implements Circuit trait.
    type Inner: CircuitExt<Fr>;

    /// Generate a dummy circuit with an empty trace.
    /// This is useful for generating vk and pk.
    fn dummy_inner_circuit() -> anyhow::Result<Self::Inner>
    where
        Self: Sized,
    {
        let witness_block = dummy_witness_block()?;
        let circuit = Self::from_witness_block(&witness_block)?.0;
        Ok(circuit)
    }

    /// Build the inner circuit and the instances from the witness block
    fn from_witness_block(
        witness_block: &witness::Block,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized;
}
