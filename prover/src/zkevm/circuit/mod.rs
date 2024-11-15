use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::CircuitExt;
use zkevm_circuits::{super_circuit::params::ScrollSuperCircuit, util::SubCircuit, witness};

mod builder;
pub use builder::{
    calculate_row_usage_of_witness_block, chunk_trace_to_witness_block, finalize_builder,
};

/// A target circuit trait is a wrapper of inner circuit, with convenient APIs for building
/// circuits from traces.
pub trait TargetCircuit {
    /// The actual inner circuit that implements Circuit trait.
    type Inner: CircuitExt<Fr, Params = ()> + SubCircuit<Fr>;

    /// Generate a dummy circuit with an empty trace. This is useful for generating vk and pk.
    fn dummy_inner_circuit() -> anyhow::Result<Self::Inner>
    where
        Self: Sized,
    {
        let witness_block = builder::dummy_witness_block();
        let circuit = Self::from_witness_block(&witness_block)?;
        Ok(circuit)
    }

    /// Build the inner circuit and the instances from the witness block.
    fn from_witness_block(witness_block: &witness::Block) -> anyhow::Result<Self::Inner>
    where
        Self: Sized,
    {
        Ok(Self::Inner::new_from_block(witness_block))
    }
}

pub struct SuperCircuit {}

impl TargetCircuit for SuperCircuit {
    type Inner = ScrollSuperCircuit;
}
