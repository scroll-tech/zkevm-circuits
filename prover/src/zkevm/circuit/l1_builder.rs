use anyhow::Result;
use bus_mapping::circuit_input_builder::{CircuitInputBuilder, CircuitsParams};
use eth_types::l2_types::BlockTrace;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::evm_circuit::witness::Block;

pub fn get_super_circuit_params() -> CircuitsParams {
    unimplemented!("Must build with feature scroll")
}

pub fn validite_block_traces(_block_traces: &[BlockTrace]) -> Result<()> {
    unimplemented!("Must build with feature scroll")
}

pub fn calculate_row_usage_of_trace(
    _block_trace: &BlockTrace,
) -> Result<Vec<zkevm_circuits::super_circuit::SubcircuitRowUsage>> {
    unimplemented!("Must build with feature scroll")
}

pub fn calculate_row_usage_of_witness_block(
    _witness_block: &Block<Fr>,
) -> Result<Vec<zkevm_circuits::super_circuit::SubcircuitRowUsage>> {
    unimplemented!("Must build with feature scroll")
}

#[allow(clippy::ptr_arg)]
pub fn check_batch_capacity(_block_traces: &mut Vec<BlockTrace>) -> Result<()> {
    unimplemented!("Must build with feature scroll")
}

pub fn block_trace_to_witness_block(_block_traces: BlockTrace) -> Result<Block<Fr>> {
    unimplemented!("Must build with feature scroll")
}

pub fn block_traces_to_witness_block(_block_traces: Vec<BlockTrace>) -> Result<Block<Fr>> {
    unimplemented!("Must build with feature scroll")
}

pub fn block_traces_to_witness_block_with_updated_state(
    _block_traces: Vec<BlockTrace>,
    _builder: &mut CircuitInputBuilder,
    _light_mode: bool,
) -> Result<Block<Fr>> {
    unimplemented!("Must build with feature scroll")
}
