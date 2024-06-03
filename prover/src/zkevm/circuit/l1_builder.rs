use crate::zkevm::SubCircuitRowUsage;
use anyhow::Result;
use bus_mapping::circuit_input_builder::CircuitInputBuilder;
use eth_types::l2_types::BlockTrace;
use zkevm_circuits::evm_circuit::witness::Block;

pub fn validite_block_traces(_block_traces: &[BlockTrace]) -> Result<()> {
    unimplemented!("Must build with feature scroll")
}

pub fn calculate_row_usage_of_witness_block(
    _witness_block: &Block,
) -> Result<Vec<SubCircuitRowUsage>> {
    unimplemented!("Must build with feature scroll")
}

pub fn print_chunk_stats(_block_traces: &[BlockTrace]) {
    unimplemented!("Must build with feature scroll")
}

pub fn block_trace_to_witness_block(_block_traces: BlockTrace) -> Result<Block> {
    unimplemented!("Must build with feature scroll")
}

pub fn block_traces_to_witness_block(_block_traces: Vec<BlockTrace>) -> Result<Block> {
    unimplemented!("Must build with feature scroll")
}

pub fn block_traces_to_witness_block_with_updated_state(
    _block_traces: Vec<BlockTrace>,
    _builder: &mut CircuitInputBuilder,
    _light_mode: bool,
) -> Result<Block> {
    unimplemented!("Must build with feature scroll")
}
