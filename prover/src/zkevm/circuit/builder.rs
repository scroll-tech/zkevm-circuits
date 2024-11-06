use bus_mapping::{circuit_input_builder::CircuitInputBuilder, Error as CircuitBuilderError};
use eth_types::{l2_types::BlockTrace, ToWord};
use itertools::Itertools;
use mpt_zktrie::state::ZkTrieHash;
use zkevm_circuits::{
    evm_circuit::witness::Block,
    super_circuit::params::{get_super_circuit_params, ScrollSuperCircuit, MAX_TXS},
    witness::block_convert,
};

use crate::zkevm::{ChunkProverError, SubCircuitRowUsage};

/// Returns the row-usage for all sub-circuits in the process of applying the entire witness block
/// to the super circuit.
pub fn calculate_row_usage_of_witness_block(
    witness_block: &Block,
) -> Result<Vec<SubCircuitRowUsage>, ChunkProverError> {
    let rows = ScrollSuperCircuit::min_num_rows_block_subcircuits(witness_block);

    // Check whether we need to "estimate" poseidon sub circuit row usage
    if witness_block.mpt_updates.smt_traces.is_empty() {
        return Err(ChunkProverError::Custom(
            "light mode no longer supported".to_string(),
        ));
    }

    let first_block_num = witness_block.first_block_number();
    let last_block_num = witness_block.last_block_number();

    log::debug!(
        "row usage of block range {:?}, tx num {:?}, tx calldata len sum {}, rows needed {:?}",
        (first_block_num, last_block_num),
        witness_block.txs.len(),
        witness_block
            .txs
            .iter()
            .map(|t| t.call_data_length)
            .sum::<usize>(),
        rows,
    );

    Ok(rows
        .into_iter()
        .map(|x| SubCircuitRowUsage {
            name: x.name,
            row_number: x.row_num_real,
        })
        .collect_vec())
}

/// Generate a dummy witness block to eventually generate proving key and verifying key for the
/// target circuit without going through the expensive process of actual witness assignment.
pub fn dummy_witness_block() -> Block {
    let dummy_chain_id = 0;
    zkevm_circuits::witness::dummy_witness_block(dummy_chain_id)
}

/// Build a witness block from block traces for all blocks in the chunk.
pub fn chunk_trace_to_witness_block(
    chunk_trace: Vec<BlockTrace>,
) -> Result<Block, ChunkProverError> {
    if chunk_trace.is_empty() {
        return Err(ChunkProverError::Custom("Empty chunk trace".to_string()));
    }
    print_chunk_stats(&chunk_trace);
    block_traces_to_witness_block(chunk_trace)
}

/// Finalize building and return witness block
pub fn finalize_builder(builder: &mut CircuitInputBuilder) -> Result<Block, CircuitBuilderError> {
    builder.finalize_building()?;

    log::debug!("converting builder.block to witness block");

    let mut witness_block = block_convert(&builder.block, &builder.code_db)?;
    log::debug!(
        "witness_block built with circuits_params {:?}",
        witness_block.circuits_params
    );

    if let Some(state) = &mut builder.mpt_init_state {
        if *state.root() != [0u8; 32] {
            log::debug!("apply_mpt_updates");
            witness_block.apply_mpt_updates_and_update_mpt_state(state);
            log::debug!("apply_mpt_updates done");
        } else {
            // Empty state root means circuit capacity checking, or dummy witness block for key gen?
            log::info!("empty state root, skip apply_mpt_updates");
        }

        let root_after = witness_block.post_state_root().to_word();
        log::debug!(
            "finish replay trie updates, root {}, root after {:#x?}",
            hex::encode(state.root()),
            root_after,
        );
        // switch state to new root
        let mut new_root_hash = ZkTrieHash::default();
        root_after.to_big_endian(&mut new_root_hash);
        assert!(state.switch_to(new_root_hash));
    }

    Ok(witness_block)
}

/// Build a witness block from block traces for all blocks in the chunk.
///
/// Kind of a duplication of [`self::chunk_trace_to_witness_block`], so should eventually be
/// deprecated.
fn block_traces_to_witness_block(block_traces: Vec<BlockTrace>) -> Result<Block, ChunkProverError> {
    if block_traces.is_empty() {
        return Err(ChunkProverError::Custom(
            "empty block traces! hint: use dummy_witness_block instead".to_string(),
        ));
    }
    let block_num = block_traces.len();
    let total_tx_num = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    if total_tx_num > MAX_TXS {
        return Err(ChunkProverError::Custom(format!(
            "tx num overflow {}, block range {} to {}",
            total_tx_num,
            block_traces[0].header.number.unwrap(),
            block_traces[block_num - 1].header.number.unwrap()
        )));
    }
    log::info!(
        "block_traces_to_witness_block, block num {}, tx num {}",
        block_num,
        total_tx_num,
    );
    for block_trace in block_traces.iter() {
        log::debug!("start_l1_queue_index: {}", block_trace.start_l1_queue_index);
    }

    let mut traces = block_traces.into_iter();
    let mut builder =
        CircuitInputBuilder::new_from_l2_trace(get_super_circuit_params(), traces.next().unwrap())?;
    for (idx, block_trace) in traces.enumerate() {
        log::debug!(
            "add_more_l2_trace idx {}, block num {:?}",
            idx + 1,
            block_trace.header.number
        );
        builder.add_more_l2_trace(block_trace)?;
    }
    let witness_block = finalize_builder(&mut builder)?;
    // send to other thread to drop
    std::thread::spawn(move || drop(builder.block));
    Ok(witness_block)
}

fn print_chunk_stats(block_traces: &[BlockTrace]) {
    let num_blocks = block_traces.len();
    let num_txs = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    let total_tx_len = block_traces
        .iter()
        .flat_map(|b| b.transactions.iter().map(|t| t.data.len()))
        .sum::<usize>();
    log::info!(
        "check capacity of block traces, num_block {}, num_tx {}, tx total len {}",
        num_blocks,
        num_txs,
        total_tx_len
    );
}
