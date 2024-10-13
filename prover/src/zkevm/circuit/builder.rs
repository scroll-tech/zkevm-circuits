use crate::zkevm::SubCircuitRowUsage;
use anyhow::{bail, Result};
use bus_mapping::circuit_input_builder::CircuitInputBuilder;
use eth_types::{l2_types::BlockTrace, ToWord};
use itertools::Itertools;
use mpt_zktrie::state::ZkTrieHash;
use zkevm_circuits::{
    evm_circuit::witness::Block,
    super_circuit::params::{get_super_circuit_params, ScrollSuperCircuit, MAX_TXS},
    witness::block_convert,
};

pub fn calculate_row_usage_of_witness_block(
    witness_block: &Block,
) -> Result<Vec<SubCircuitRowUsage>> {
    let rows = ScrollSuperCircuit::min_num_rows_block_subcircuits(witness_block);

    // Check whether we need to "estimate" poseidon sub circuit row usage
    if witness_block.mpt_updates.smt_traces.is_empty() {
        bail!("light mode no longer supported");
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
    let row_usage_details: Vec<SubCircuitRowUsage> = rows
        .into_iter()
        .map(|x| SubCircuitRowUsage {
            name: x.name,
            row_number: x.row_num_real,
        })
        .collect_vec();
    Ok(row_usage_details)
}

pub fn print_chunk_stats(block_traces: &[BlockTrace]) {
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

pub fn dummy_witness_block() -> Result<Block> {
    log::debug!("generate dummy witness block");
    let dummy_chain_id = 0;
    let witness_block = zkevm_circuits::witness::dummy_witness_block(dummy_chain_id);
    log::debug!("generate dummy witness block done");
    Ok(witness_block)
}

pub fn block_traces_to_witness_block(block_traces: Vec<BlockTrace>) -> Result<Block> {
    if block_traces.is_empty() {
        bail!("use dummy_witness_block instead");
    }
    let block_num = block_traces.len();
    let total_tx_num = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    if total_tx_num > MAX_TXS {
        bail!(
            "tx num overflow {}, block range {} to {}",
            total_tx_num,
            block_traces[0].header.number.unwrap(),
            block_traces[block_num - 1].header.number.unwrap()
        );
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

/// Finalize building and return witness block
pub fn finalize_builder(builder: &mut CircuitInputBuilder) -> Result<Block> {
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
