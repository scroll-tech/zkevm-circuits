use super::TargetCircuit;
use crate::utils::read_env_var;
use anyhow::{bail, Result};
use bus_mapping::circuit_input_builder::{self, CircuitInputBuilder};
use eth_types::{
    l2_types::BlockTrace,
    state_db::{CodeDB, StateDB},
    ToWord, H256,
};
use mpt_zktrie::state::{ZkTrieHash, ZktrieState};
use std::{sync::LazyLock, time::Instant};
use zkevm_circuits::{
    evm_circuit::witness::Block,
    super_circuit::params::{get_super_circuit_params, MAX_TXS},
    util::SubCircuit,
    witness::block_convert,
};

static CHAIN_ID: LazyLock<u64> = LazyLock::new(|| read_env_var("CHAIN_ID", 53077));

pub fn calculate_row_usage_of_witness_block(
    witness_block: &Block,
) -> Result<Vec<zkevm_circuits::super_circuit::SubcircuitRowUsage>> {
    let mut rows = <super::SuperCircuit as TargetCircuit>::Inner::min_num_rows_block_subcircuits(
        witness_block,
    );
    // Check whether we need to "estimate" poseidon sub circuit row usage
    if witness_block.mpt_updates.smt_traces.is_empty() {
        assert_eq!(rows[11].name, "poseidon");
        assert_eq!(rows[14].name, "mpt");
        // We collected real metrics from Scroll mainnet, and here is the graph
        // https://ibb.co/gVfvW7h
        // 6 is already very very conservative. Besides, considering a chunk consists of many txs,
        // using this number is safe.
        let poseidon_estimate_ratio = if witness_block.txs.len() > 1 {
            // follower ccc
            6
        } else {
            // singer ccc or single tx block follower ccc,
            // even i think 6 is safe, here we still keep the old value
            12
        };
        let mpt_poseidon_rows = rows[14].row_num_real * poseidon_estimate_ratio;
        rows[11].row_num_real += mpt_poseidon_rows;
        log::debug!("calculate_row_usage_of_witness_block light mode, adding {mpt_poseidon_rows} poseidon rows");
    } else {
        log::debug!("calculate_row_usage_of_witness_block normal mode, skip adding poseidon rows");
    }
    let first_block_num = witness_block
        .context
        .ctxs
        .first_key_value()
        .map_or(0.into(), |(_, ctx)| ctx.number);
    let last_block_num = witness_block
        .context
        .ctxs
        .last_key_value()
        .map_or(0.into(), |(_, ctx)| ctx.number);
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
    Ok(rows)
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

// prepare an empty builder which can updated by more trace
// from the default settings
// only require the prev state root being provided
// any initial zktrie state can be also set
fn prepare_default_builder(
    old_root: H256,
    initial_mpt_state: Option<ZktrieState>,
) -> CircuitInputBuilder {
    let mut builder_block =
        circuit_input_builder::Block::from_headers(&[], get_super_circuit_params());
    builder_block.chain_id = *CHAIN_ID;
    builder_block.prev_state_root = old_root.to_word();
    let code_db = CodeDB::new();

    if let Some(mpt_state) = &initial_mpt_state {
        assert_eq!(
            H256::from_slice(mpt_state.root()),
            old_root,
            "the provided zktrie state must be the prev state"
        );
    }

    let mut builder = CircuitInputBuilder::new(StateDB::new(), code_db, &builder_block);
    builder.mpt_init_state = initial_mpt_state;
    builder
}

/// check if block traces match preset parameters
pub fn validite_block_traces(block_traces: &[BlockTrace]) -> Result<()> {
    let chain_id = block_traces
        .iter()
        .map(|block_trace| block_trace.chain_id)
        .next()
        .unwrap_or(*CHAIN_ID);
    if *CHAIN_ID != chain_id {
        bail!(
            "CHAIN_ID env var is wrong. chain id in trace {chain_id}, CHAIN_ID {}",
            *CHAIN_ID
        );
    }
    Ok(())
}

pub fn block_trace_to_witness_block(block_trace: BlockTrace) -> Result<Block> {
    let chain_id = block_trace.chain_id;
    if *CHAIN_ID != chain_id {
        bail!(
            "CHAIN_ID env var is wrong. chain id in trace {chain_id}, CHAIN_ID {}",
            *CHAIN_ID
        );
    }
    let total_tx_num = block_trace.transactions.len();
    if total_tx_num > MAX_TXS {
        bail!(
            "block {}tx num overflow {total_tx_num}",
            block_trace.header.number.unwrap()
        );
    }
    log::info!("block_trace_to_witness_block, tx num {total_tx_num}");
    log::debug!("start_l1_queue_index: {}", block_trace.start_l1_queue_index);
    let mut builder = CircuitInputBuilder::new_from_l2_trace(
        get_super_circuit_params(),
        block_trace,
        false,
        false,
    )?;
    block_traces_to_witness_block_with_updated_state(vec![], &mut builder)
}

pub fn block_traces_to_witness_block(block_traces: Vec<BlockTrace>) -> Result<Block> {
    validite_block_traces(&block_traces)?;
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
        log::debug!("start_l1_queue_index: {}", block_trace.start_l1_queue_index,);
    }

    // TODO: now witness block is context senstive (?) with prev_root, start l1 index
    // etc, so the generated block maybe invalid without any message
    if block_traces.is_empty() {
        let mut builder = prepare_default_builder(eth_types::Hash::zero(), None);
        block_traces_to_witness_block_with_updated_state(vec![], &mut builder)
    } else {
        let block_traces_len = block_traces.len();
        let mut traces = block_traces.into_iter();
        let mut builder = CircuitInputBuilder::new_from_l2_trace(
            get_super_circuit_params(),
            traces.next().unwrap(),
            block_traces_len > 1,
            false,
        )?;
        let witness = block_traces_to_witness_block_with_updated_state(
            traces.collect(), // this is a cold path
            &mut builder,
        );
        // send to other thread to drop
        std::thread::spawn(move || drop(builder.block));
        witness
    }
}

/// update the builder with another chunk of trace and then *FINALIZE* it
/// (so the buidler CAN NOT be update any more)
/// light_mode skip the time consuming calculation on mpt root for each
/// tx, currently used in row estimation
pub fn block_traces_to_witness_block_with_updated_state(
    block_traces: Vec<BlockTrace>,
    builder: &mut CircuitInputBuilder,
) -> Result<Block> {
    let metric = |builder: &CircuitInputBuilder, idx: usize| -> Result<(), bus_mapping::Error> {
        let t = Instant::now();
        let block = block_convert(&builder.block.clone(), &builder.code_db)?;
        log::debug!("block convert time {:?}", t.elapsed());
        let rows = <super::SuperCircuit as TargetCircuit>::Inner::min_num_rows_block(&block);
        log::debug!(
            "after block {}, tx num {:?}, tx len sum {}, rows needed {:?}. estimate time: {:?}",
            idx,
            builder.block.txs().len(),
            builder
                .block
                .txs()
                .iter()
                .map(|t| t.input.len())
                .sum::<usize>(),
            rows,
            t.elapsed()
        );
        Ok(())
    };

    // TODO: enable this switch
    let per_block_metric = false;

    let initial_blk_index = if builder.block.txs.is_empty() {
        0
    } else {
        if per_block_metric {
            metric(builder, 0)?;
        }
        1
    };

    let block_traces_len = block_traces.len();
    for (idx, block_trace) in block_traces.into_iter().enumerate() {
        let is_last = idx == block_traces_len - 1;
        log::debug!(
            "add_more_l2_trace idx {idx}, block num {:?}",
            block_trace.header.number
        );
        builder.add_more_l2_trace(block_trace, !is_last)?;
        if per_block_metric {
            metric(builder, idx + initial_blk_index)?;
        }
    }

    builder.finalize_building()?;

    log::debug!("converting builder.block to witness block");

    let mut witness_block = block_convert(&builder.block, &builder.code_db)?;
    log::debug!(
        "witness_block built with circuits_params {:?}",
        witness_block.circuits_params
    );

    if let Some(state) = &mut builder.mpt_init_state {
        if *state.root() != [0u8; 32] {
            log::debug!("block_apply_mpt_state");
            witness_block.apply_mpt_updates(state);
            log::debug!("block_apply_mpt_state done");
        };
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
