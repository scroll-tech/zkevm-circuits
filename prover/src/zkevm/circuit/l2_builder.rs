use super::TargetCircuit;
use crate::{config::INNER_DEGREE, utils::read_env_var};
use anyhow::{bail, Result};
use bus_mapping::{
    circuit_input_builder::{self, CircuitInputBuilder, CircuitsParams, PrecompileEcParams},
    state_db::{CodeDB, StateDB},
};
use eth_types::{
    l2_types::{BlockTrace, StorageTrace},
    ToBigEndian, ToWord, H256,
};
use halo2_proofs::halo2curves::bn256::Fr;
use itertools::Itertools;
use mpt_zktrie::state::ZktrieState;
use once_cell::sync::Lazy;
use std::{collections::HashMap, time::Instant};
use zkevm_circuits::{
    evm_circuit::witness::{block_apply_mpt_state, block_convert_with_l1_queue_index, Block},
    util::SubCircuit,
    witness::WithdrawProof,
};

static CHAIN_ID: Lazy<u64> = Lazy::new(|| read_env_var("CHAIN_ID", 53077));
static AUTO_TRUNCATE: Lazy<bool> = Lazy::new(|| read_env_var("AUTO_TRUNCATE", false));

////// params for degree = 20 ////////////
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

/// default params for super circuit
pub fn get_super_circuit_params() -> CircuitsParams {
    CircuitsParams {
        max_evm_rows: MAX_RWS,
        max_rws: MAX_RWS,
        max_copy_rows: MAX_RWS,
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_bytecode: MAX_BYTECODE,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_keccak_rows: MAX_KECCAK_ROWS,
        max_poseidon_rows: MAX_POSEIDON_ROWS,
        max_vertical_circuit_rows: MAX_VERTICLE_ROWS,
        max_exp_steps: MAX_EXP_STEPS,
        max_mpt_rows: MAX_MPT_ROWS,
        max_rlp_rows: MAX_RLP_ROWS,
        max_ec_ops: PrecompileEcParams {
            ec_add: MAX_PRECOMPILE_EC_ADD,
            ec_mul: MAX_PRECOMPILE_EC_MUL,
            ec_pairing: MAX_PRECOMPILE_EC_PAIRING,
        },
    }
}

// TODO: optimize it later
pub fn calculate_row_usage_of_trace(
    block_trace: &BlockTrace,
) -> Result<Vec<zkevm_circuits::super_circuit::SubcircuitRowUsage>> {
    let witness_block = block_traces_to_witness_block(std::slice::from_ref(block_trace))?;
    calculate_row_usage_of_witness_block(&witness_block)
}

pub fn calculate_row_usage_of_witness_block(
    witness_block: &Block<Fr>,
) -> Result<Vec<zkevm_circuits::super_circuit::SubcircuitRowUsage>> {
    let mut rows = <super::SuperCircuit as TargetCircuit>::Inner::min_num_rows_block_subcircuits(
        witness_block,
    );
    assert_eq!(rows[10].name, "poseidon");
    assert_eq!(rows[13].name, "mpt");
    // empirical estimation is each row in mpt cost 1.5 hash (aka 12 rows)
    let mpt_poseidon_rows = rows[13].row_num_real * 12;
    if witness_block.mpt_updates.smt_traces.is_empty() {
        rows[10].row_num_real += mpt_poseidon_rows;
        log::debug!("calculate_row_usage_of_witness_block light mode, adding {mpt_poseidon_rows} poseidon rows");
    } else {
        //rows[10].row_num_real += mpt_poseidon_rows;
        log::debug!("calculate_row_usage_of_witness_block normal mode, skip adding {mpt_poseidon_rows} poseidon rows");
    }

    log::debug!(
        "row usage of block {:?}, tx num {:?}, tx calldata len sum {}, rows needed {:?}",
        witness_block
            .context
            .ctxs
            .first_key_value()
            .map_or(0.into(), |(_, ctx)| ctx.number),
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

// FIXME: we need better API name for this.
// This function also mutates the block trace.
pub fn check_batch_capacity(block_traces: &mut Vec<BlockTrace>) -> Result<()> {
    let block_traces_len = block_traces.len();
    let total_tx_count = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    let total_tx_len_sum = block_traces
        .iter()
        .flat_map(|b| b.transactions.iter().map(|t| t.data.len()))
        .sum::<usize>();
    log::info!(
        "check capacity of block traces, num_block {}, num_tx {}, tx total len {}",
        block_traces_len,
        total_tx_count,
        total_tx_len_sum
    );

    if block_traces_len > MAX_INNER_BLOCKS {
        bail!("too many blocks");
    }

    if !*AUTO_TRUNCATE {
        log::debug!("AUTO_TRUNCATE=false, keep batch as is");
        return Ok(());
    }

    let t = Instant::now();
    let mut acc: Vec<crate::zkevm::SubCircuitRowUsage> = Vec::new();
    let mut n_txs = 0;
    let mut truncate_idx = block_traces.len();
    for (idx, block) in block_traces.iter().enumerate() {
        let usage = calculate_row_usage_of_trace(block)?
            .into_iter()
            .map(|x| crate::zkevm::SubCircuitRowUsage {
                name: x.name,
                row_number: x.row_num_real,
            })
            .collect_vec();
        if acc.is_empty() {
            acc = usage.clone();
        } else {
            acc.iter_mut().zip(usage.iter()).for_each(|(acc, usage)| {
                acc.row_number += usage.row_number;
            });
        }
        let rows: usize = itertools::max(acc.iter().map(|x| x.row_number)).unwrap();
        log::debug!(
            "row usage after block {}({:?}): {}, {:?}",
            idx,
            block.header.number,
            rows,
            usage
        );
        n_txs += block.transactions.len();
        if rows > (1 << *INNER_DEGREE) - 256 || n_txs > MAX_TXS {
            log::warn!(
                "truncate blocks [{}..{}), n_txs {}, rows {}",
                idx,
                block_traces_len,
                n_txs,
                rows
            );
            truncate_idx = idx;
            break;
        }
    }
    log::debug!("check_batch_capacity takes {:?}", t.elapsed());
    block_traces.truncate(truncate_idx);
    let total_tx_count2 = block_traces
        .iter()
        .map(|b| b.transactions.len())
        .sum::<usize>();
    if total_tx_count != 0 && total_tx_count2 == 0 {
        // the circuit cannot even prove the first non-empty block...
        bail!("circuit capacity not enough");
    }
    Ok(())
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

    if let Some(mpt_state) = initial_mpt_state {
        assert_eq!(
            H256::from_slice(mpt_state.root()),
            old_root,
            "the provided zktrie state must be the prev state"
        );
        let state_db = StateDB::from(&mpt_state);
        let mut builder = CircuitInputBuilder::new(state_db, code_db, &builder_block);
        builder.mpt_init_state = mpt_state;
        builder
    } else {
        CircuitInputBuilder::new(StateDB::new(), code_db, &builder_block)
    }
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

pub fn block_traces_to_witness_block(block_traces: &[BlockTrace]) -> Result<Block<Fr>> {
    validite_block_traces(block_traces)?;
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
    for block_trace in block_traces {
        log::debug!("start_l1_queue_index: {}", block_trace.start_l1_queue_index,);
    }

    // TODO: now witness block is context senstive (?) with prev_root, start l1 index
    // etc, so the generated block maybe invalid without any message
    if block_traces.is_empty() {
        let mut builder = prepare_default_builder(eth_types::Hash::zero(), None);
        block_traces_to_witness_block_with_updated_state(&[], &mut builder, false)
    } else {
        let mut builder = CircuitInputBuilder::new_from_l2_trace(
            get_super_circuit_params(),
            &block_traces[0],
            block_traces.len() > 1,
            false,
        )?;
        block_traces_to_witness_block_with_updated_state(&block_traces[1..], &mut builder, false)
    }
}

/// update the builder with another batch of trace and then *FINALIZE* it
/// (so the buidler CAN NOT be update any more)
/// light_mode skip the time consuming calculation on mpt root for each
/// tx, currently used in row estimation
pub fn block_traces_to_witness_block_with_updated_state(
    block_traces: &[BlockTrace],
    builder: &mut CircuitInputBuilder,
    light_mode: bool,
) -> Result<Block<Fr>> {
    let metric = |builder: &CircuitInputBuilder, idx: usize| -> Result<(), bus_mapping::Error> {
        let t = Instant::now();
        let block = block_convert_with_l1_queue_index::<Fr>(
            &builder.block,
            &builder.code_db,
            builder.block.start_l1_queue_index,
        )?;
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

    for (idx, block_trace) in block_traces.iter().enumerate() {
        let is_last = idx == block_traces.len() - 1;
        log::debug!(
            "add_more_l2_trace idx {idx}, block num {:?}",
            block_trace.header.number
        );
        builder.add_more_l2_trace(block_trace, !is_last, false)?;
        if per_block_metric {
            metric(builder, idx + initial_blk_index)?;
        }
    }

    builder.finalize_building()?;
    let start_l1_queue_index = builder.block.start_l1_queue_index;

    log::debug!("converting builder.block to witness block");
    let mut witness_block =
        block_convert_with_l1_queue_index(&builder.block, &builder.code_db, start_l1_queue_index)?;
    log::debug!(
        "witness_block built with circuits_params {:?}",
        witness_block.circuits_params
    );

    if !light_mode && *builder.mpt_init_state.root() != [0u8; 32] {
        log::debug!("block_apply_mpt_state");
        block_apply_mpt_state(&mut witness_block, &builder.mpt_init_state);
        log::debug!("block_apply_mpt_state done");
    }
    log::debug!(
        "finish replay trie updates, root {}",
        hex::encode(builder.mpt_init_state.root())
    );
    Ok(witness_block)
}

pub fn normalize_withdraw_proof(proof: &WithdrawProof) -> StorageTrace {
    let address = *bus_mapping::l2_predeployed::message_queue::ADDRESS;
    let key = *bus_mapping::l2_predeployed::message_queue::WITHDRAW_TRIE_ROOT_SLOT;
    StorageTrace {
        // Not typo! We are preparing `StorageTrace` for the dummy padding chunk
        // So `post_state_root` of prev chunk will be `root_before` for new chunk
        root_before: H256::from(proof.state_root.to_be_bytes()),
        root_after: H256::from(proof.state_root.to_be_bytes()),
        proofs: Some(HashMap::from([(
            address,
            proof
                .account_proof
                .iter()
                .map(|b| b.clone().into())
                .collect(),
        )])),
        storage_proofs: HashMap::from([(
            address,
            HashMap::from([(
                key,
                proof
                    .storage_proof
                    .iter()
                    .map(|b| b.clone().into())
                    .collect(),
            )]),
        )]),
        deletion_proofs: Default::default(),
    }
}
