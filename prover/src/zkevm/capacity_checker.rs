use super::circuit::{
    MAX_BYTECODE, MAX_CALLDATA, MAX_EXP_STEPS, MAX_KECCAK_ROWS, MAX_MPT_ROWS, MAX_POSEIDON_ROWS,
    MAX_RWS, MAX_VERTICLE_ROWS,
};

use super::circuit::{
    block_traces_to_witness_block_with_updated_state, calculate_row_usage_of_witness_block,
    get_super_circuit_params,
};
use bus_mapping::{
    circuit_input_builder::{self, CircuitInputBuilder},
    state_db::{CodeDB, StateDB},
};
use eth_types::{l2_types::BlockTrace, ToWord, H256};
use itertools::Itertools;
use mpt_zktrie::state::ZktrieState;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubCircuitRowUsage {
    pub name: String,
    pub row_number: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RowUsage {
    pub is_ok: bool,
    pub row_number: usize,
    pub row_usage_details: Vec<SubCircuitRowUsage>,
}

impl Default for RowUsage {
    fn default() -> Self {
        Self::new()
    }
}

const NORMALIZED_ROW_LIMIT: usize = 1_000_000;

impl RowUsage {
    pub fn new() -> Self {
        Self {
            is_ok: true,
            row_number: 0,
            row_usage_details: Vec::new(),
        }
    }
    // We treat 1M as 100%
    pub fn normalize(&self) -> Self {
        let real_available_rows = [
            MAX_RWS,           // evm
            MAX_RWS,           // state
            MAX_BYTECODE,      // bytecode
            MAX_RWS,           // copy
            MAX_KECCAK_ROWS,   // keccak
            MAX_VERTICLE_ROWS, // tx
            MAX_CALLDATA,      // rlp
            7 * MAX_EXP_STEPS, // exp
            MAX_KECCAK_ROWS,   // modexp
            MAX_RWS,           // pi
            MAX_POSEIDON_ROWS, // poseidon
            MAX_VERTICLE_ROWS, // sig
            MAX_VERTICLE_ROWS, // ecc
            MAX_MPT_ROWS,      // mpt
        ]
        .map(|x| (x as f32 * 0.95) as usize);
        let details = self
            .row_usage_details
            .iter()
            .zip_eq(real_available_rows.iter())
            .map(|(x, limit)| SubCircuitRowUsage {
                name: x.name.clone(),
                row_number: (1_000_000u64 * (x.row_number as u64) / (*limit as u64)) as usize,
            })
            .collect_vec();
        log::debug!(
            "normalize row usage, before {:#?}\nafter {:#?}",
            self.row_usage_details,
            details
        );
        Self::from_row_usage_details(details)
    }
    pub fn from_row_usage_details(row_usage_details: Vec<SubCircuitRowUsage>) -> Self {
        let row_number = row_usage_details
            .iter()
            .map(|x| x.row_number)
            .max()
            .unwrap();
        Self {
            row_usage_details,
            row_number,
            is_ok: row_number < NORMALIZED_ROW_LIMIT,
        }
    }
    pub fn add(&mut self, other: &RowUsage) {
        if self.row_usage_details.is_empty() {
            self.row_usage_details = other.row_usage_details.clone();
        } else {
            assert_eq!(self.row_usage_details.len(), other.row_usage_details.len());
            for i in 0..self.row_usage_details.len() {
                self.row_usage_details[i].row_number += other.row_usage_details[i].row_number;
            }
        }

        self.row_number = self
            .row_usage_details
            .iter()
            .map(|x| x.row_number)
            .max()
            .unwrap();
        self.is_ok = self.row_number < NORMALIZED_ROW_LIMIT;
    }
}

#[derive(Debug, Clone)]
pub struct CircuitCapacityChecker {
    /// When "light_mode" enabled, we skip zktrie subcircuit in row estimation to avoid the heavy
    /// poseidon cost.
    pub light_mode: bool,
    pub acc_row_usage: RowUsage,
    pub row_usages: Vec<RowUsage>,
    pub builder_ctx: Option<(CodeDB, StateDB, ZktrieState)>,
}

// Currently TxTrace is same as BlockTrace, with "transactions" and "executionResults" should be of
// len 1, "storageProofs" should contain "slot touched" during when executing this tx.
pub type TxTrace = BlockTrace;

impl Default for CircuitCapacityChecker {
    fn default() -> Self {
        Self::new()
    }
}

// Used inside sequencer to estimate the row usage, so sequencer can decide when to deal a block.
impl CircuitCapacityChecker {
    pub fn new() -> Self {
        Self {
            acc_row_usage: RowUsage::new(),
            row_usages: Vec::new(),
            light_mode: true,
            builder_ctx: None,
        }
    }
    pub fn reset(&mut self) {
        self.builder_ctx = None;
        self.acc_row_usage = RowUsage::new();
        self.row_usages = Vec::new();
    }
    pub fn estimate_circuit_capacity(
        &mut self,
        txs: &[TxTrace],
    ) -> Result<RowUsage, anyhow::Error> {
        assert!(!txs.is_empty());
        let mut estimate_builder = if let Some((code_db, sdb, mpt_state)) = self.builder_ctx.take()
        {
            // here we create a new builder for another (sealed) witness block
            // this builder inherit the current execution state (sdb/cdb) of
            // the previous one and do not use zktrie state,
            // notice the prev_root in current builder may be not invalid (since the state has
            // changed but we may not update it in light mode)
            let mut builder_block =
                circuit_input_builder::Block::from_headers(&[], get_super_circuit_params());
            builder_block.chain_id = txs[0].chain_id;
            builder_block.start_l1_queue_index = txs[0].start_l1_queue_index;
            builder_block.prev_state_root = H256(*mpt_state.root()).to_word();
            let mut builder =
                CircuitInputBuilder::new_with_trie_state(sdb, code_db, mpt_state, &builder_block);
            builder.add_more_l2_trace(&txs[0], txs.len() > 1, true)?;
            builder
        } else {
            CircuitInputBuilder::new_from_l2_trace(
                get_super_circuit_params(),
                &txs[0],
                txs.len() > 1,
                true,
            )?
        };
        let traces = &txs[1..];
        let witness_block = block_traces_to_witness_block_with_updated_state(
            traces,
            &mut estimate_builder,
            self.light_mode,
        )?;
        let rows = calculate_row_usage_of_witness_block(&witness_block)?;
        let row_usage_details: Vec<SubCircuitRowUsage> = rows
            .into_iter()
            .map(|x| SubCircuitRowUsage {
                name: x.name,
                row_number: x.row_num_real,
            })
            .collect_vec();
        let tx_row_usage = RowUsage::from_row_usage_details(row_usage_details);
        self.row_usages.push(tx_row_usage.clone());
        self.acc_row_usage.add(&tx_row_usage);
        self.builder_ctx.replace((
            estimate_builder.code_db,
            estimate_builder.sdb,
            estimate_builder.mpt_init_state,
        ));
        Ok(self.acc_row_usage.normalize())
    }
}
