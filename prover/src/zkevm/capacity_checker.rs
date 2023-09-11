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
            (MAX_RWS, 0.95),           // evm
            (MAX_RWS, 0.95),           // state
            (MAX_BYTECODE, 0.95),      // bytecode
            (MAX_RWS, 0.95),           // copy
            (MAX_KECCAK_ROWS, 0.95),   // keccak
            (MAX_VERTICLE_ROWS, 0.95), // tx
            (MAX_CALLDATA, 0.95),      // rlp
            (7 * MAX_EXP_STEPS, 0.95), // exp
            (MAX_KECCAK_ROWS, 0.95),   // modexp
            (MAX_RWS, 0.95),           // pi
            (MAX_POSEIDON_ROWS, 0.95), // poseidon
            (MAX_VERTICLE_ROWS, 0.95), // sig
            (MAX_VERTICLE_ROWS, 1.0),  // ecc
            (MAX_MPT_ROWS, 0.95),      // mpt
        ]
        .map(|(limit, confidence)| (limit as f32 * confidence) as usize);
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
            is_ok: row_number <= NORMALIZED_ROW_LIMIT,
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
        self.is_ok = self.row_number <= NORMALIZED_ROW_LIMIT;
    }
}

#[derive(Debug)]
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
    pub fn get_tx_num(&self) -> usize {
        self.row_usages.len()
    }
    pub fn get_acc_row_usage(&self, normalize: bool) -> RowUsage {
        if normalize {
            self.acc_row_usage.normalize()
        } else {
            self.acc_row_usage.clone()
        }
    }
    pub fn estimate_circuit_capacity(
        &mut self,
        txs: &[TxTrace],
    ) -> Result<RowUsage, anyhow::Error> {
        log::debug!("estimate_circuit_capacity with txs num {}", txs.len());
        assert!(!txs.is_empty());
        let (mut estimate_builder, codedb_prev) =
            if let Some((code_db, sdb, mpt_state)) = self.builder_ctx.take() {
                // here we create a new builder for another (sealed) witness block
                // this builder inherit the current execution state (sdb) of
                // the previous one and do not use zktrie state,
                // notice the prev_root in current builder may be not invalid (since the state has
                // changed but we may not update it in light mode)
                let mut builder_block =
                    circuit_input_builder::Block::from_headers(&[], get_super_circuit_params());
                builder_block.chain_id = txs[0].chain_id;
                builder_block.start_l1_queue_index = txs[0].start_l1_queue_index;
                builder_block.prev_state_root = H256(*mpt_state.root()).to_word();
                // notice the trace has included all code required for builidng witness block,
                // so we do not need to pick them from previous one, but we still keep the
                // old codedb in previous run for some dedup work
                let mut builder = CircuitInputBuilder::new_with_trie_state(
                    sdb,
                    CodeDB::new(),
                    mpt_state,
                    &builder_block,
                );
                builder.add_more_l2_trace(&txs[0], txs.len() > 1, self.light_mode)?;
                (builder, Some(code_db))
            } else {
                (
                    CircuitInputBuilder::new_from_l2_trace(
                        get_super_circuit_params(),
                        &txs[0],
                        txs.len() > 1,
                        self.light_mode,
                    )?,
                    None,
                )
            };
        let traces = &txs[1..];
        let witness_block = block_traces_to_witness_block_with_updated_state(
            traces,
            &mut estimate_builder,
            self.light_mode,
        )?;
        let mut rows = calculate_row_usage_of_witness_block(&witness_block)?;

        let mut code_db = codedb_prev.unwrap_or_else(CodeDB::new);
        // merge current codes with previous , and dedup bytecode row usage
        // for bytecode circuit / poseidon circuit
        for (hash, bytes) in estimate_builder.code_db.0 {
            let bytes_len = bytes.len();
            // code for current run has been evaluated in previous
            if code_db.0.insert(hash, bytes).is_some() {
                assert_eq!(rows[2].name, "bytecode");
                rows[2].row_num_real -= bytes_len + 1;
                assert_eq!(rows[10].name, "poseidon");
                rows[10].row_num_real -= bytes_len / (31 * 2) * 9;
            }
        }

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
            code_db,
            estimate_builder.sdb,
            estimate_builder.mpt_init_state,
        ));
        Ok(self.acc_row_usage.normalize())
    }
}
