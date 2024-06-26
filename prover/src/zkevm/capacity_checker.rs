use super::circuit::{calculate_row_usage_of_witness_block, finalize_builder};
use bus_mapping::circuit_input_builder::{self, CircuitInputBuilder};
use eth_types::{
    l2_types::BlockTrace,
    state_db::{CodeDB, StateDB},
    H256,
};
use halo2_proofs::halo2curves::bn256::Fr;
use itertools::Itertools;
use mpt_zktrie::state::ZktrieState;
use serde_derive::{Deserialize, Serialize};
use zkevm_circuits::{
    poseidon_circuit::{Hashable, HASH_BLOCK_STEP_SIZE},
    super_circuit::params::{get_sub_circuit_limit_and_confidence, get_super_circuit_params},
};

pub use super::SubCircuitRowUsage;

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
        let real_available_rows: Vec<_> = get_sub_circuit_limit_and_confidence()
            .into_iter()
            .map(|(limit, confidence)| (limit as f64 * confidence) as usize)
            .collect();
        let details = self
            .row_usage_details
            .iter()
            .zip_eq(real_available_rows.iter())
            .map(|(x, limit)| SubCircuitRowUsage {
                name: x.name.clone(),
                row_number: (1_000_000u64 * (x.row_number as u64) / (*limit as u64)) as usize,
            })
            .collect_vec();
        log::trace!(
            "normalize row usage, before {:?}\nafter {:?}",
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
    pub builder_ctx: Option<(CodeDB, StateDB, Option<ZktrieState>)>,
}

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
    pub fn set_light_mode(&mut self, light_mode: bool) {
        self.light_mode = light_mode;
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
        trace: BlockTrace,
    ) -> Result<RowUsage, anyhow::Error> {
        let (mut estimate_builder, codedb_prev) =
            if let Some((code_db, sdb, mpt_state)) = self.builder_ctx.take() {
                // here we create a new builder for another (sealed) witness block
                // this builder inherit the current execution state (sdb) of
                // the previous one and do not use zktrie state,
                // notice the prev_root in current builder may be not invalid (since the state has
                // changed but we may not update it in light mode)
                let mut builder_block =
                    circuit_input_builder::Blocks::init(trace.chain_id, get_super_circuit_params());
                builder_block.start_l1_queue_index = trace.start_l1_queue_index;
                builder_block.prev_state_root = mpt_state
                    .as_ref()
                    .map(|state| state.root())
                    .map(|root| H256(*root))
                    .unwrap_or(trace.header.state_root);
                // notice the trace has included all code required for builidng witness block,
                // so we do not need to pick them from previous one, but we still keep the
                // old codedb in previous run for some dedup work
                let mut builder = if let Some(mpt_state) = mpt_state {
                    CircuitInputBuilder::new_with_trie_state(
                        sdb,
                        CodeDB::new(),
                        mpt_state,
                        &builder_block,
                    )
                } else {
                    CircuitInputBuilder::new(sdb, CodeDB::new(), &builder_block)
                };
                builder.add_more_l2_trace(trace)?;
                (builder, Some(code_db))
            } else {
                (
                    CircuitInputBuilder::new_from_l2_trace(
                        get_super_circuit_params(),
                        trace,
                        self.light_mode,
                    )?,
                    None,
                )
            };
        let witness_block = finalize_builder(&mut estimate_builder)?;
        let mut rows = calculate_row_usage_of_witness_block(&witness_block)?;

        let mut code_db = codedb_prev.unwrap_or_else(CodeDB::new);
        // merge current codes with previous , and dedup bytecode row usage
        // for bytecode circuit / poseidon circuit
        for (hash, bytes) in estimate_builder.code_db.0 {
            let bytes_len = bytes.len();
            // code for current run has been evaluated in previous
            if code_db.0.insert(hash, bytes).is_some() {
                assert_eq!(rows[2].name, "bytecode");
                rows[2].row_number -= bytes_len + 1;
                assert_eq!(rows[11].name, "poseidon");
                rows[11].row_number -= bytes_len / HASH_BLOCK_STEP_SIZE * Fr::hash_block_size();
            }
        }
        let tx_row_usage = RowUsage::from_row_usage_details(rows);
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
