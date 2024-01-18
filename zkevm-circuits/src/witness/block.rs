use ethers_core::types::Signature;
use std::collections::{BTreeMap, HashMap};

#[cfg(any(feature = "test", test))]
use crate::evm_circuit::{detect_fixed_table_tags, EvmCircuit};

use crate::{
    evm_circuit::util::rlc,
    table::{BlockContextFieldTag, RwTableTag},
    util::SubCircuit,
};
use bus_mapping::{
    circuit_input_builder::{
        self, BigModExp, CircuitsParams, CopyEvent, EcAddOp, EcMulOp, EcPairingOp, ExpEvent,
        PrecompileEvents, SHA256,
    },
    Error,
};
use eth_types::{sign_types::SignData, Address, Field, ToLittleEndian, ToScalar, Word, U256};
use halo2_proofs::circuit::Value;
use itertools::Itertools;

use super::{
    mpt::ZktrieState as MptState, step::step_convert, tx::tx_convert, Bytecode, ExecStep,
    MptUpdates, RwMap, Transaction,
};
use crate::util::Challenges;

// TODO: Remove fields that are duplicated in`eth_block`
/// Block is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default)]
pub struct Block<F> {
    /// For historical reasons..
    pub _marker: std::marker::PhantomData<F>,
    /// Transactions in the block
    pub txs: Vec<Transaction>,
    /// Signatures in the block
    pub sigs: Vec<Signature>,
    /// EndBlock step that is repeated after the last transaction and before
    /// reaching the last EVM row.
    pub end_block_not_last: ExecStep,
    /// Last EndBlock step that appears in the last EVM row.
    pub end_block_last: ExecStep,
    /// Read write events in the RwTable
    pub rws: RwMap,
    /// Bytecode used in the block
    pub bytecodes: BTreeMap<Word, Bytecode>,
    /// The block context
    pub context: BlockContexts,
    /// Copy events for the copy circuit's table.
    pub copy_events: Vec<CopyEvent>,
    /// Exponentiation traces for the exponentiation circuit's table.
    pub exp_events: Vec<ExpEvent>,
    /// Circuit Setup Parameters
    pub circuits_params: CircuitsParams,
    /// Inputs to the SHA3 opcode
    pub sha3_inputs: Vec<Vec<u8>>,
    /// State root of the previous block
    pub prev_state_root: Word, // TODO: Make this H256
    /// State root after the block, is set if block_apply_mpt_state is called
    pub state_root: Option<Word>, // TODO: Make this H256
    /// Withdraw root
    pub withdraw_root: Word,
    /// Withdraw roof of the previous block
    pub prev_withdraw_root: Word,
    /// Keccak inputs
    pub keccak_inputs: Vec<Vec<u8>>,
    /// Mpt updates
    pub mpt_updates: MptUpdates,
    /// Chain ID
    pub chain_id: u64,
    /// StartL1QueueIndex
    pub start_l1_queue_index: u64,
    /// IO to/from precompile calls.
    pub precompile_events: PrecompileEvents,
}

/// ...
#[derive(Debug, Default, Clone)]
pub struct BlockContexts {
    /// Hashmap that maps block number to its block context.
    pub ctxs: BTreeMap<u64, BlockContext>,
    /// relax mode flag inherited from block builder
    pub relax_mode: bool,
}

impl<F: Field> Block<F> {
    /// For each tx, for each step, print the rwc at the beginning of the step,
    /// and all the rw operations of the step.
    pub(crate) fn debug_print_txs_steps_rw_ops(&self) {
        for (tx_idx, tx) in self.txs.iter().enumerate() {
            println!("tx {tx_idx}");
            for step in &tx.steps {
                println!(" step {:?} rwc: {}", step.execution_state, step.rw_counter);
                for rw_ref in &step.rw_indices {
                    println!("  - {:?}", self.rws[*rw_ref]);
                }
            }
        }
    }

    /// Get signature (witness) from the block for tx signatures and ecRecover calls.
    pub(crate) fn get_sign_data(&self, padding: bool) -> Vec<SignData> {
        let mut signatures: Vec<SignData> = self
            .txs
            .iter()
            // Since L1Msg tx does not have signature, it do not need to do lookup into sig table
            .filter(|tx| !tx.tx_type.is_l1_msg())
            .map(|tx| tx.sign_data())
            .filter_map(|res| res.ok())
            .collect::<Vec<SignData>>();
        signatures.extend_from_slice(&self.precompile_events.get_ecrecover_events());
        if padding && self.txs.len() < self.circuits_params.max_txs {
            // padding tx's sign data
            signatures.push(Transaction::dummy(self.chain_id).sign_data().unwrap());
        }
        signatures
    }

    /// Get EcAdd operations from all precompiled contract calls in this block.
    pub(crate) fn get_ec_add_ops(&self) -> Vec<EcAddOp> {
        self.precompile_events.get_ec_add_events()
    }

    /// Get EcMul operations from all precompiled contract calls in this block.
    pub(crate) fn get_ec_mul_ops(&self) -> Vec<EcMulOp> {
        self.precompile_events.get_ec_mul_events()
    }

    /// Get EcPairing operations from all precompiled contract calls in this block.
    pub(crate) fn get_ec_pairing_ops(&self) -> Vec<EcPairingOp> {
        self.precompile_events.get_ec_pairing_events()
    }

    /// Get BigModexp operations from all precompiled contract calls in this block.
    pub(crate) fn get_big_modexp(&self) -> Vec<BigModExp> {
        self.precompile_events.get_modexp_events()
    }

    /// Get sha256 operations from all precompiled contract calls in this block.
    pub(crate) fn get_sha256(&self) -> Vec<SHA256> {
        self.precompile_events.get_sha256_events()
    }

    pub(crate) fn print_evm_circuit_row_usage(&self) {
        let mut num_rows = 0;
        let mut counter = HashMap::new();
        let mut step_num = 0;
        for transaction in &self.txs {
            step_num += transaction.steps.len();
            for step in &transaction.steps {
                let height = step.execution_state.get_step_height();
                num_rows += height;
                *counter.entry(step.execution_state).or_insert(0) += height;
            }
        }
        // TODO: change to log::trace?
        let mut counter_vec: Vec<_> = counter.into_iter().collect();
        // DESC
        counter_vec.sort_by_key(|(_e, c)| -(*c as i64));
        let print_top_k = 10;
        for (idx, (e, usage)) in counter_vec.iter().enumerate() {
            if idx > print_top_k {
                break;
            }
            let height = e.get_step_height();
            log::debug!(
                "evm circuit row usage: {:?}, step ratio {}, row ratio {}, height {}",
                e,
                (usage / height) as f64 / step_num as f64,
                *usage as f64 / num_rows as f64,
                height
            );
        }
    }

    pub(crate) fn print_rw_usage(&self) {
        // opcode -> (count, mem_rw_len, stack_rw_len)
        let mut opcode_info_map = BTreeMap::new();
        for t in &self.txs {
            for step in &t.steps {
                if let Some(op) = step.opcode {
                    opcode_info_map.entry(op).or_insert((0, 0, 0));
                    let mut values = opcode_info_map[&op];
                    values.0 += 1;
                    values.1 += step
                        .rw_indices
                        .iter()
                        .filter(|rw| rw.0 == RwTableTag::Memory)
                        .count();
                    values.2 += step
                        .rw_indices
                        .iter()
                        .filter(|rw| rw.0 == RwTableTag::Stack)
                        .count();
                    opcode_info_map.insert(op, values);
                }
            }
        }
        for (op, (count, mem, stack)) in opcode_info_map
            .iter()
            .sorted_by_key(|(_, (_, m, _))| m)
            .rev()
        {
            log::debug!(
                "op {:?}, count {}, memory_word rw {}(avg {:.2}), stack rw {}(avg {:.2})",
                op,
                count,
                mem,
                *mem as f32 / *count as f32,
                stack,
                *stack as f32 / *count as f32
            );
        }
        log::debug!("memory_word num: {}", self.rws.rw_num(RwTableTag::Memory));
        log::debug!("stack num: {}", self.rws.rw_num(RwTableTag::Stack));
        log::debug!(
            "storage num: {}",
            self.rws.rw_num(RwTableTag::AccountStorage)
        );
        log::debug!(
            "tx_access_list_account num: {}",
            self.rws.rw_num(RwTableTag::TxAccessListAccount)
        );
        log::debug!(
            "tx_access_list_account_storage num: {}",
            self.rws.rw_num(RwTableTag::TxAccessListAccountStorage)
        );
        log::debug!("tx_refund num: {}", self.rws.rw_num(RwTableTag::TxRefund));
        log::debug!("account num: {}", self.rws.rw_num(RwTableTag::Account));
        log::debug!(
            "call_context num: {}",
            self.rws.rw_num(RwTableTag::CallContext)
        );
        log::debug!("tx_receipt num: {}", self.rws.rw_num(RwTableTag::TxReceipt));
        log::debug!("tx_log num: {}", self.rws.rw_num(RwTableTag::TxLog));
        log::debug!("start num: {}", self.rws.rw_num(RwTableTag::Start));
    }
}

#[cfg(feature = "test")]
use crate::exp_circuit::param::OFFSET_INCREMENT;
use crate::tx_circuit::TX_LEN;
#[cfg(feature = "test")]
use crate::util::log2_ceil;

#[cfg(feature = "test")]
impl<F: Field> Block<F> {
    /// Obtains the expected Circuit degree needed in order to be able to test
    /// the EvmCircuit with this block without needing to configure the
    /// `ConstraintSystem`.
    pub fn get_evm_test_circuit_degree(&self) -> u32 {
        let num_rows_required_for_execution_steps: usize =
            EvmCircuit::<F>::get_num_rows_required(self);
        let num_rows_required_for_rw_table: usize = self.circuits_params.max_rws;
        let num_rows_required_for_fixed_table: usize = detect_fixed_table_tags(self)
            .iter()
            .map(|tag| tag.build::<F>().count())
            .sum();
        let num_rows_required_for_bytecode_table: usize = self
            .bytecodes
            .values()
            .map(|bytecode| bytecode.bytes.len() + 1)
            .sum();
        let num_rows_required_for_copy_table: usize = self
            .copy_events
            .iter()
            .map(|c| c.copy_bytes.bytes.len() * 2)
            .sum();
        let num_rows_required_for_keccak_table: usize = self.keccak_inputs.len();
        // tx_table load only does tx padding, no calldata padding
        let num_rows_required_for_tx_table: usize = self.circuits_params.max_txs * TX_LEN
            + self.txs.iter().map(|tx| tx.call_data.len()).sum::<usize>();
        let num_rows_required_for_exp_table: usize = self
            .exp_events
            .iter()
            .map(|e| e.steps.len() * OFFSET_INCREMENT)
            .sum();

        let rows_needed: usize = itertools::max([
            num_rows_required_for_execution_steps,
            num_rows_required_for_rw_table,
            num_rows_required_for_fixed_table,
            num_rows_required_for_bytecode_table,
            num_rows_required_for_copy_table,
            num_rows_required_for_keccak_table,
            num_rows_required_for_tx_table,
            num_rows_required_for_exp_table,
        ])
        .unwrap();

        let k = log2_ceil(EvmCircuit::<F>::unusable_rows() + rows_needed);
        log::debug!(
            "num_rows_required_for rw_table={}, fixed_table={}, bytecode_table={}, \
            copy_table={}, keccak_table={}, tx_table={}, exp_table={}",
            num_rows_required_for_rw_table,
            num_rows_required_for_fixed_table,
            num_rows_required_for_bytecode_table,
            num_rows_required_for_copy_table,
            num_rows_required_for_keccak_table,
            num_rows_required_for_tx_table,
            num_rows_required_for_exp_table
        );
        log::debug!("circuit uses k = {}, rows = {}", k, rows_needed);
        k
    }
}

/// Block context for execution
#[derive(Debug, Clone)]
pub struct BlockContext {
    /// The address of the miner for the block
    pub coinbase: Address,
    /// The gas limit of the block
    pub gas_limit: u64,
    /// The number of the block
    pub number: Word,
    /// The timestamp of the block
    pub timestamp: Word,
    /// The difficulty of the block
    pub difficulty: Word,
    /// The base fee, the minimum amount of gas fee for a transaction
    pub base_fee: Word,
    /// The hash of previous blocks
    pub history_hashes: Vec<Word>,
    /// The chain id
    pub chain_id: u64,
    /// Original Block from geth
    pub eth_block: eth_types::Block<eth_types::Transaction>,
}

impl BlockContext {
    /// Assignments for block table
    pub fn table_assignments<F: Field>(
        &self,
        num_txs: usize,
        cum_num_txs: usize,
        num_all_txs: u64,
        challenges: &Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 3]> {
        let current_block_number = self.number.to_scalar().unwrap();
        let randomness = challenges.evm_word();
        [
            vec![
                [
                    Value::known(F::from(BlockContextFieldTag::Coinbase as u64)),
                    Value::known(current_block_number),
                    Value::known(self.coinbase.to_scalar().unwrap()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Timestamp as u64)),
                    Value::known(current_block_number),
                    Value::known(self.timestamp.to_scalar().unwrap()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Number as u64)),
                    Value::known(current_block_number),
                    Value::known(current_block_number),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Difficulty as u64)),
                    Value::known(current_block_number),
                    randomness.map(|rand| rlc::value(&self.difficulty.to_le_bytes(), rand)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::GasLimit as u64)),
                    Value::known(current_block_number),
                    Value::known(F::from(self.gas_limit)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::BaseFee as u64)),
                    Value::known(current_block_number),
                    randomness
                        .map(|randomness| rlc::value(&self.base_fee.to_le_bytes(), randomness)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::ChainId as u64)),
                    Value::known(current_block_number),
                    Value::known(F::from(self.chain_id)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::NumTxs as u64)),
                    Value::known(current_block_number),
                    Value::known(F::from(num_txs as u64)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::CumNumTxs as u64)),
                    Value::known(current_block_number),
                    Value::known(F::from(cum_num_txs as u64)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::NumAllTxs as u64)),
                    Value::known(current_block_number),
                    Value::known(F::from(num_all_txs)),
                ],
            ],
            self.block_hash_assignments(randomness),
        ]
        .concat()
    }

    fn block_hash_assignments<F: Field>(&self, randomness: Value<F>) -> Vec<[Value<F>; 3]> {
        use eth_types::ToWord;

        #[cfg(not(feature = "scroll"))]
        let history_hashes: &[U256] = &self.history_hashes;
        #[cfg(feature = "scroll")]
        let history_hashes: &[U256] = &[]; // block_hash is computed as keccak256(chain_id || block_number)

        let len_history = history_hashes.len();

        history_hashes
            .iter()
            .enumerate()
            .map(|(idx, hash)| {
                let block_number = self
                    .number
                    .low_u64()
                    .checked_sub((len_history - idx) as u64)
                    .unwrap_or_default();
                if block_number + 1 == self.number.low_u64() {
                    debug_assert_eq!(self.eth_block.parent_hash.to_word(), hash.into());
                }
                [
                    Value::known(F::from(BlockContextFieldTag::BlockHash as u64)),
                    Value::known(F::from(block_number)),
                    randomness.map(|randomness| rlc::value(&hash.to_le_bytes(), randomness)),
                ]
            })
            .collect()
    }
}

impl From<&circuit_input_builder::Block> for BlockContexts {
    fn from(block: &circuit_input_builder::Block) -> Self {
        Self {
            ctxs: block
                .headers
                .values()
                .map(|block| {
                    (
                        block.number.as_u64(),
                        BlockContext {
                            coinbase: block.coinbase,
                            gas_limit: block.gas_limit,
                            number: block.number,
                            timestamp: block.timestamp,
                            difficulty: block.difficulty,
                            base_fee: block.base_fee,
                            history_hashes: block.history_hashes.clone(),
                            chain_id: block.chain_id,
                            eth_block: block.eth_block.clone(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            relax_mode: block.is_relaxed(),
        }
    }
}

/// Convert a block struct in bus-mapping to a witness block used in circuits
pub fn block_convert<F: Field>(
    block: &circuit_input_builder::Block,
    code_db: &bus_mapping::state_db::CodeDB,
) -> Result<Block<F>, Error> {
    let rws = RwMap::from(&block.container);
    rws.check_value()?;
    let num_txs = block.txs().len();
    let last_block_num = block
        .headers
        .iter()
        .next_back()
        .map(|(k, _)| *k)
        .unwrap_or_default();
    let chain_id = block.chain_id();
    rws.check_rw_counter_sanity();
    let end_block_not_last = step_convert(&block.block_steps.end_block_not_last, last_block_num);
    let end_block_last = step_convert(&block.block_steps.end_block_last, last_block_num);
    log::trace!(
        "witness block: end_block_not_last {:?}, end_block_last {:?}",
        end_block_not_last,
        end_block_last
    );
    let max_rws = if block.circuits_params.max_rws == 0 {
        end_block_last.rw_counter + end_block_last.rw_indices.len() + 1
    } else {
        block.circuits_params.max_rws
    };

    let mpt_updates = MptUpdates::from_unsorted_rws_with_mock_state_roots(
        &rws.table_assignments_unsorted(),
        block.prev_state_root,
        block.end_state_root(),
    );

    let _withdraw_root_check_rw = if end_block_last.rw_counter == 0 {
        0
    } else {
        end_block_last.rw_counter + 1
    };
    let total_tx_as_txid = num_txs;
    let withdraw_root_entry = mpt_updates.get(&super::rw::Rw::AccountStorage {
        tx_id: total_tx_as_txid,
        account_address: *bus_mapping::l2_predeployed::message_queue::ADDRESS,
        storage_key: bus_mapping::l2_predeployed::message_queue::WITHDRAW_TRIE_ROOT_SLOT,
        // following field is not used in Mpt::Key so we just fill them arbitrarily
        rw_counter: 0,
        is_write: false,
        value: U256::zero(),
        value_prev: U256::zero(),
        committed_value: U256::zero(),
    });
    if let Some(entry) = withdraw_root_entry {
        let (withdraw_root, _) = entry.values();
        if block.withdraw_root != withdraw_root {
            log::error!(
                "new withdraw root non consistent ({:#x}, vs ,{:#x})",
                block.withdraw_root,
                withdraw_root,
            );
        }
    } else {
        log::error!("withdraw root is not avaliable");
    }

    Ok(Block {
        _marker: Default::default(),
        context: block.into(),
        rws,
        txs: block
            .txs()
            .iter()
            .enumerate()
            .map(|(idx, tx)| {
                let next_block_num = if idx + 1 < num_txs {
                    block.txs()[idx + 1].block_num
                } else {
                    last_block_num + 1
                };
                tx_convert(tx, idx + 1, chain_id, next_block_num)
            })
            .collect(),
        sigs: block.txs().iter().map(|tx| tx.signature).collect(),
        end_block_not_last,
        end_block_last,
        bytecodes: code_db
            .0
            .iter()
            .map(|(code_hash, bytes)| {
                let hash = Word::from_big_endian(code_hash.as_bytes());
                (
                    hash,
                    Bytecode {
                        hash,
                        bytes: bytes.clone(),
                    },
                )
            })
            .collect(),
        copy_events: block.copy_events.clone(),
        exp_events: block.exp_events.clone(),
        sha3_inputs: block.sha3_inputs.clone(),
        circuits_params: CircuitsParams {
            max_rws,
            ..block.circuits_params
        },
        prev_state_root: block.prev_state_root,
        state_root: None,
        withdraw_root: block.withdraw_root,
        prev_withdraw_root: block.prev_withdraw_root,
        keccak_inputs: circuit_input_builder::keccak_inputs(block, code_db)?,
        mpt_updates,
        chain_id,
        start_l1_queue_index: block.start_l1_queue_index,
        precompile_events: block.precompile_events.clone(),
    })
}

/// Convert a block struct in bus-mapping to a witness block used in circuits
pub fn block_convert_with_l1_queue_index<F: Field>(
    block: &circuit_input_builder::Block,
    code_db: &bus_mapping::state_db::CodeDB,
    start_l1_queue_index: u64,
) -> Result<Block<F>, Error> {
    let mut block = block.clone();
    // keccak_inputs_pi_circuit needs correct start_l1_queue_index
    // but at this time it can be start_l1_queue_index of last block inside the chunk
    // TODO kunxian: any better solution
    block.start_l1_queue_index = start_l1_queue_index;
    let witness_block = block_convert(&block, code_db)?;
    Ok(witness_block)
}

/// Attach witness block with mpt states
pub fn block_apply_mpt_state<F: Field>(block: &mut Block<F>, mpt_state: &MptState) {
    block.mpt_updates.fill_state_roots(mpt_state);
    block.state_root = Some(block.mpt_updates.new_root());
}

/// Mocking generate mpt witness from mpt states
pub fn block_mocking_apply_mpt<F: Field>(block: &mut Block<F>) {
    block.mpt_updates.mock_fill_state_roots();
    block.state_root = Some(block.mpt_updates.new_root());
    block.prev_state_root = block.mpt_updates.old_root();
}
