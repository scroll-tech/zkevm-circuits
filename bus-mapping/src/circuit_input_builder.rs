//! This module contains the CircuitInputBuilder, which is an object that takes
//! types from geth / web3 and outputs the circuit inputs.

mod access;
mod block;
mod builder_client;
mod call;
/// Curie hardfork
pub mod curie;
mod execution;
mod input_state_ref;
#[cfg(feature = "scroll")]
mod l2;
#[cfg(all(feature = "tracer-tests", feature = "enable-memory", test))]
mod tracer_tests;
mod transaction;

pub use self::block::Block;
use crate::{
    error::Error,
    evm::opcodes::{gen_associated_ops, gen_associated_steps},
    operation::{self, CallContextField, Operation, RWCounter, StartOp, StorageOp, RW},
};
pub use access::{Access, AccessSet, AccessValue, CodeSource};
pub use block::{BlockContext, Blocks};
pub use builder_client::{build_state_code_db, BuilderClient};
pub use call::{Call, CallContext, CallKind};
use core::fmt::Debug;
use eth_types::{
    self,
    evm_types::{GasCost, OpcodeId},
    sign_types::get_dummy_tx,
    state_db::{CodeDB, StateDB},
    EthBlock, GethExecTrace, Word, H256,
};
use ethers_core::utils::keccak256;
pub use execution::{
    BigModExp, CopyAccessList, CopyBytes, CopyDataType, CopyEvent, CopyEventStepsBuilder, CopyStep,
    EcAddOp, EcMulOp, EcPairingOp, EcPairingPair, ExecState, ExecStep, ExpEvent, ExpStep,
    NumberOrHash, PrecompileEvent, PrecompileEvents, N_BYTES_PER_PAIR, N_PAIRING_PER_OP, SHA256,
};
pub use input_state_ref::CircuitInputStateRef;
use itertools::Itertools;
#[cfg(feature = "scroll")]
use mpt_zktrie::state::ZktrieState;
use std::collections::BTreeMap;
pub use transaction::{
    Transaction, TransactionContext, TxL1Fee, TX_L1_COMMIT_EXTRA_COST, TX_L1_FEE_PRECISION,
};

/// Setup parameters for ECC-related precompile calls.
#[derive(Debug, Clone, Copy)]
pub struct PrecompileEcParams {
    /// Maximum number of EcAdd ops supported in one block.
    pub ec_add: usize,
    /// Maximum number of EcMul ops supported in one block.
    pub ec_mul: usize,
    /// Maximum number of EcPairing ops supported in one block.
    pub ec_pairing: usize,
}

impl Default for PrecompileEcParams {
    fn default() -> Self {
        Self {
            ec_add: 50,
            ec_mul: 50,
            ec_pairing: 2,
        }
    }
}

/// Circuit Setup Parameters
#[derive(Debug, Clone, Copy)]
pub struct CircuitsParams {
    /// Maximum number of rw operations in the state circuit (RwTable length /
    /// number of rows). This must be at least the number of rw operations
    /// + 1, in order to allocate at least a Start row.
    pub max_rws: usize,
    /// Maximum number of txs in the Tx Circuit
    pub max_txs: usize,
    /// Maximum number of bytes from all txs calldata in the Tx Circuit
    pub max_calldata: usize,
    /// Maximum number of rows that the RLP Circuit can have
    pub max_rlp_rows: usize,
    /// Max amount of rows that the CopyCircuit can have.
    pub max_copy_rows: usize,
    /// Maximum number of inner blocks in a chunk
    pub max_inner_blocks: usize,
    /// Max number of steps that the ExpCircuit can have. Each step is further
    /// expressed in 7 rows
    /// TODO: change this to max_exp_rows too
    pub max_exp_steps: usize,
    /// Maximum number of bytes supported in the Bytecode Circuit
    pub max_bytecode: usize,
    /// Pad evm circuit number of rows.
    /// When 0, the EVM circuit number of rows will be dynamically calculated,
    /// so the same circuit will not be able to proof different witnesses.
    /// In this case it will contain as many rows for all steps + 1 row
    /// for EndBlock.
    pub max_evm_rows: usize,
    /// Max amount of rows that the MptCircuit can have.
    pub max_mpt_rows: usize,
    /// Pad the keccak circuit with this number of invocations to a static
    /// capacity.  Number of keccak_f that the Keccak circuit will support.
    /// When 0, the Keccak circuit number of rows will be dynamically
    /// calculated, so the same circuit will not be able to prove different
    /// witnesses.
    pub max_keccak_rows: usize,
    /// Maximum number of rows that the Poseidon Circuit can have
    pub max_poseidon_rows: usize,
    /// Max number of ECC-related ops supported in the ECC circuit.
    pub max_ec_ops: PrecompileEcParams,
    /// This number indicate what 100% usage means, for example if we can support up to 2
    /// ecPairing inside circuit, and max_vertical_circuit_rows is set to 1_000_000,
    /// then if there is 1 ecPairing in the input, we will return 500_000 as the "row usage"
    /// for the ec circuit.
    pub max_vertical_circuit_rows: usize,
}

impl Default for CircuitsParams {
    /// Default values for most of the unit tests of the Circuit Parameters
    fn default() -> Self {
        CircuitsParams {
            max_rws: 1000,
            max_txs: 1,
            max_calldata: 256,
            max_inner_blocks: 64,
            // TODO: Check whether this value is correct or we should increase/decrease based on
            // this lib tests
            max_copy_rows: 2000,
            max_mpt_rows: 2049,
            max_exp_steps: 1000,
            max_bytecode: 512,
            max_evm_rows: 0,
            max_keccak_rows: 0,
            max_poseidon_rows: 0,
            max_vertical_circuit_rows: 0,
            max_rlp_rows: 1000,
            max_ec_ops: PrecompileEcParams::default(),
        }
    }
}

/// Builder to generate a complete circuit input from data gathered from a geth
/// instance. This structure is the centre of the crate and is intended to be
/// the only entry point to it. The `CircuitInputBuilder` works in several
/// steps:
///
/// 1. Take a [`eth_types::Block`] to build the circuit input associated with
/// the block. 2. For each [`eth_types::Transaction`] in the block, take the
/// [`eth_types::GethExecTrace`] to build the circuit input associated with
/// each transaction, and the bus-mapping operations associated with each
/// [`eth_types::GethExecStep`] in the [`eth_types::GethExecTrace`].
///
/// The generated bus-mapping operations are:
/// [`StackOp`](crate::operation::StackOp)s,
/// [`MemoryOp`](crate::operation::MemoryOp)s and
/// [`StorageOp`](crate::operation::StorageOp), which correspond to each
/// [`OpcodeId`](crate::evm::OpcodeId)s used in each `ExecTrace` step so that
/// the State Proof witnesses are already generated on a structured manner and
/// ready to be added into the State circuit.
#[derive(Debug)]
pub struct CircuitInputBuilder {
    /// StateDB key-value DB
    pub sdb: StateDB,
    /// Map of account codes by code hash
    pub code_db: CodeDB,
    /// TODO: rename this to chunk
    pub block: Blocks,
    /// TODO: rename this to chunk_ctx
    pub block_ctx: BlockContext,
    #[cfg(feature = "scroll")]
    /// Initial Zktrie Status for a incremental updating
    pub mpt_init_state: Option<ZktrieState>,
}

impl<'a> CircuitInputBuilder {
    /// Create a new CircuitInputBuilder from the given `eth_block` and
    /// `constants`.
    pub fn new(sdb: StateDB, code_db: CodeDB, blocks: &Blocks) -> Self {
        Self {
            sdb,
            code_db,
            block: blocks.clone(),
            block_ctx: BlockContext::new(),
            #[cfg(feature = "scroll")]
            mpt_init_state: Default::default(),
        }
    }
    /// Create a new CircuitInputBuilder from the given `eth_block` and
    /// `constants`.
    pub fn new_from_params(
        chain_id: u64,
        circuits_params: CircuitsParams,
        sdb: StateDB,
        code_db: CodeDB,
    ) -> Self {
        // lispczz@scroll:
        // the `block` here is in fact "chunk" for l2.
        // while "headers" in the "block"(usually single tx) for l2.
        // But to reduce the code conflicts with upstream, we still use the name `block`
        Self::new(sdb, code_db, &Blocks::init(chain_id, circuits_params))
    }

    /// Obtain a mutable reference to the state that the `CircuitInputBuilder`
    /// maintains, contextualized to a particular transaction and a
    /// particular execution step in that transaction.
    pub fn state_ref(
        &'a mut self,
        tx: &'a mut Transaction,
        tx_ctx: &'a mut TransactionContext,
    ) -> CircuitInputStateRef {
        CircuitInputStateRef {
            sdb: &mut self.sdb,
            code_db: &mut self.code_db,
            block: &mut self.block,
            block_ctx: &mut self.block_ctx,
            tx,
            tx_ctx,
        }
    }

    /// Create a new Transaction from a [`eth_types::Transaction`].
    pub fn new_tx(
        &mut self,
        eth_tx: &eth_types::Transaction,
        is_success: bool,
    ) -> Result<Transaction, Error> {
        let call_id = self.block_ctx.rwc.0;

        self.block_ctx.call_map.insert(
            call_id,
            (
                eth_tx
                    .transaction_index
                    .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?
                    .as_u64() as usize,
                0,
            ),
        );

        Transaction::new(
            call_id,
            self.block.chain_id(),
            &self.sdb,
            &mut self.code_db,
            eth_tx,
            is_success,
        )
    }

    /// Iterate over all generated CallContext RwCounterEndOfReversion
    /// operations and set the correct value. This is required because when we
    /// generate the RwCounterEndOfReversion operation in
    /// `gen_associated_ops` we don't know yet which value it will take,
    /// so we put a placeholder; so we do it here after the values are known.
    pub fn set_value_ops_call_context_rwc_eor(&mut self) {
        for oper in self.block.container.call_context.iter_mut() {
            let op = oper.op_mut();
            if matches!(op.field, CallContextField::RwCounterEndOfReversion) {
                let (tx_idx, call_idx) = self
                    .block_ctx
                    .call_map
                    .get(&op.call_id)
                    .expect("call_id not found in call_map");
                op.value = self.block.txs[*tx_idx].calls()[*call_idx]
                    .rw_counter_end_of_reversion
                    .into();
            }
        }
    }

    /// make finalize actions on building, must called after
    /// all block trace have been input
    pub fn finalize_building(&mut self) -> Result<(), Error> {
        self.set_value_ops_call_context_rwc_eor();
        self.set_end_block()
    }

    /// Handle a block by handling each transaction to generate all the
    /// associated operations.
    pub fn handle_block(
        &mut self,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
    ) -> Result<(), Error> {
        self.handle_block_inner(eth_block, geth_traces)?;
        self.finalize_building()?;
        Ok(())
    }
    /// Handle a block by handling each transaction to generate all the
    /// associated operations.
    pub fn handle_block_inner(
        &mut self,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
    ) -> Result<(), Error> {
        // accumulates gas across all txs in the block
        log::info!(
            "handling block {:?}, tx num {}",
            eth_block.number,
            eth_block.transactions.len()
        );
        for (tx_index, tx) in eth_block.transactions.iter().enumerate() {
            let chunk_tx_idx = self.block.txs.len();
            if self.block.txs.len() >= self.block.circuits_params.max_txs {
                log::error!(
                    "tx num overflow, MAX_TX limit {}, {}th tx(inner idx: {}) {:?}",
                    self.block.circuits_params.max_txs,
                    chunk_tx_idx,
                    tx.transaction_index.unwrap_or_default(),
                    tx.hash
                );
                return Err(Error::InternalError("tx num overflow"));
            }
            let geth_trace = &geth_traces[tx_index];
            log::info!(
                "handling {}th tx(inner idx: {}): {:?} rwc {:?}, to: {:?}, input_len {:?}",
                chunk_tx_idx,
                tx.transaction_index.unwrap_or_default(),
                tx.hash,
                self.block_ctx.rwc,
                tx.to,
                tx.input.len(),
            );
            let mut tx = tx.clone();
            // Chunk can contain multi blocks, so transaction_index needs to be updated
            tx.transaction_index = Some(self.block.txs.len().into());
            self.handle_tx(&tx, geth_trace)?;
            log::debug!(
                "after handle {}th tx: rwc {:?}, total gas {:?}",
                chunk_tx_idx,
                self.block_ctx.rwc,
                self.block_ctx.cumulative_gas_used
            );
            self.check_post_state(&geth_trace.account_after);
        }
        log::info!(
            "handle_block_inner, total gas {:?}",
            self.block_ctx.cumulative_gas_used
        );
        Ok(())
    }

    fn check_post_state(&self, post_states: &[eth_types::l2_types::AccountTrace]) {
        for account_post_state in post_states {
            let address = account_post_state.address;
            let local_acc = self.sdb.get_account(&address).1;
            log::trace!("local acc {local_acc:?}, trace acc {account_post_state:?}");
            if local_acc.balance != account_post_state.balance {
                log::error!("incorrect balance")
            }
            if local_acc.nonce != account_post_state.nonce.into() {
                log::error!("incorrect nonce")
            }
            let p_hash = account_post_state.poseidon_code_hash;
            if p_hash.is_zero() {
                if !local_acc.is_empty() {
                    log::error!("incorrect poseidon_code_hash")
                }
            } else {
                if local_acc.code_hash != p_hash {
                    log::error!("incorrect poseidon_code_hash")
                }
            }
            let k_hash = account_post_state.keccak_code_hash;
            if k_hash.is_zero() {
                if !local_acc.is_empty() {
                    log::error!("incorrect keccak_code_hash")
                }
            } else {
                if local_acc.keccak_code_hash != k_hash {
                    log::error!("incorrect keccak_code_hash")
                }
            }
        }
    }
    fn print_rw_usage(&self) {
        // opcode -> (count, mem_rw_len, stack_rw_len)
        let mut opcode_info_map = BTreeMap::new();
        for t in &self.block.txs {
            for step in t.steps() {
                if let ExecState::Op(op) = step.exec_state {
                    opcode_info_map.entry(op).or_insert((0, 0, 0));
                    let mut values = opcode_info_map[&op];
                    values.0 += 1;
                    values.1 += step
                        .bus_mapping_instance
                        .iter()
                        .filter(|rw| rw.0 == operation::Target::Memory)
                        .count();
                    values.2 += step
                        .bus_mapping_instance
                        .iter()
                        .filter(|rw| rw.0 == operation::Target::Stack)
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
        log::debug!("memory_word num: {}", self.block.container.memory.len());
        log::debug!("stack num: {}", self.block.container.stack.len());
        log::debug!("storage num: {}", self.block.container.storage.len());
        log::debug!(
            "tx_access_list_account num: {}",
            self.block.container.tx_access_list_account.len()
        );
        log::debug!(
            "tx_access_list_account_storage num: {}",
            self.block.container.tx_access_list_account_storage.len()
        );
        log::debug!("tx_refund num: {}", self.block.container.tx_refund.len());
        log::debug!("account num: {}", self.block.container.account.len());
        log::debug!(
            "call_context num: {}",
            self.block.container.call_context.len()
        );
        log::debug!("tx_receipt num: {}", self.block.container.tx_receipt.len());
        log::debug!("tx_log num: {}", self.block.container.tx_log.len());
        log::debug!("start num: {}", self.block.container.start.len());
    }

    /// Build the EndBlock step, fill needed rws like reading withdraw root
    pub fn set_end_block(&mut self) -> Result<(), Error> {
        use crate::l2_predeployed::message_queue::{
            ADDRESS as MESSAGE_QUEUE, WITHDRAW_TRIE_ROOT_SLOT,
        };

        let withdraw_root = *self
            .sdb
            .get_storage(&MESSAGE_QUEUE, &WITHDRAW_TRIE_ROOT_SLOT)
            .1;
        let withdraw_root_before = *self
            .sdb
            .get_committed_storage(&MESSAGE_QUEUE, &WITHDRAW_TRIE_ROOT_SLOT)
            .1;

        let max_rws = self.block.circuits_params.max_rws;
        let mut padding_step = self.block.block_steps.padding_step.clone();
        let mut end_block_step = self.block.block_steps.end_block_step.clone();
        padding_step.rwc = self.block_ctx.rwc;
        end_block_step.rwc = self.block_ctx.rwc;

        let mut dummy_tx = Transaction::dummy();
        let mut dummy_tx_ctx = TransactionContext::default();
        let mut state = self.state_ref(&mut dummy_tx, &mut dummy_tx_ctx);

        let dummy_tx_id = state.block.txs.len();
        if let Some(call_id) = state.block.txs.last().map(|tx| tx.calls[0].call_id) {
            state.call_context_read(
                &mut end_block_step,
                call_id,
                CallContextField::TxId,
                Word::from(dummy_tx_id as u64),
            )?;
        }

        // 0-block chunk is only valid for vk gen.
        if let Some(last_block_num) = state.block.last_block_num() {
            // Curie sys contract upgrade
            let is_curie_fork_block =
                curie::is_curie_fork_block(state.block.chain_id, last_block_num);
            if is_curie_fork_block {
                log::info!(
                    "apply curie, chain id {}, block num {}",
                    state.block.chain_id,
                    last_block_num
                );
                curie::apply_curie(&mut state, &mut end_block_step)?;
            }
        }

        state.push_op(
            &mut end_block_step,
            RW::READ,
            StorageOp::new(
                *MESSAGE_QUEUE,
                WITHDRAW_TRIE_ROOT_SLOT,
                withdraw_root,
                withdraw_root,
                dummy_tx_id,
                withdraw_root_before,
            ),
        )?;

        let mut push_op = |step: &mut ExecStep, rwc: RWCounter, rw: RW, op: StartOp| {
            let op_ref = state.block.container.insert(Operation::new(rwc, rw, op));
            step.bus_mapping_instance.push(op_ref);
        };

        let total_rws = state.block_ctx.rwc.0 - 1;
        // 2 here means we need at least 2 StartOp in state circuit.
        let max_rws = if max_rws == 0 { total_rws + 2 } else { max_rws };
        // We need at least 1 extra Start row
        #[allow(clippy::int_plus_one)]
        {
            if total_rws + 1 > max_rws {
                log::error!(
                    "total_rws + 1 > max_rws, total_rws={}, max_rws={}",
                    total_rws,
                    max_rws
                );
                if cfg!(feature = "strict-ccc") {
                    return Err(Error::InternalError("rws not enough"));
                }
            };
        }
        push_op(&mut end_block_step, RWCounter(1), RW::READ, StartOp {});
        push_op(
            &mut end_block_step,
            RWCounter(max_rws - total_rws),
            RW::READ,
            StartOp {},
        );

        self.block.withdraw_root = withdraw_root;
        self.block.prev_withdraw_root = withdraw_root_before;
        self.block.block_steps.padding_step = padding_step;
        self.block.block_steps.end_block_step = end_block_step;
        Ok(())
    }

    /// Handle a transaction with its corresponding execution trace to generate
    /// all the associated operations.  Each operation is registered in
    /// `self.block.container`, and each step stores the
    /// [`OperationRef`](crate::exec_trace::OperationRef) to each of the
    /// generated operations.
    fn handle_tx(
        &mut self,
        eth_tx: &eth_types::Transaction,
        geth_trace: &GethExecTrace,
    ) -> Result<(), Error> {
        let mut tx = self.new_tx(eth_tx, !geth_trace.failed)?;

        // Sanity check for transaction L1 fee.
        let tx_l1_fee = if tx.tx_type.is_l1_msg() {
            0
        } else {
            tx.l1_fee()
        };
        if tx_l1_fee != geth_trace.l1_fee {
            log::error!(
                "Mismatch tx_l1_fee: calculated = {}, real = {}",
                tx_l1_fee,
                geth_trace.l1_fee
            );
        }

        let mut tx_ctx = TransactionContext::new(eth_tx, geth_trace)?;
        let mut debug_tx = tx.clone();
        debug_tx.input.clear();
        debug_tx.rlp_bytes.clear();
        debug_tx.rlp_unsigned_bytes.clear();
        log::trace!("handle_tx tx {:?}", debug_tx);

        // Generate BeginTx step
        let begin_tx_steps = gen_associated_steps(
            &mut self.state_ref(&mut tx, &mut tx_ctx),
            ExecState::BeginTx,
        )?;

        // check gas cost
        {
            let steps_gas_cost: u64 = begin_tx_steps.iter().map(|st| st.gas_cost.0).sum();
            let real_gas_cost = if geth_trace.struct_logs.is_empty() {
                GasCost(geth_trace.gas.0)
            } else {
                GasCost(tx.gas - geth_trace.struct_logs[0].gas.0)
            };
            debug_assert_eq!(
                steps_gas_cost,
                real_gas_cost.as_u64(),
                "begin step cost {:?}, next step cost {:?}",
                begin_tx_steps[0].gas_cost,
                begin_tx_steps.get(1).map(|st| st.gas_cost),
            );
        }

        tx.steps_mut().extend(begin_tx_steps);

        for (index, geth_step) in geth_trace.struct_logs.iter().enumerate() {
            let tx_gas = tx.gas;
            let mut state_ref = self.state_ref(&mut tx, &mut tx_ctx);
            log::trace!(
                "handle {}th tx depth {} {}th/{} opcode {:?} pc: {} gas_left: {} gas_used: {} rwc: {} call_id: {} msize: {} refund: {} args: {}",
                eth_tx.transaction_index.unwrap_or_default(),
                geth_step.depth,
                index,
                geth_trace.struct_logs.len(),
                geth_step.op,
                geth_step.pc.0,
                geth_step.gas.0,
                tx_gas - geth_step.gas.0,
                state_ref.block_ctx.rwc.0,
                state_ref.call().map(|c| c.call_id).unwrap_or(0),
                state_ref.call_ctx()?.memory.len(),
                geth_step.refund.0,
                {
                    let stack = &state_ref.call_ctx()?.stack;
                    if geth_step.op.is_push_with_data() {
                        #[cfg(feature = "enable-stack")]
                        {
                            format!("{:?}", geth_trace.struct_logs.get(index + 1).map(|step| step.stack.last()))
                        }
                        #[cfg(not(feature = "enable-stack"))]
                        {
                            "N/A".to_string()
                        }
                    } else if geth_step.op.is_call_without_value() {
                        format!(
                            "{:?} {:40x} {:?} {:?} {:?} {:?}",
                            stack.last(),
                            stack.nth_last(1).unwrap_or_default(),
                            stack.nth_last(2),
                            stack.nth_last(3),
                            stack.nth_last(4),
                            stack.nth_last(5)
                        )
                    } else if geth_step.op.is_call_with_value() {
                        format!(
                            "{:?} {:40x} {:?} {:?} {:?} {:?} {:?}",
                            stack.last(),
                            stack.nth_last(1).unwrap_or_default(),
                            stack.nth_last(2),
                            stack.nth_last(3),
                            stack.nth_last(4),
                            stack.nth_last(5),
                            stack.nth_last(6),
                        )
                    } else if geth_step.op.is_create() {
                        format!(
                            "value {:?} offset {:?} size {:?} {}",
                            stack.last(),
                            stack.nth_last(1),
                            stack.nth_last(2),
                            if geth_step.op == OpcodeId::CREATE2 {
                                format!("salt {:?}", stack.nth_last(3))
                            } else {
                                "".to_string()
                            }
                        )
                    } else if matches!(geth_step.op, OpcodeId::SSTORE) {
                        format!(
                            "{:?} {:?} {:?}",
                            state_ref.call().map(|c| c.address),
                            stack.last(),
                            stack.nth_last(1),
                        )
                    } else {
                        let stack_input_num = 1024 - geth_step.op.valid_stack_ptr_range().1 as usize;
                        (0..stack_input_num).map(|i|
                            format!("{:?}",  stack.nth_last(i))
                        ).collect_vec().join(" ")
                    }
                }
            );
            debug_assert_eq!(
                geth_step.depth as usize,
                state_ref.call().unwrap().depth,
                "call {:?} calls {:?}",
                state_ref.call(),
                state_ref.tx.calls()
            );
            let exec_steps = gen_associated_ops(
                &geth_step.op,
                &mut state_ref,
                &geth_trace.struct_logs[index..],
            )?;
            tx.steps_mut().extend(exec_steps);
        }

        // Generate EndTx step
        log::trace!("gen_end_tx_ops");
        let end_tx_steps =
            gen_associated_steps(&mut self.state_ref(&mut tx, &mut tx_ctx), ExecState::EndTx)?;
        self.sdb.clear_transient_storage();
        tx.steps_mut().extend(end_tx_steps);

        debug_assert_eq!(
            tx.calls.len(),
            tx_ctx.call_is_success_offset + tx_ctx.call_is_success.len()
        );

        self.sdb.commit_tx();
        self.block.txs.push(tx);
        log::trace!("handle_tx finished");

        Ok(())
    }
}

#[cfg(feature = "test")]
impl CircuitInputBuilder {
    /// test if this circuit has any different evm behaviour trace
    pub fn has_l2_different_evm_behaviour_trace(&self) -> bool {
        self.block
            .txs
            .iter()
            .any(|tx| tx.has_l2_different_evm_behaviour_step())
    }
}

/// Get the tx hash of the dummy tx (nonce=0, gas=0, gas_price=0, to=0, value=0,
/// data="")
pub fn get_dummy_tx_hash() -> H256 {
    let (tx, sig) = get_dummy_tx();

    let tx_hash = keccak256(tx.rlp_signed(&sig));

    assert_eq!(
        hex::encode(tx_hash),
        "137c41d53f2e633af81c75e938f6ccf7298ad6d2fa698b19a50545c1ae5b2b85"
    );

    H256(tx_hash)
}

/// Retrieve the init_code from memory for {CREATE, CREATE2}
pub fn get_create_init_code(call_ctx: &CallContext) -> Result<Vec<u8>, Error> {
    let offset = call_ctx.stack.nth_last(1)?.low_u64() as usize;
    let length = call_ctx.stack.nth_last(2)?.as_usize();

    let mem_len = call_ctx.memory.0.len();
    let mut result = vec![0u8; length];
    if length > 0 && offset < mem_len {
        let offset_end = offset.checked_add(length).unwrap().min(mem_len);
        let copy_len = offset_end - offset;
        result[..copy_len].copy_from_slice(&call_ctx.memory.0[offset..offset_end]);
    }
    Ok(result)
}

/// Retrieve the memory offset and length of call.
pub fn get_call_memory_offset_length(
    call_ctx: &CallContext,
    nth: usize,
) -> Result<(u64, u64), Error> {
    let offset = call_ctx.stack.nth_last(nth)?;
    let length = call_ctx.stack.nth_last(nth + 1)?;
    if length.is_zero() {
        Ok((0, 0))
    } else {
        Ok((offset.low_u64(), length.low_u64()))
    }
}
