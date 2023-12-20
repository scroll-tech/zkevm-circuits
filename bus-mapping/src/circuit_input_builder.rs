//! This module contains the CircuitInputBuilder, which is an object that takes
//! types from geth / web3 and outputs the circuit inputs.

mod access;
mod block;
mod call;
mod execution;
mod input_state_ref;
#[cfg(feature = "scroll")]
mod l2;
#[cfg(all(feature = "tracer-tests", feature = "enable-memory", test))]
mod tracer_tests;
mod transaction;

use self::access::gen_state_access_trace;
pub use self::block::BlockHead;
use crate::{
    error::Error,
    evm::opcodes::{gen_associated_ops, gen_associated_steps},
    operation::{self, CallContextField, Operation, RWCounter, StartOp, StorageOp, RW},
    rpc::GethClient,
    state_db::{self, CodeDB, StateDB},
    util::{hash_code_keccak, KECCAK_CODE_HASH_EMPTY},
};
pub use access::{Access, AccessSet, AccessValue, CodeSource};
pub use block::{Block, BlockContext};
pub use call::{Call, CallContext, CallKind};
use core::fmt::Debug;
use eth_types::{
    self,
    evm_types::{GasCost, OpcodeId},
    geth_types,
    sign_types::{pk_bytes_le, pk_bytes_swap_endianness, SignData},
    Address, GethExecStep, GethExecTrace, ToBigEndian, ToWord, Word, H256,
};
use ethers_providers::JsonRpcClient;
pub use execution::{
    BigModExp, CopyBytes, CopyDataType, CopyEvent, CopyEventStepsBuilder, CopyStep, EcAddOp,
    EcMulOp, EcPairingOp, EcPairingPair, ExecState, ExecStep, ExpEvent, ExpStep, NumberOrHash,
    PrecompileEvent, PrecompileEvents, N_BYTES_PER_PAIR, N_PAIRING_PER_OP, SHA256,
};
use hex::decode_to_slice;

use eth_types::sign_types::get_dummy_tx;
use ethers_core::utils::keccak256;
pub use input_state_ref::CircuitInputStateRef;
use itertools::Itertools;
use log::warn;
#[cfg(feature = "scroll")]
use mpt_zktrie::state::ZktrieState;
use std::{
    collections::{BTreeMap, HashMap},
    iter,
};
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
    /// Block
    pub block: Block,
    /// Block Context
    pub block_ctx: BlockContext,
    #[cfg(feature = "scroll")]
    /// Initial Zktrie Status for a incremental updating
    pub mpt_init_state: Option<ZktrieState>,
}

impl<'a> CircuitInputBuilder {
    /// Create a new CircuitInputBuilder from the given `eth_block` and
    /// `constants`.
    pub fn new(sdb: StateDB, code_db: CodeDB, block: &Block) -> Self {
        Self {
            sdb,
            code_db,
            block: block.clone(),
            block_ctx: BlockContext::new(),
            #[cfg(feature = "scroll")]
            mpt_init_state: Default::default(),
        }
    }
    /// Create a new CircuitInputBuilder from the given `eth_block` and
    /// `constants`.
    pub fn new_from_headers(
        circuits_params: CircuitsParams,
        sdb: StateDB,
        code_db: CodeDB,
        headers: &[BlockHead],
    ) -> Self {
        // lispczz@scroll:
        // the `block` here is in fact "chunk" for l2.
        // while "headers" in the "block"(usually single tx) for l2.
        // But to reduce the code conflicts with upstream, we still use the name `block`
        Self::new(sdb, code_db, &Block::from_headers(headers, circuits_params))
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

        Transaction::new(call_id, &self.sdb, &mut self.code_db, eth_tx, is_success)
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

    /// Handle a block by handling each transaction to generate all the
    /// associated operations.
    pub fn handle_block(
        &mut self,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
    ) -> Result<(), Error> {
        self.handle_block_inner(eth_block, geth_traces, true, true)
    }
    /// Handle a block by handling each transaction to generate all the
    /// associated operations.
    pub fn handle_block_inner(
        &mut self,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
        handle_rwc_reversion: bool,
        check_last_tx: bool,
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
                if self.block.is_relaxed() {
                    log::warn!(
                        "tx num overflow, MAX_TX limit {}, {}th tx(inner idx: {}) {:?}, would process for partial block",
                        self.block.circuits_params.max_txs,
                        chunk_tx_idx,
                        tx.transaction_index.unwrap_or_default(),
                        tx.hash
                    );
                    break;
                } else {
                    log::error!(
                        "tx num overflow, MAX_TX limit {}, {}th tx(inner idx: {}) {:?}",
                        self.block.circuits_params.max_txs,
                        chunk_tx_idx,
                        tx.transaction_index.unwrap_or_default(),
                        tx.hash
                    );
                    return Err(Error::InternalError("tx num overflow"));
                }
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
            self.handle_tx(
                &tx,
                geth_trace,
                check_last_tx && tx_index + 1 == eth_block.transactions.len(),
            )?;
            log::debug!(
                "after handle {}th tx: rwc {:?}, total gas {:?}",
                chunk_tx_idx,
                self.block_ctx.rwc,
                self.block_ctx.cumulative_gas_used
            );
            for account_post_state in &geth_trace.account_after {
                let account_post_state: eth_types::l2_types::AccountProofWrapper =
                    account_post_state.clone();
                if let Some(address) = account_post_state.address {
                    let local_acc = self.sdb.get_account(&address).1;
                    log::trace!("local acc {local_acc:?}, trace acc {account_post_state:?}");
                    if local_acc.balance != account_post_state.balance.unwrap() {
                        log::error!("incorrect balance")
                    }
                    if local_acc.nonce != account_post_state.nonce.unwrap().into() {
                        log::error!("incorrect nonce")
                    }
                    let p_hash = account_post_state.poseidon_code_hash.unwrap();
                    if p_hash.is_zero() {
                        if !local_acc.is_empty() {
                            log::error!("incorrect poseidon_code_hash")
                        }
                    } else {
                        if local_acc.code_hash != p_hash {
                            log::error!("incorrect poseidon_code_hash")
                        }
                    }
                    let k_hash = account_post_state.keccak_code_hash.unwrap();
                    if k_hash.is_zero() {
                        if !local_acc.is_empty() {
                            log::error!("incorrect keccak_code_hash")
                        }
                    } else {
                        if local_acc.keccak_code_hash != k_hash {
                            log::error!("incorrect keccak_code_hash")
                        }
                    }
                    if let Some(storage) = account_post_state.storage {
                        let k = storage.key.unwrap();
                        let local_v = self.sdb.get_storage(&address, &k).1;
                        if *local_v != storage.value.unwrap() {
                            log::error!("incorrect storage for k = {k}");
                        }
                    }
                }
            }
        }
        if handle_rwc_reversion {
            self.set_value_ops_call_context_rwc_eor();
            self.set_end_block()?;
        }
        log::info!(
            "handle_block_inner, total gas {:?}",
            self.block_ctx.cumulative_gas_used
        );
        Ok(())
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

    /// ..
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
        let mut end_block_not_last = self.block.block_steps.end_block_not_last.clone();
        let mut end_block_last = self.block.block_steps.end_block_last.clone();
        end_block_not_last.rwc = self.block_ctx.rwc;
        end_block_last.rwc = self.block_ctx.rwc;

        let mut dummy_tx = Transaction::dummy();
        let mut dummy_tx_ctx = TransactionContext::default();
        let mut state = self.state_ref(&mut dummy_tx, &mut dummy_tx_ctx);

        let dummy_tx_id = state.block.txs.len();
        if let Some(call_id) = state.block.txs.last().map(|tx| tx.calls[0].call_id) {
            state.call_context_read(
                &mut end_block_last,
                call_id,
                CallContextField::TxId,
                Word::from(dummy_tx_id as u64),
            )?;
        }

        // increase the total rwc by 1
        state.push_op(
            &mut end_block_last,
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
                return Err(Error::InternalError("rws not enough"));
            };
        }
        push_op(&mut end_block_last, RWCounter(1), RW::READ, StartOp {});
        push_op(
            &mut end_block_last,
            RWCounter(max_rws - total_rws),
            RW::READ,
            StartOp {},
        );

        self.block.withdraw_root = withdraw_root;
        self.block.prev_withdraw_root = withdraw_root_before;
        self.block.block_steps.end_block_not_last = end_block_not_last;
        self.block.block_steps.end_block_last = end_block_last;
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
        is_last_tx: bool,
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

        let mut tx_ctx = TransactionContext::new(eth_tx, geth_trace, is_last_tx)?;
        let mut debug_tx = tx.clone();
        debug_tx.input.clear();
        debug_tx.rlp_bytes.clear();
        debug_tx.rlp_unsigned_bytes.clear();
        log::trace!("handle_tx tx {:?}", debug_tx);
        if let Some(al) = &eth_tx.access_list {
            for item in &al.0 {
                self.sdb.add_account_to_access_list(item.address);
                for k in &item.storage_keys {
                    self.sdb
                        .add_account_storage_to_access_list((item.address, (*k).to_word()));
                }
            }
        }

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
            // EIP2930 not implemented
            if tx.access_list.is_none() {
                debug_assert_eq!(
                    steps_gas_cost,
                    real_gas_cost.as_u64(),
                    "begin step cost {:?}, precompile step cost {:?}",
                    begin_tx_steps[0].gas_cost,
                    begin_tx_steps.get(1).map(|st| st.gas_cost),
                );
            }
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
                if geth_step.op.is_push_with_data() {
                    format!("{:?}", geth_trace.struct_logs.get(index + 1).map(|step| step.stack.last()))
                } else if geth_step.op.is_call_without_value() {
                    format!(
                        "{:?} {:40x} {:?} {:?} {:?} {:?}",
                        geth_step.stack.last(),
                        geth_step.stack.nth_last(1).unwrap_or_default(),
                        geth_step.stack.nth_last(2),
                        geth_step.stack.nth_last(3),
                        geth_step.stack.nth_last(4),
                        geth_step.stack.nth_last(5)
                    )
                } else if geth_step.op.is_call_with_value() {
                    format!(
                        "{:?} {:40x} {:?} {:?} {:?} {:?} {:?}",
                        geth_step.stack.last(),
                        geth_step.stack.nth_last(1).unwrap_or_default(),
                        geth_step.stack.nth_last(2),
                        geth_step.stack.nth_last(3),
                        geth_step.stack.nth_last(4),
                        geth_step.stack.nth_last(5),
                        geth_step.stack.nth_last(6),
                    )
                } else if geth_step.op.is_create() {
                    format!(
                        "value {:?} offset {:?} size {:?} {}",
                        geth_step.stack.last(),
                        geth_step.stack.nth_last(1),
                        geth_step.stack.nth_last(2),
                        if geth_step.op == OpcodeId::CREATE2 {
                            format!("salt {:?}", geth_step.stack.nth_last(3))
                        } else {
                            "".to_string()
                        }
                    )
                } else if matches!(geth_step.op, OpcodeId::SSTORE) {
                    format!(
                        "{:?} {:?} {:?}",
                        state_ref.call().map(|c| c.address),
                        geth_step.stack.last(),
                        geth_step.stack.nth_last(1),
                    )
                } else {
                    let stack_input_num = 1024 - geth_step.op.valid_stack_ptr_range().1 as usize;
                    (0..stack_input_num).map(|i|
                        format!("{:?}",  geth_step.stack.nth_last(i))
                    ).collect_vec().join(" ")
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
        tx.steps_mut().extend(end_tx_steps);

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

    /// enable relax mode for testing
    pub fn enable_relax_mode(mut self) -> Self {
        self.block = self.block.relax();
        self
    }
}

/// Return all the keccak inputs used during the processing of the current
/// block.
pub fn keccak_inputs(block: &Block, code_db: &CodeDB) -> Result<Vec<Vec<u8>>, Error> {
    let mut keccak_inputs = Vec::new();
    // Tx Circuit
    let txs: Vec<geth_types::Transaction> = block.txs.iter().map(|tx| tx.into()).collect();
    keccak_inputs.extend_from_slice(&keccak_inputs_tx_circuit(&txs)?);
    log::debug!(
        "keccak total len after txs: {}",
        keccak_inputs.iter().map(|i| i.len()).sum::<usize>()
    );
    // Ecrecover
    keccak_inputs.extend_from_slice(&keccak_inputs_sign_verify(
        &block.precompile_events.get_ecrecover_events(),
    ));
    log::debug!(
        "keccak total len after ecrecover: {}",
        keccak_inputs.iter().map(|i| i.len()).sum::<usize>()
    );
    // PI circuit
    keccak_inputs.extend(keccak_inputs_pi_circuit(
        block.chain_id,
        block.start_l1_queue_index,
        block.prev_state_root,
        block.withdraw_root,
        &block.headers,
        block.txs(),
    ));
    // Bytecode Circuit
    for _bytecode in code_db.0.values() {
        // keccak_inputs.push(bytecode.clone());
    }
    log::debug!(
        "keccak total len after bytecodes: {}",
        keccak_inputs.iter().map(|i| i.len()).sum::<usize>()
    );
    // EVM Circuit
    keccak_inputs.extend_from_slice(&block.sha3_inputs);
    log::debug!(
        "keccak total len after opcodes: {}",
        keccak_inputs.iter().map(|i| i.len()).sum::<usize>()
    );

    let inputs_len: usize = keccak_inputs.iter().map(|k| k.len()).sum();
    let inputs_num = keccak_inputs.len();
    let keccak_inputs: Vec<_> = keccak_inputs.into_iter().unique().collect();
    let inputs_len2: usize = keccak_inputs.iter().map(|k| k.len()).sum();
    let inputs_num2 = keccak_inputs.len();
    log::debug!("keccak inputs after dedup: input num {inputs_num}->{inputs_num2}, input total len {inputs_len}->{inputs_len2}");

    // MPT Circuit
    // TODO https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/696
    Ok(keccak_inputs)
}

/// Generate the keccak inputs required by the SignVerify Chip from the
/// signature datas.
pub fn keccak_inputs_sign_verify(sigs: &[SignData]) -> Vec<Vec<u8>> {
    let mut inputs = Vec::new();
    let dummy_sign_data = SignData::default();
    for sig in sigs.iter().chain(iter::once(&dummy_sign_data)) {
        let pk_le = pk_bytes_le(&sig.pk);
        let pk_be = pk_bytes_swap_endianness(&pk_le);
        inputs.push(pk_be.to_vec());
        inputs.push(sig.msg.to_vec());
    }
    inputs
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

fn keccak_inputs_pi_circuit(
    chain_id: u64,
    start_l1_queue_index: u64,
    prev_state_root: Word,
    withdraw_trie_root: Word,
    block_headers: &BTreeMap<u64, BlockHead>,
    transactions: &[Transaction],
) -> Vec<Vec<u8>> {
    let mut total_l1_popped = start_l1_queue_index;
    log::debug!(
        "start_l1_queue_index in keccak_inputs: {}",
        start_l1_queue_index
    );
    let data_bytes = iter::empty()
        .chain(block_headers.iter().flat_map(|(&block_num, block)| {
            let num_l2_txs = transactions
                .iter()
                .filter(|tx| !tx.tx_type.is_l1_msg() && tx.block_num == block_num)
                .count() as u64;
            let num_l1_msgs = transactions
                .iter()
                .filter(|tx| tx.tx_type.is_l1_msg() && tx.block_num == block_num)
                // tx.nonce alias for queue_index for l1 msg tx
                .map(|tx| tx.nonce)
                .max()
                .map_or(0, |max_queue_index| max_queue_index - total_l1_popped + 1);
            total_l1_popped += num_l1_msgs;

            let num_txs = (num_l2_txs + num_l1_msgs) as u16;
            log::debug!(
                "[block {}] total_l1_popped: {}, num_l1_msgs: {}, num_l2_txs: {}, num_txs: {}",
                block_num,
                total_l1_popped,
                num_l1_msgs,
                num_l2_txs,
                num_txs,
            );

            iter::empty()
                // Block Values
                .chain(block.number.as_u64().to_be_bytes())
                .chain(block.timestamp.as_u64().to_be_bytes())
                .chain(block.base_fee.to_be_bytes())
                .chain(block.gas_limit.to_be_bytes())
                .chain(num_txs.to_be_bytes())
        }))
        // Tx Hashes
        .chain(transactions.iter().flat_map(|tx| tx.hash.to_fixed_bytes()))
        .collect::<Vec<u8>>();
    let data_hash = H256(keccak256(&data_bytes));
    log::debug!(
        "chunk data hash: {}",
        hex::encode(data_hash.to_fixed_bytes())
    );
    let after_state_root = block_headers
        .last_key_value()
        .map(|(_, blk)| blk.eth_block.state_root)
        .unwrap_or(H256(prev_state_root.to_be_bytes()));
    let pi_bytes = iter::empty()
        .chain(chain_id.to_be_bytes())
        .chain(prev_state_root.to_be_bytes())
        .chain(after_state_root.to_fixed_bytes())
        .chain(withdraw_trie_root.to_be_bytes())
        .chain(data_hash.to_fixed_bytes())
        .collect::<Vec<u8>>();

    vec![data_bytes, pi_bytes]
}

/// Generate the keccak inputs required by the Tx Circuit from the transactions.
pub fn keccak_inputs_tx_circuit(txs: &[geth_types::Transaction]) -> Result<Vec<Vec<u8>>, Error> {
    let mut inputs = Vec::new();

    let hash_datas = txs
        .iter()
        .map(|tx| tx.rlp_bytes.clone())
        .collect::<Vec<Vec<u8>>>();
    let dummy_hash_data = {
        // dummy tx is a legacy tx.
        let (dummy_tx, dummy_sig) = get_dummy_tx();
        dummy_tx.rlp_signed(&dummy_sig).to_vec()
    };
    inputs.extend_from_slice(&hash_datas);
    inputs.push(dummy_hash_data);

    let sign_datas: Vec<SignData> = txs
        .iter()
        .enumerate()
        .filter(|(i, tx)| {
            if !tx.tx_type.is_l1_msg() && tx.v == 0 && tx.r.is_zero() && tx.s.is_zero() {
                warn!(
                    "tx {} is not signed and is not L1Msg, skipping tx circuit keccak input",
                    i
                );
                false
            } else {
                true
            }
        })
        .map(|(_, tx)| {
            if tx.tx_type.is_l1_msg() {
                Ok(SignData::default())
            } else {
                tx.sign_data()
            }
        })
        .try_collect()?;
    // Keccak inputs from SignVerify Chip
    let sign_verify_inputs = keccak_inputs_sign_verify(&sign_datas);
    inputs.extend_from_slice(&sign_verify_inputs);

    Ok(inputs)
}

/// Retrieve the init_code from memory for {CREATE, CREATE2}
pub fn get_create_init_code(call_ctx: &CallContext, step: &GethExecStep) -> Result<Vec<u8>, Error> {
    let offset = step.stack.nth_last(1)?.low_u64() as usize;
    let length = step.stack.nth_last(2)?.as_usize();

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
pub fn get_call_memory_offset_length(step: &GethExecStep, nth: usize) -> Result<(u64, u64), Error> {
    let offset = step.stack.nth_last(nth)?;
    let length = step.stack.nth_last(nth + 1)?;
    if length.is_zero() {
        Ok((0, 0))
    } else {
        Ok((offset.low_u64(), length.low_u64()))
    }
}

type EthBlock = eth_types::Block<eth_types::Transaction>;

/// Struct that wraps a GethClient and contains methods to perform all the steps
/// necessary to generate the circuit inputs for a block by querying geth for
/// the necessary information and using the CircuitInputBuilder.
pub struct BuilderClient<P: JsonRpcClient> {
    cli: GethClient<P>,
    chain_id: u64,
    circuits_params: CircuitsParams,
}

/// Get State Accesses from TxExecTraces
pub fn get_state_accesses(
    eth_block: &EthBlock,
    geth_traces: &[eth_types::GethExecTrace],
) -> Result<AccessSet, Error> {
    let mut block_access_trace = vec![Access::new(
        None,
        RW::WRITE,
        AccessValue::Account {
            address: eth_block
                .author
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?,
        },
    )];
    for (tx_index, tx) in eth_block.transactions.iter().enumerate() {
        let geth_trace = &geth_traces[tx_index];
        let tx_access_trace = gen_state_access_trace(eth_block, tx, geth_trace)?;
        block_access_trace.extend(tx_access_trace);
    }

    Ok(AccessSet::from(block_access_trace))
}

/// Build a partial StateDB from step 3
pub fn build_state_code_db(
    proofs: Vec<eth_types::EIP1186ProofResponse>,
    codes: HashMap<Address, Vec<u8>>,
) -> (StateDB, CodeDB) {
    let mut sdb = StateDB::new();
    for proof in proofs {
        let mut storage = HashMap::new();
        for storage_proof in proof.storage_proof {
            storage.insert(storage_proof.key, storage_proof.value);
        }
        sdb.set_account(
            &proof.address,
            state_db::Account {
                nonce: proof.nonce,
                balance: proof.balance,
                storage,
                code_hash: proof.code_hash,
                keccak_code_hash: proof.keccak_code_hash,
                code_size: proof.code_size,
            },
        )
    }

    let mut code_db = CodeDB::new();
    for (_address, code) in codes {
        code_db.insert(code.clone());
    }
    (sdb, code_db)
}

impl<P: JsonRpcClient> BuilderClient<P> {
    /// Create a new BuilderClient
    pub async fn new(
        client: GethClient<P>,
        circuits_params: CircuitsParams,
    ) -> Result<Self, Error> {
        let chain_id = client.get_chain_id().await?;

        Ok(Self {
            cli: client,
            chain_id,
            circuits_params,
        })
    }

    /// Step 1. Query geth for Block, Txs, TxExecTraces, history block hashes
    /// and previous state root.
    pub async fn get_block(
        &self,
        block_num: u64,
    ) -> Result<(EthBlock, Vec<eth_types::GethExecTrace>, Vec<Word>, Word), Error> {
        let eth_block = self.cli.get_block_by_number(block_num.into()).await?;
        let geth_traces = self.cli.trace_block_by_number(block_num.into()).await?;

        // fetch up to 256 blocks
        let mut n_blocks = 0; // std::cmp::min(256, block_num as usize);
        let mut next_hash = eth_block.parent_hash;
        let mut prev_state_root: Option<Word> = None;
        let mut history_hashes = vec![Word::default(); n_blocks];
        while n_blocks > 0 {
            n_blocks -= 1;

            // TODO: consider replacing it with `eth_getHeaderByHash`, it's faster
            let header = self.cli.get_block_by_hash(next_hash).await?;

            // set the previous state root
            if prev_state_root.is_none() {
                prev_state_root = Some(header.state_root.to_word());
            }

            // latest block hash is the last item
            let block_hash = header
                .hash
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?
                .to_word();
            history_hashes[n_blocks] = block_hash;

            // continue
            next_hash = header.parent_hash;
        }

        Ok((
            eth_block,
            geth_traces,
            history_hashes,
            prev_state_root.unwrap_or_default(),
        ))
    }

    /// Step 2. Get State Accesses from TxExecTraces
    pub fn get_state_accesses(
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
    ) -> Result<AccessSet, Error> {
        get_state_accesses(eth_block, geth_traces)
    }

    /// Step 3. Query geth for all accounts, storage keys, and codes from
    /// Accesses
    pub async fn get_state(
        &self,
        block_num: u64,
        access_set: AccessSet,
    ) -> Result<
        (
            Vec<eth_types::EIP1186ProofResponse>,
            HashMap<Address, Vec<u8>>,
        ),
        Error,
    > {
        let mut proofs = Vec::new();
        for (address, key_set) in access_set.state {
            let mut keys: Vec<Word> = key_set.iter().cloned().collect();
            keys.sort();
            let proof = self
                .cli
                .get_proof(address, keys, (block_num - 1).into())
                .await
                .unwrap();
            proofs.push(proof);
        }
        let mut codes: HashMap<Address, Vec<u8>> = HashMap::new();
        for address in access_set.code {
            let code = self
                .cli
                .get_code(address, (block_num - 1).into())
                .await
                .unwrap();
            codes.insert(address, code);
        }
        Ok((proofs, codes))
    }

    /// Yet-another Step 3. Get the account state and codes from pre-state tracing
    /// the account state is limited since proof is not included,
    /// but it is enough to build the sdb/cdb
    /// if a hash for tx is provided, would return the prestate for this tx
    pub async fn get_pre_state(
        &self,
        eth_block: &EthBlock,
        tx_hash: Option<H256>,
    ) -> Result<
        (
            Vec<eth_types::EIP1186ProofResponse>,
            HashMap<Address, Vec<u8>>,
        ),
        Error,
    > {
        let traces = if let Some(tx_hash) = tx_hash {
            vec![self.cli.trace_tx_prestate_by_hash(tx_hash).await?]
        } else {
            self.cli
                .trace_block_prestate_by_hash(
                    eth_block
                        .hash
                        .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?,
                )
                .await?
        };

        let mut account_set =
            HashMap::<Address, (eth_types::EIP1186ProofResponse, HashMap<Word, Word>)>::new();
        let mut code_set = HashMap::new();

        for trace in traces.into_iter() {
            for (addr, prestate) in trace.into_iter() {
                let (_, storages) = account_set.entry(addr).or_insert_with(|| {
                    let code_size =
                        Word::from(prestate.code.as_ref().map(|bt| bt.len()).unwrap_or(0));
                    let (code_hash, keccak_code_hash) = if let Some(bt) = prestate.code {
                        let h = CodeDB::hash(&bt);
                        // only require for L2
                        let keccak_h = if cfg!(feature = "scroll") {
                            hash_code_keccak(&bt)
                        } else {
                            h
                        };
                        code_set.insert(addr, Vec::from(bt.as_ref()));
                        (h, keccak_h)
                    } else {
                        (CodeDB::empty_code_hash(), *KECCAK_CODE_HASH_EMPTY)
                    };

                    (
                        eth_types::EIP1186ProofResponse {
                            address: addr,
                            balance: prestate.balance.unwrap_or_default(),
                            nonce: prestate.nonce.unwrap_or_default().into(),
                            code_hash,
                            keccak_code_hash,
                            code_size,
                            ..Default::default()
                        },
                        HashMap::new(),
                    )
                });

                if let Some(stg) = prestate.storage {
                    for (k, v) in stg {
                        storages.entry(k).or_insert(v);
                    }
                }
            }
        }

        // a hacking? since the coinbase address is not touch in prestate
        let coinbase_addr = eth_block
            .author
            .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?;
        let block_num = eth_block
            .number
            .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?;
        assert_ne!(
            block_num.as_u64(),
            0,
            "is not expected to access genesis block"
        );
        if let std::collections::hash_map::Entry::Vacant(e) = account_set.entry(coinbase_addr) {
            let coinbase_proof = self
                .cli
                .get_proof(coinbase_addr, Vec::new(), (block_num - 1).into())
                .await?;
            e.insert((coinbase_proof, HashMap::new()));
        }

        Ok((
            account_set
                .into_iter()
                .map(|(_, (mut acc_resp, storage_proofs))| {
                    acc_resp.storage_proof = storage_proofs
                        .into_iter()
                        .map(|(key, value)| eth_types::StorageProof {
                            key,
                            value,
                            ..Default::default()
                        })
                        .collect();
                    acc_resp
                })
                .collect::<Vec<_>>(),
            code_set,
        ))
    }

    /// Step 4. Build a partial StateDB from step 3
    pub fn build_state_code_db(
        proofs: Vec<eth_types::EIP1186ProofResponse>,
        codes: HashMap<Address, Vec<u8>>,
    ) -> (StateDB, CodeDB) {
        build_state_code_db(proofs, codes)
    }

    /// Step 5. For each step in TxExecTraces, gen the associated ops and state
    /// circuit inputs
    pub fn gen_inputs_from_state(
        &self,
        sdb: StateDB,
        code_db: CodeDB,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
        history_hashes: Vec<Word>,
        _prev_state_root: Word,
    ) -> Result<CircuitInputBuilder, Error> {
        let block = Block::new(
            self.chain_id,
            history_hashes,
            eth_block,
            self.circuits_params,
        )?;
        let mut builder = CircuitInputBuilder::new(sdb, code_db, &block);
        builder.handle_block(eth_block, geth_traces)?;
        Ok(builder)
    }

    /// Step 5. For each step in TxExecTraces, gen the associated ops and state
    /// circuit inputs
    pub fn gen_inputs_from_state_multi(
        &self,
        sdb: StateDB,
        code_db: CodeDB,
        blocks_and_traces: &[(EthBlock, Vec<eth_types::GethExecTrace>)],
    ) -> Result<CircuitInputBuilder, Error> {
        let mut builder = CircuitInputBuilder::new_from_headers(
            self.circuits_params,
            sdb,
            code_db,
            Default::default(),
        );
        for (idx, (eth_block, geth_traces)) in blocks_and_traces.iter().enumerate() {
            let is_last = idx == blocks_and_traces.len() - 1;
            let header = BlockHead::new(self.chain_id, Default::default(), eth_block)?;
            builder.block.headers.insert(header.number.as_u64(), header);
            builder.handle_block_inner(eth_block, geth_traces, is_last, is_last)?;
        }
        Ok(builder)
    }

    /// Perform all the steps to generate the circuit inputs
    pub async fn gen_inputs(
        &self,
        block_num: u64,
    ) -> Result<
        (
            CircuitInputBuilder,
            eth_types::Block<eth_types::Transaction>,
        ),
        Error,
    > {
        let (mut eth_block, mut geth_traces, history_hashes, prev_state_root) =
            self.get_block(block_num).await?;
        //let access_set = Self::get_state_accesses(&eth_block, &geth_traces)?;
        let (proofs, codes) = self.get_pre_state(&eth_block, None).await?;
        let (state_db, code_db) = Self::build_state_code_db(proofs, codes);
        if eth_block.transactions.len() > self.circuits_params.max_txs {
            log::error!(
                "max_txs too small: {} < {} for block {}",
                self.circuits_params.max_txs,
                eth_block.transactions.len(),
                eth_block.number.unwrap_or_default()
            );
            eth_block
                .transactions
                .truncate(self.circuits_params.max_txs);
            geth_traces.truncate(self.circuits_params.max_txs);
        }
        let builder = self.gen_inputs_from_state(
            state_db,
            code_db,
            &eth_block,
            &geth_traces,
            history_hashes,
            prev_state_root,
        )?;
        Ok((builder, eth_block))
    }

    /// Perform all the steps to generate the circuit inputs
    pub async fn gen_inputs_multi_blocks(
        &self,
        block_num_begin: u64,
        block_num_end: u64,
    ) -> Result<CircuitInputBuilder, Error> {
        let mut blocks_and_traces = Vec::new();
        let mut access_set = AccessSet::default();
        for block_num in block_num_begin..block_num_end {
            let (eth_block, geth_traces, _, _) = self.get_block(block_num).await?;
            let mut access_list = Self::get_state_accesses(&eth_block, &geth_traces)?;
            access_set.extend(&mut access_list);
            blocks_and_traces.push((eth_block, geth_traces));
        }
        let (proofs, codes) = self.get_state(block_num_begin, access_set).await?;
        let (state_db, code_db) = Self::build_state_code_db(proofs, codes);
        let builder = self.gen_inputs_from_state_multi(state_db, code_db, &blocks_and_traces)?;
        Ok(builder)
    }

    /// Perform all the steps to generate the circuit inputs
    pub async fn gen_inputs_tx(&self, hash_str: &str) -> Result<CircuitInputBuilder, Error> {
        let mut hash: [u8; 32] = [0; 32];
        let hash_str = if &hash_str[0..2] == "0x" {
            &hash_str[2..]
        } else {
            hash_str
        };
        decode_to_slice(hash_str, &mut hash).unwrap();
        let tx_hash = H256::from(hash);

        let mut tx: eth_types::Transaction = self.cli.get_tx_by_hash(tx_hash).await?;
        tx.transaction_index = Some(0.into());
        let geth_trace = self.cli.trace_tx_by_hash(tx_hash).await?;
        let mut eth_block = self
            .cli
            .get_block_by_number(tx.block_number.unwrap().into())
            .await?;

        eth_block.transactions = vec![tx.clone()];

        let (proofs, codes) = self.get_pre_state(&eth_block, Some(tx_hash)).await?;
        let (state_db, code_db) = Self::build_state_code_db(proofs, codes);
        let builder = self.gen_inputs_from_state(
            state_db,
            code_db,
            &eth_block,
            &[geth_trace],
            Default::default(),
            Default::default(),
        )?;
        Ok(builder)
    }
}
