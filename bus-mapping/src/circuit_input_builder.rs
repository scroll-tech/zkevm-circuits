//! This module contains the CircuitInputBuilder, which is an object that takes
//! types from geth / web3 and outputs the circuit inputs.

mod access;
mod block;
mod call;
mod execution;
mod input_state_ref;
#[cfg(test)]
mod tracer_tests;
mod transaction;

use self::access::gen_state_access_trace;
pub use self::block::BlockHead;
use crate::{
    error::Error,
    evm::opcodes::{gen_associated_ops, gen_begin_tx_ops, gen_end_tx_ops},
    operation::{CallContextField, Operation, RWCounter, StartOp, RW},
    rpc::GethClient,
    state_db::{self, CodeDB, StateDB},
};
pub use access::{Access, AccessSet, AccessValue, CodeSource};
pub use block::{Block, BlockContext};
pub use call::{Call, CallContext, CallKind};
use core::fmt::Debug;
use eth_types::{
    self,
    evm_types::OpcodeId,
    geth_types,
    sign_types::{pk_bytes_le, pk_bytes_swap_endianness, SignData},
    Address, GethExecStep, GethExecTrace, ToBigEndian, ToWord, Word, H256, U256,
};
use ethers_core::{
    k256::ecdsa::SigningKey,
    types::{Bytes, NameOrAddress, Signature, TransactionRequest},
};
use ethers_providers::JsonRpcClient;
pub use execution::{
    CopyDataType, CopyEvent, CopyStep, ExecState, ExecStep, ExpEvent, ExpStep, NumberOrHash,
};
use hex::decode_to_slice;

use ethers_core::utils::keccak256;
pub use input_state_ref::CircuitInputStateRef;
use itertools::Itertools;
use log::warn;
use std::{
    collections::{BTreeMap, HashMap},
    iter,
};
pub use transaction::{Transaction, TransactionContext};

/// Circuit Setup Parameters
#[derive(Debug, Clone, Copy)]
pub struct CircuitsParams {
    /// Maximum number of rw operations in the state circuit (RwTable length /
    /// number of rows). This must be at least the number of rw operations
    /// + 1, in order to allocate at least a Start row.
    pub max_rws: usize,
    // TODO: evm_rows: Maximum number of rows in the EVM Circuit
    /// Maximum number of txs in the Tx Circuit
    pub max_txs: usize,
    /// Maximum number of bytes from all txs calldata in the Tx Circuit
    pub max_calldata: usize,
    /// Max amount of rows that the CopyCircuit can have.
    pub max_copy_rows: usize,
    /// Maximum number of inner blocks in a batch
    pub max_inner_blocks: usize,
    /// Max number of steps that the ExpCircuit can have. Each step is further
    /// expressed in 7 rows
    pub max_exp_steps: usize,
    /// Maximum number of bytes supported in the Bytecode Circuit
    pub max_bytecode: usize,
    /// Pad evm circuit number of rows.
    /// When 0, the EVM circuit number of rows will be dynamically calculated,
    /// so the same circuit will not be able to proof different witnesses.
    /// In this case it will contain as many rows for all steps + 1 row
    /// for EndBlock.
    pub max_evm_rows: usize,
    /// Pad the keccak circuit with this number of invocations to a static
    /// capacity.  Number of keccak_f that the Keccak circuit will support.
    /// When 0, the Keccak circuit number of rows will be dynamically
    /// calculated, so the same circuit will not be able to prove different
    /// witnesses.
    pub max_keccak_rows: usize,
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
            max_copy_rows: 1000,
            max_exp_steps: 1000,
            max_bytecode: 512,
            max_evm_rows: 0,
            max_keccak_rows: 0,
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
        // the `block` here is in fact "batch" for l2.
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
        log::info!("handling block {:?}", eth_block.number);
        for (tx_index, tx) in eth_block.transactions.iter().enumerate() {
            if self.block.txs.len() >= self.block.circuits_params.max_txs {
                log::warn!(
                    "skip tx outside MAX_TX limit {}, {}th(inner idx: {}) tx {:?}",
                    self.block.circuits_params.max_txs,
                    tx.transaction_index.unwrap_or_default(),
                    self.block.txs.len(),
                    tx.hash
                );
                continue;
            }
            let geth_trace = &geth_traces[tx_index];
            log::info!(
                "handling {}th(inner idx: {}) tx: {:?} rwc {:?}, to: {:?}, input_len {:?}",
                tx.transaction_index.unwrap_or_default(),
                self.block.txs.len(),
                tx.hash,
                self.block_ctx.rwc,
                tx.to,
                tx.input.len(),
            );
            let mut tx = tx.clone();
            // needed for multi block feature
            tx.transaction_index = Some(self.block.txs.len().into());
            self.handle_tx(
                &tx,
                geth_trace,
                check_last_tx && tx_index + 1 == eth_block.transactions.len(),
            )?;
        }
        if handle_rwc_reversion {
            self.set_value_ops_call_context_rwc_eor();
            self.set_end_block()?;
        }
        log::info!(
            "handling block done, total gas {:?}",
            self.block_ctx.cumulative_gas_used
        );
        Ok(())
    }

    /// ..
    pub fn set_end_block(&mut self) -> Result<(), Error> {
        let max_rws = self.block.circuits_params.max_rws;
        let mut end_block_not_last = self.block.block_steps.end_block_not_last.clone();
        let mut end_block_last = self.block.block_steps.end_block_last.clone();
        end_block_not_last.rwc = self.block_ctx.rwc;
        end_block_last.rwc = self.block_ctx.rwc;

        let mut dummy_tx = Transaction::dummy();
        let mut dummy_tx_ctx = TransactionContext::default();
        let mut state = self.state_ref(&mut dummy_tx, &mut dummy_tx_ctx);

        if let Some(call_id) = state.block.txs.last().map(|tx| tx.calls[0].call_id) {
            state.call_context_read(
                &mut end_block_last,
                call_id,
                CallContextField::TxId,
                Word::from(state.block.txs.len() as u64),
            );
        }

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
        let mut tx_ctx = TransactionContext::new(eth_tx, geth_trace, is_last_tx)?;
        let mut debug_tx = tx.clone();
        debug_tx.input.clear();
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
        // TODO: Move into gen_associated_steps with
        // - execution_state: BeginTx
        // - op: None
        // Generate BeginTx step
        gen_begin_tx_ops(&mut self.state_ref(&mut tx, &mut tx_ctx), geth_trace)?;

        for (index, geth_step) in geth_trace.struct_logs.iter().enumerate() {
            let mut state_ref = self.state_ref(&mut tx, &mut tx_ctx);
            log::trace!(
                "handle {}th tx depth {} {}th opcode {:?} pc: {} gas_left: {} rwc: {} call_id: {} msize: {} args: {}",
                eth_tx.transaction_index.unwrap_or_default(),
                geth_step.depth,
                index,
                geth_step.op,
                geth_step.pc.0,
                geth_step.gas.0,
                state_ref.block_ctx.rwc.0,
                state_ref.call().map(|c| c.call_id).unwrap_or(0),
                state_ref.call_ctx()?.memory.len(),
                if geth_step.op.is_push() {
                    format!("{:?}", geth_trace.struct_logs[index + 1].stack.last())
                } else if geth_step.op.is_call_without_value() {
                    format!(
                        "{:?} {:40x} {:?} {:?} {:?} {:?}",
                        geth_step.stack.nth_last(0),
                        geth_step.stack.nth_last(1).unwrap(),
                        geth_step.stack.nth_last(2),
                        geth_step.stack.nth_last(3),
                        geth_step.stack.nth_last(4),
                        geth_step.stack.nth_last(5)
                    )
                } else if geth_step.op.is_call_with_value() {
                    format!(
                        "{:?} {:40x} {:?} {:?} {:?} {:?} {:?}",
                        geth_step.stack.nth_last(0),
                        geth_step.stack.nth_last(1).unwrap(),
                        geth_step.stack.nth_last(2),
                        geth_step.stack.nth_last(3),
                        geth_step.stack.nth_last(4),
                        geth_step.stack.nth_last(5),
                        geth_step.stack.nth_last(6),
                    )
                } else if geth_step.op.is_create() {
                    format!(
                        "value {:?} offset {:?} size {:?} {}",
                        geth_step.stack.nth_last(0),
                        geth_step.stack.nth_last(1),
                        geth_step.stack.nth_last(2),
                        if geth_step.op == OpcodeId::CREATE2 {
                            format!("salt {:?}", geth_step.stack.nth_last(3))
                        } else {
                            "".to_string()
                        }
                    )
                } else if matches!(geth_step.op, OpcodeId::MLOAD) {
                    format!(
                        "{:?}",
                        geth_step.stack.nth_last(0),
                    )
                } else if matches!(geth_step.op, OpcodeId::MSTORE | OpcodeId::MSTORE8) {
                    format!(
                        "{:?} {:?}",
                        geth_step.stack.nth_last(0),
                        geth_step.stack.nth_last(1),
                    )
                } else {
                    "".to_string()
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

        // TODO: Move into gen_associated_steps with
        // - execution_state: EndTx
        // - op: None
        // Generate EndTx step
        log::trace!("gen_end_tx_ops");
        let end_tx_step = gen_end_tx_ops(&mut self.state_ref(&mut tx, &mut tx_ctx))?;
        tx.steps_mut().push(end_tx_step);

        self.sdb.commit_tx();
        self.block.txs.push(tx);
        log::trace!("handle_tx finished");

        Ok(())
    }
}

/// Return all the keccak inputs used during the processing of the current
/// block.
pub fn keccak_inputs(block: &Block, code_db: &CodeDB) -> Result<Vec<Vec<u8>>, Error> {
    let mut keccak_inputs = Vec::new();
    // Tx Circuit
    let txs: Vec<geth_types::Transaction> = block.txs.iter().map(|tx| tx.into()).collect();
    keccak_inputs.extend_from_slice(&keccak_inputs_tx_circuit(&txs, block.chain_id().as_u64())?);
    log::debug!(
        "keccak total len after txs: {}",
        keccak_inputs.iter().map(|i| i.len()).sum::<usize>()
    );
    // PI circuit
    keccak_inputs.push(keccak_inputs_pi_circuit(
        block.chain_id().as_u64(),
        block.prev_state_root,
        &block.headers,
        block.txs(),
        block.circuits_params.max_txs,
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
    for sig in sigs {
        let pk_le = pk_bytes_le(&sig.pk);
        let pk_be = pk_bytes_swap_endianness(&pk_le);
        inputs.push(pk_be.to_vec());
        inputs.push(sig.msg.to_vec());
    }
    // Padding signature
    let pk_le = pk_bytes_le(&SignData::default().pk);
    let pk_be = pk_bytes_swap_endianness(&pk_le);
    inputs.push(pk_be.to_vec());
    inputs
}

/// Generate a dummy tx in which
/// (nonce=0, gas=0, gas_price=0, to=0, value=0, data="", chain_id)
/// using the dummy private key = 1
pub fn get_dummy_tx(chain_id: u64) -> (TransactionRequest, Signature) {
    let mut sk_be_scalar = [0u8; 32];
    sk_be_scalar[31] = 1_u8;

    let sk = SigningKey::from_bytes(&sk_be_scalar).expect("sign key = 1");
    let wallet = ethers_signers::Wallet::from(sk);

    let tx = TransactionRequest::new()
        .nonce(0)
        .gas(0)
        .gas_price(U256::zero())
        .to(Address::zero())
        .value(U256::zero())
        .data(Bytes::default())
        .chain_id(chain_id);

    // FIXME: need to check if this is deterministic which means sig is fixed.
    let sig = wallet.sign_transaction_sync(&tx.clone().into());

    (tx, sig)
}

/// Get the tx hash of the dummy tx (nonce=0, gas=0, gas_price=0, to=0, value=0,
/// data="") for any chain_id
pub fn get_dummy_tx_hash(chain_id: u64) -> H256 {
    let (tx, sig) = get_dummy_tx(chain_id);

    let tx_hash = keccak256(tx.rlp_signed(&sig));

    H256(tx_hash)
}

fn keccak_inputs_pi_circuit(
    chain_id: u64,
    prev_state_root: Word,
    block_headers: &BTreeMap<u64, BlockHead>,
    transactions: &[Transaction],
    max_txs: usize,
) -> Vec<u8> {
    let dummy_tx_hash = get_dummy_tx_hash(chain_id);
    // TODO: use real-world withdraw trie root
    let withdraw_trie_root = Word::zero(); // zero for now

    let result = iter::empty()
        // state roots
        .chain(prev_state_root.to_be_bytes())
        .chain(
            block_headers
                .last_key_value()
                .map(|(_, blk)| blk.eth_block.state_root)
                .unwrap_or(H256(prev_state_root.to_be_bytes()))
                .to_fixed_bytes(),
        )
        // withdraw trie root
        .chain(withdraw_trie_root.to_be_bytes())
        .chain(block_headers.iter().flat_map(|(block_num, block)| {
            let num_txs = transactions
                .iter()
                .filter(|tx| tx.block_num == *block_num)
                .count() as u16;
            let parent_hash = block.eth_block.parent_hash;
            let block_hash = block.eth_block.hash.unwrap_or(H256::zero());
            let num_l1_msgs = 0_u16; // 0 for now

            iter::empty()
                // Block Values
                .chain(block_hash.to_fixed_bytes())
                .chain(parent_hash.to_fixed_bytes()) // parent hash
                .chain(block.number.as_u64().to_be_bytes())
                .chain(block.timestamp.as_u64().to_be_bytes())
                .chain(block.base_fee.to_be_bytes())
                .chain(block.gas_limit.to_be_bytes())
                .chain(num_txs.to_be_bytes())
                .chain(num_l1_msgs.to_be_bytes())
        }))
        // Tx Hashes
        .chain(transactions.iter().flat_map(|tx| tx.hash.to_fixed_bytes()))
        .chain(
            (0..(max_txs - transactions.len()))
                .into_iter()
                .flat_map(|_| dummy_tx_hash.to_fixed_bytes()),
        )
        .collect::<Vec<u8>>();

    result
}

/// Generate the keccak inputs required by the Tx Circuit from the transactions.
pub fn keccak_inputs_tx_circuit(
    txs: &[geth_types::Transaction],
    chain_id: u64,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut inputs = Vec::new();

    let hash_datas = txs
        .iter()
        .map(|tx| {
            let sig = Signature {
                r: tx.r,
                s: tx.s,
                v: tx.v,
            };
            let mut tx: TransactionRequest = tx.into();
            if tx.to.is_some() {
                let to = tx.to.clone().unwrap();
                match to {
                    NameOrAddress::Name(_) => {}
                    NameOrAddress::Address(addr) => {
                        // the rlp of zero addr is 0x80
                        if addr == Address::zero() {
                            tx.to = None;
                        }
                    }
                }
            }
            tx.rlp_signed(&sig).to_vec()
        })
        .collect::<Vec<Vec<u8>>>();
    let dummy_hash_data = {
        // dummy tx is a legacy tx.
        let (dummy_tx, dummy_sig) = get_dummy_tx(chain_id);
        dummy_tx.rlp_signed(&dummy_sig).to_vec()
    };
    inputs.extend_from_slice(&hash_datas);
    inputs.push(dummy_hash_data);

    let sign_datas: Vec<SignData> = txs
        .iter()
        .enumerate()
        .filter(|(i, tx)| {
            if tx.v == 0 && tx.r.is_zero() && tx.s.is_zero() {
                warn!("tx {} is not signed, skipping tx circuit keccak input", i);
                false
            } else {
                true
            }
        })
        .map(|(_, tx)| tx.sign_data(chain_id))
        .try_collect()?;
    // Keccak inputs from SignVerify Chip
    let sign_verify_inputs = keccak_inputs_sign_verify(&sign_datas);
    inputs.extend_from_slice(&sign_verify_inputs);

    // Since the SignData::default() already includes pk = [1]G which is also the
    // one that we use in get_dummy_tx, so we only need to include the tx sign
    // hash of the dummy tx.
    let dummy_sign_input = {
        let (dummy_tx, _) = get_dummy_tx(chain_id);
        dummy_tx.rlp().to_vec()
    };
    inputs.push(dummy_sign_input);
    // NOTE: We don't verify the Tx Hash in the circuit yet, so we don't have more
    // hash inputs.
    Ok(inputs)
}

/// Retrieve the init_code from memory for {CREATE, CREATE2}
pub fn get_create_init_code<'a>(
    call_ctx: &'a CallContext,
    step: &GethExecStep,
) -> Result<&'a [u8], Error> {
    let offset = step.stack.nth_last(1)?.low_u64() as usize;
    let length = step.stack.nth_last(2)?.as_usize();

    let mem_len = call_ctx.memory.0.len();
    if offset >= mem_len {
        return Ok(&[]);
    }

    let offset_end = offset.checked_add(length).unwrap_or(mem_len);

    Ok(&call_ctx.memory.0[offset..offset_end])
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
    chain_id: Word,
    circuits_params: CircuitsParams,
}

/// Get State Accesses from TxExecTraces
pub fn get_state_accesses(
    eth_block: &EthBlock,
    geth_traces: &[eth_types::GethExecTrace],
) -> Result<Vec<Access>, Error> {
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

    Ok(block_access_trace)
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
            chain_id: chain_id.into(),
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
    ) -> Result<Vec<Access>, Error> {
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
        let block = BlockHead::new(self.chain_id, history_hashes, eth_block)?;
        let mut builder =
            CircuitInputBuilder::new_from_headers(self.circuits_params, sdb, code_db, &[block]);

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
        let access_set = Self::get_state_accesses(&eth_block, &geth_traces)?;
        let (proofs, codes) = self.get_state(block_num, access_set.into()).await?;
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
            let access_list = Self::get_state_accesses(&eth_block, &geth_traces)?;
            access_set.add(access_list);
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
        let geth_traces = self.cli.trace_tx_by_hash(tx_hash).await?;
        let mut eth_block = self
            .cli
            .get_block_by_number(tx.block_number.unwrap().into())
            .await?;

        eth_block.transactions = vec![tx.clone()];

        let mut block_access_trace = vec![Access::new(
            None,
            RW::WRITE,
            AccessValue::Account {
                address: eth_block.author.unwrap(),
            },
        )];
        let geth_trace = &geth_traces[0];
        let tx_access_trace = gen_state_access_trace(
            &eth_types::Block::<eth_types::Transaction>::default(),
            &tx,
            geth_trace,
        )?;
        block_access_trace.extend(tx_access_trace);

        let access_set = AccessSet::from(block_access_trace);

        let (proofs, codes) = self
            .get_state(tx.block_number.unwrap().as_u64(), access_set)
            .await?;
        let (state_db, code_db) = Self::build_state_code_db(proofs, codes);
        let builder = self.gen_inputs_from_state(
            state_db,
            code_db,
            &eth_block,
            &geth_traces,
            Default::default(),
            Default::default(),
        )?;
        Ok(builder)
    }
}
