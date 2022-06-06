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
use crate::error::Error;
use crate::evm::opcodes::{gen_associated_ops, gen_begin_tx_ops, gen_end_tx_ops};
use crate::operation::{CallContextField, RW};
use crate::rpc::GethClient;
use crate::state_db::{self, CodeDB, StateDB};
pub use access::{Access, AccessSet, AccessValue, CodeSource};
pub use block::{Block, BlockContext};
pub use call::{Call, CallContext, CallKind};
use core::fmt::Debug;
use eth_types::evm_types::GasCost;
use eth_types::{self, Address, GethExecStep, GethExecTrace, ToWord, Word};
use ethers_providers::JsonRpcClient;
pub use execution::{CopyDetails, ExecState, ExecStep, StepAuxiliaryData};
pub use input_state_ref::CircuitInputStateRef;
use std::collections::HashMap;
pub use transaction::{Transaction, TransactionContext};

/// Builder to generate a complete circuit input from data gathered from a geth
/// instance. This structure is the centre of the crate and is intended to be
/// the only entry point to it. The `CircuitInputBuilder` works in several
/// steps:
///
/// 1. Take a [`eth_types::Block`] to build the circuit input associated with
/// the block. 2. For each [`eth_types::Transaction`] in the block, take the
/// [`eth_types::GethExecTrace`] to    build the circuit input associated with
/// each transaction, and the bus-mapping operations    associated with each
/// `eth_types::GethExecStep`] in the [`eth_types::GethExecTrace`].
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
    pub fn new(sdb: StateDB, code_db: CodeDB, block: Block) -> Self {
        Self {
            sdb,
            code_db,
            block,
            block_ctx: BlockContext::new(),
        }
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
        // accumulates gas across all txs in the block
        let mut cumulative_gas_used = HashMap::new();
        for (tx_index, tx) in eth_block.transactions.iter().enumerate() {
            let geth_trace = &geth_traces[tx_index];
            if geth_trace.struct_logs.is_empty() {
                log::warn!("Native transfer transaction is left unimplemented");
                continue;
            }
            if tx.to.is_none() {
                log::warn!("Creation transaction is left unimplemented");
                continue;
            }
            self.handle_tx(
                tx,
                geth_trace,
                tx_index + 1 == eth_block.transactions.len(),
                &mut cumulative_gas_used,
            )?;
        }
        self.set_value_ops_call_context_rwc_eor();
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
        cumulative_gas_used: &mut HashMap<usize, u64>,
    ) -> Result<(), Error> {
        let mut tx = self.new_tx(eth_tx, !geth_trace.failed)?;
        let mut tx_ctx = TransactionContext::new(eth_tx, geth_trace, is_last_tx)?;

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
        let mut begin_tx_step = gen_begin_tx_ops(&mut self.state_ref(&mut tx, &mut tx_ctx))?;
        begin_tx_step.gas_cost = GasCost(tx.gas - geth_trace.struct_logs[0].gas.0);
        tx.steps_mut().push(begin_tx_step);

        for (index, geth_step) in geth_trace.struct_logs.iter().enumerate() {
            let mut state_ref = self.state_ref(&mut tx, &mut tx_ctx);
            log::trace!("handle {}th opcode {:?} ", index, geth_step.op);
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
        let end_tx_step = gen_end_tx_ops(
            &mut self.state_ref(&mut tx, &mut tx_ctx),
            cumulative_gas_used,
        )?;
        tx.steps_mut().push(end_tx_step);

        self.sdb.commit_tx();
        self.block.txs.push(tx);

        Ok(())
    }
}

/// Retrieve the init_code from memory for {CREATE, CREATE2}
pub fn get_create_init_code(step: &GethExecStep) -> Result<&[u8], Error> {
    let offset = step.stack.nth_last(1)?;
    let length = step.stack.nth_last(2)?;
    Ok(&step.memory.0[offset.low_u64() as usize..(offset.low_u64() + length.low_u64()) as usize])
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
    history_hashes: Vec<Word>,
}

impl<P: JsonRpcClient> BuilderClient<P> {
    /// Create a new BuilderClient
    pub async fn new(client: GethClient<P>) -> Result<Self, Error> {
        let chain_id = client.get_chain_id().await?;

        Ok(Self {
            cli: client,
            chain_id: chain_id.into(),
            // TODO: Get history hashes
            history_hashes: Vec::new(),
        })
    }

    /// Step 1. Query geth for Block, Txs and TxExecTraces
    pub async fn get_block(
        &self,
        block_num: u64,
    ) -> Result<(EthBlock, Vec<eth_types::GethExecTrace>), Error> {
        let eth_block = self.cli.get_block_by_number(block_num.into()).await?;
        let geth_traces = self.cli.trace_block_by_number(block_num.into()).await?;
        Ok((eth_block, geth_traces))
    }

    /// Step 2. Get State Accesses from TxExecTraces
    pub fn get_state_accesses(
        &self,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
    ) -> Result<AccessSet, Error> {
        let mut block_access_trace = vec![Access::new(
            None,
            RW::WRITE,
            AccessValue::Account {
                address: eth_block.author,
            },
        )];
        for (tx_index, tx) in eth_block.transactions.iter().enumerate() {
            let geth_trace = &geth_traces[tx_index];
            let tx_access_trace = gen_state_access_trace(eth_block, tx, geth_trace)?;
            block_access_trace.extend(tx_access_trace);
        }

        Ok(AccessSet::from(block_access_trace))
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
        &self,
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
                },
            )
        }

        let mut code_db = CodeDB::new();
        for (_address, code) in codes {
            code_db.insert(code.clone());
        }
        (sdb, code_db)
    }

    /// Step 5. For each step in TxExecTraces, gen the associated ops and state
    /// circuit inputs
    pub fn gen_inputs_from_state(
        &self,
        sdb: StateDB,
        code_db: CodeDB,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
    ) -> Result<CircuitInputBuilder, Error> {
        let block = Block::new(self.chain_id, self.history_hashes.clone(), eth_block)?;
        let mut builder = CircuitInputBuilder::new(sdb, code_db, block);
        builder.handle_block(eth_block, geth_traces)?;
        Ok(builder)
    }

    /// Perform all the steps to generate the circuit inputs
    pub async fn gen_inputs(&self, block_num: u64) -> Result<CircuitInputBuilder, Error> {
        let (eth_block, geth_traces) = self.get_block(block_num).await?;
        let access_set = self.get_state_accesses(&eth_block, &geth_traces)?;
        let (proofs, codes) = self.get_state(block_num, access_set).await?;
        let (state_db, code_db) = self.build_state_code_db(proofs, codes);
        let builder = self.gen_inputs_from_state(state_db, code_db, &eth_block, &geth_traces)?;
        Ok(builder)
    }
}
