//! This module contains the CircuitInputBuilder, which is an object that takes
//! types from geth / web3 and outputs the circuit inputs.
use crate::evm::opcodes::{gen_associated_ops, gen_begin_tx_ops, gen_end_tx_ops};
use crate::exec_trace::OperationRef;
use crate::geth_errors::*;
use crate::operation::container::OperationContainer;
use crate::operation::{
    AccountField, CallContextField, MemoryOp, Op, OpEnum, Operation, RWCounter, StackOp, Target, RW,
};
use crate::state_db::{self, CodeDB, StateDB};
use crate::Error;
use core::fmt::Debug;
use eth_types::evm_types::{Gas, GasCost, MemoryAddress, OpcodeId, ProgramCounter, StackAddress};
use eth_types::{
    self, Address, GethExecStep, GethExecTrace, Hash, ToAddress, ToBigEndian, Word, H256, U256,
};
use ethers_core::utils::{get_contract_address, get_create2_address};
use itertools::Itertools;
use std::collections::{hash_map::Entry, BTreeMap, HashMap, HashSet};

use crate::rpc::GethClient;
use ethers_providers::JsonRpcClient;

/// Out of Gas errors by opcode
#[derive(Clone, Debug, PartialEq)]
pub enum OogError {
    /// Out of Gas for opcodes which have non-zero constant gas cost
    Constant,
    /// Out of Gas for MLOAD, MSTORE, MSTORE8, which have static memory
    /// expansion gas cost
    StaticMemoryExpansion,
    /// Out of Gas for CREATE, RETURN, REVERT, which have dynamic memory
    /// expansion gas cost
    DynamicMemoryExpansion,
    /// Out of Gas for CALLDATACOPY, CODECOPY, RETURNDATACOPY, which copy a
    /// specified chunk of memory
    MemoryCopy,
    /// Out of Gas for BALANCE, EXTCODESIZE, EXTCODEHASH, which possibly touch
    /// an extra account
    AccountAccess,
    /// Out of Gas for RETURN which has code storing gas cost when it's is
    /// creation
    CodeStore,
    /// Out of Gas for LOG0, LOG1, LOG2, LOG3, LOG4
    Log,
    /// Out of Gas for EXP
    Exp,
    /// Out of Gas for SHA3
    Sha3,
    /// Out of Gas for EXTCODECOPY
    ExtCodeCopy,
    /// Out of Gas for SLOAD
    Sload,
    /// Out of Gas for SSTORE
    Sstore,
    /// Out of Gas for CALL
    Call,
    /// Out of Gas for CALLCODE
    CallCode,
    /// Out of Gas for DELEGATECALL
    DelegateCall,
    /// Out of Gas for CREATE2
    Create2,
    /// Out of Gas for STATICCALL
    StaticCall,
    /// Out of Gas for SELFDESTRUCT
    SelfDestruct,
}

/// EVM Execution Error
#[derive(Clone, Debug, PartialEq)]
pub enum ExecError {
    /// Invalid Opcode
    InvalidOpcode,
    /// For opcodes who push more than pop
    StackOverflow,
    /// For opcodes which pop, DUP and SWAP, which peek deeper element directly
    StackUnderflow,
    /// Out of Gas
    OutOfGas(OogError),
    /// For SSTORE, LOG0, LOG1, LOG2, LOG3, LOG4, CREATE, CALL, CREATE2,
    /// SELFDESTRUCT
    WriteProtection,
    /// For CALL, CALLCODE, DELEGATECALL, STATICCALL
    Depth,
    /// For CALL, CALLCODE
    InsufficientBalance,
    /// For CREATE, CREATE2
    ContractAddressCollision,
    /// contract must not begin with 0xef due to EIP #3541 EVM Object Format
    /// (EOF)
    InvalidCreationCode,
    /// For JUMP, JUMPI
    InvalidJump,
    /// For RETURNDATACOPY
    ReturnDataOutOfBounds,
    /// For RETURN in a CREATE, CREATE2
    CodeStoreOutOfGas,
    /// For RETURN in a CREATE, CREATE2
    MaxCodeSizeExceeded,
}

/// Execution state
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecState {
    /// EVM Opcode ID
    Op(OpcodeId),
    /// Virtual step Begin Tx
    BeginTx,
    /// Virtual step End Tx
    EndTx,
    /// Virtual step Copy To Memory
    CopyToMemory,
    /// Virtal step Copy Code To Memory
    CopyCodeToMemory,
}

impl ExecState {
    /// Returns `true` if `ExecState` is an opcode and the opcode is a `PUSHn`.
    pub fn is_push(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_push()
        } else {
            false
        }
    }

    /// Returns `true` if `ExecState` is an opcode and the opcode is a `DUPn`.
    pub fn is_dup(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_dup()
        } else {
            false
        }
    }

    /// Returns `true` if `ExecState` is an opcode and the opcode is a `SWAPn`.
    pub fn is_swap(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_swap()
        } else {
            false
        }
    }
}

/// Auxiliary data for CopyToMemory internal state.
#[derive(Clone, Copy, Debug)]
pub struct CopyToMemoryAuxData {
    /// Source start address
    pub src_addr: u64,
    /// Destination address
    pub dst_addr: u64,
    /// Bytes left
    pub bytes_left: u64,
    /// Source end address
    pub src_addr_end: u64,
    /// Indicate if copy from transaction call data
    pub from_tx: bool,
}

/// Auxiliary data for CopyCodeToMemory internal state.
#[derive(Clone, Copy, Debug)]
pub struct CopyCodeToMemoryAuxData {
    /// Source start address
    pub src_addr: u64,
    /// Destination address
    pub dst_addr: u64,
    /// Bytes left
    pub bytes_left: u64,
    /// Source end address
    pub src_addr_end: u64,
    /// Hash of the bytecode to be copied
    pub code_source: U256,
}

/// Auxiliary data of Execution step
#[derive(Clone, Copy, Debug)]
pub enum StepAuxiliaryData {
    /// Auxiliary data of Copy To Memory
    CopyToMemory(CopyToMemoryAuxData),
    /// Auxiliary data of Copy Code To Memory
    CopyCodeToMemory(CopyCodeToMemoryAuxData),
}

/// An execution step of the EVM.
#[derive(Clone, Debug)]
pub struct ExecStep {
    /// Execution state
    pub exec_state: ExecState,
    /// Program Counter
    pub pc: ProgramCounter,
    /// Stack size
    pub stack_size: usize,
    /// Memory size
    pub memory_size: usize,
    /// Gas left
    pub gas_left: Gas,
    /// Gas cost of the step.  If the error is OutOfGas caused by a "gas uint64
    /// overflow", this value will **not** be the actual Gas cost of the
    /// step.
    pub gas_cost: GasCost,
    /// Accumulated gas refund
    pub gas_refund: Gas,
    /// Call index within the [`Transaction`]
    pub call_index: usize,
    /// The global counter when this step was executed.
    pub rwc: RWCounter,
    /// Reversible Write Counter.  Counter of write operations in the call that
    /// will need to be undone in case of a revert.
    pub reversible_write_counter: usize,
    /// The list of references to Operations in the container
    pub bus_mapping_instance: Vec<OperationRef>,
    /// Error generated by this step
    pub error: Option<ExecError>,
    /// Step auxiliary data
    pub aux_data: Option<StepAuxiliaryData>,
}

impl ExecStep {
    /// Create a new Self from a `GethExecStep`.
    pub fn new(
        step: &GethExecStep,
        call_index: usize,
        rwc: RWCounter,
        reversible_write_counter: usize,
    ) -> Self {
        ExecStep {
            exec_state: ExecState::Op(step.op),
            pc: step.pc,
            stack_size: step.stack.0.len(),
            memory_size: step.memory.0.len(),
            gas_left: step.gas,
            gas_cost: step.gas_cost,
            gas_refund: Gas(0),
            call_index,
            rwc,
            reversible_write_counter,
            bus_mapping_instance: Vec::new(),
            error: None,
            aux_data: None,
        }
    }
}

impl Default for ExecStep {
    fn default() -> Self {
        Self {
            exec_state: ExecState::Op(OpcodeId::INVALID(0)),
            pc: ProgramCounter(0),
            stack_size: 0,
            memory_size: 0,
            gas_left: Gas(0),
            gas_cost: GasCost(0),
            gas_refund: Gas(0),
            call_index: 0,
            rwc: RWCounter(0),
            reversible_write_counter: 0,
            bus_mapping_instance: Vec::new(),
            error: None,
            aux_data: None,
        }
    }
}

/// Context of a [`Block`] which can mutate in a [`Transaction`].
#[derive(Debug)]
pub struct BlockContext {
    /// Used to track the global counter in every operation in the block.
    /// Contains the next available value.
    pub rwc: RWCounter,
    /// Map call_id to (tx_index, call_index) (where tx_index is the index used
    /// in Block.txs and call_index is the index used in Transaction.
    /// calls).
    call_map: HashMap<usize, (usize, usize)>,
}

impl Default for BlockContext {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockContext {
    /// Create a new Self
    pub fn new() -> Self {
        Self {
            rwc: RWCounter::new(),
            call_map: HashMap::new(),
        }
    }
}

/// Circuit Input related to a block.
#[derive(Debug)]
pub struct Block {
    /// chain id
    pub chain_id: Word,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// coinbase
    pub coinbase: Address,
    /// time
    pub gas_limit: u64,
    /// number
    pub number: Word,
    /// difficulty
    pub timestamp: Word,
    /// gas limit
    pub difficulty: Word,
    /// base fee
    pub base_fee: Word,
    /// Container of operations done in this block.
    pub container: OperationContainer,
    /// Transactions contained in the block
    pub txs: Vec<Transaction>,
    code: HashMap<Hash, Vec<u8>>,
}

impl Block {
    /// Create a new block.
    pub fn new<TX>(
        chain_id: Word,
        history_hashes: Vec<Word>,
        eth_block: &eth_types::Block<TX>,
    ) -> Result<Self, Error> {
        if eth_block.base_fee_per_gas.is_none() {
            // FIXME: resolve this once we have proper EIP-1559 support
            log::warn!(
                "This does not look like a EIP-1559 block - base_fee_per_gas defaults to zero"
            );
        }

        Ok(Self {
            chain_id,
            history_hashes,
            coinbase: eth_block.author,
            gas_limit: eth_block.gas_limit.low_u64(),
            number: eth_block
                .number
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?
                .low_u64()
                .into(),
            timestamp: eth_block.timestamp,
            difficulty: eth_block.difficulty,
            base_fee: eth_block.base_fee_per_gas.unwrap_or_default(),
            container: OperationContainer::new(),
            txs: Vec::new(),
            code: HashMap::new(),
        })
    }

    /// Return the list of transactions of this block.
    pub fn txs(&self) -> &[Transaction] {
        &self.txs
    }

    #[cfg(test)]
    pub fn txs_mut(&mut self) -> &mut Vec<Transaction> {
        &mut self.txs
    }
}

/// Type of a *CALL*/CREATE* Function.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CallKind {
    /// CALL
    Call,
    /// CALLCODE
    CallCode,
    /// DELEGATECALL
    DelegateCall,
    /// STATICCALL
    StaticCall,
    /// CREATE
    Create,
    /// CREATE2
    Create2,
}

impl CallKind {
    fn is_create(&self) -> bool {
        matches!(self, Self::Create | Self::Create2)
    }
}

impl Default for CallKind {
    fn default() -> Self {
        Self::Call
    }
}

impl TryFrom<OpcodeId> for CallKind {
    type Error = Error;

    fn try_from(op: OpcodeId) -> Result<Self, Self::Error> {
        Ok(match op {
            OpcodeId::CALL => CallKind::Call,
            OpcodeId::CALLCODE => CallKind::CallCode,
            OpcodeId::DELEGATECALL => CallKind::DelegateCall,
            OpcodeId::STATICCALL => CallKind::StaticCall,
            OpcodeId::CREATE => CallKind::Create,
            OpcodeId::CREATE2 => CallKind::Create2,
            _ => return Err(Error::OpcodeIdNotCallType),
        })
    }
}

/// Circuit Input related to an Ethereum Call
#[derive(Clone, Debug, Default)]
pub struct Call {
    /// Unique call identifier within the Block.
    pub call_id: usize,
    /// Caller's id.
    pub caller_id: usize,
    /// Type of call
    pub kind: CallKind,
    /// This call is being executed without write access (STATIC)
    pub is_static: bool,
    /// This call generated implicity by a Transaction.
    pub is_root: bool,
    /// This call is persistent or call stack reverts at some point
    pub is_persistent: bool,
    /// This call ends successfully or not
    pub is_success: bool,
    /// This rw_counter at the end of reversion
    pub rw_counter_end_of_reversion: usize,
    /// Address of caller
    pub caller_address: Address,
    /// Address where this call is being executed
    pub address: Address,
    /// Code Source
    pub code_source: CodeSource,
    /// Code Hash
    pub code_hash: Hash,
    /// Depth
    pub depth: usize,
    /// Value
    pub value: Word,
    /// Call data offset
    pub call_data_offset: u64,
    /// Call data length
    pub call_data_length: u64,
    /// Return data offset
    pub return_data_offset: u64,
    /// Return data length
    pub return_data_length: u64,
}

impl Call {
    /// This call is root call with tx.to == null, or op == CREATE or op ==
    /// CREATE2
    pub fn is_create(&self) -> bool {
        self.kind.is_create()
    }
}

/// Context of a [`Call`].
#[derive(Debug, Default)]
pub struct CallContext {
    /// Index of call
    pub index: usize,
    /// Reversible Write Counter tracks the number of write operations in the
    /// call. It is incremented when a subcall in this call succeeds by the
    /// number of successful writes in the subcall.
    pub reversible_write_counter: usize,
    /// Call data (copy of tx input or caller's
    /// memory[call_data_offset..call_data_offset + call_data_length])
    pub call_data: Vec<u8>,
}

/// A reversion group is the collection of calls and the operations which are
/// [`Operation::reversible`] that happened in them, that will be reverted at
/// once when the call that initiated this reversion group eventually ends with
/// failure (and thus reverts).
#[derive(Debug, Default)]
pub struct ReversionGroup {
    /// List of `index` and `reversible_write_counter_offset` of calls belong to
    /// this group. `reversible_write_counter_offset` is the number of
    /// reversible operations that have happened before the call within the
    /// same reversion group.
    calls: Vec<(usize, usize)>,
    /// List of `step_index` and `OperationRef` that have been done in this
    /// group.
    op_refs: Vec<(usize, OperationRef)>,
}

#[derive(Debug)]
/// Context of a [`Transaction`] which can mutate in an [`ExecStep`].
pub struct TransactionContext {
    /// Unique identifier of transaction of the block. The value is `index + 1`.
    id: usize,
    /// Identifier if this transaction is last one of the block or not.
    is_last_tx: bool,
    /// Call stack.
    calls: Vec<CallContext>,
    /// Call `is_success` indexed by `call_index`.
    call_is_success: Vec<bool>,
    /// Reversion groups by failure calls. We keep the reversion groups in a
    /// stack because it's possible to encounter a revert within a revert,
    /// and in such case, we must only process the reverted operation once:
    /// in the inner most revert (which we track with the last element in
    /// the reversion groups stack), and skip it in the outer revert.
    reversion_groups: Vec<ReversionGroup>,
}

impl TransactionContext {
    /// Create a new Self.
    pub fn new(
        eth_tx: &eth_types::Transaction,
        geth_trace: &GethExecTrace,
        is_last_tx: bool,
    ) -> Result<Self, Error> {
        // Iterate over geth_trace to inspect and collect each call's is_success, which
        // is at the top of stack at the step after a call.
        let call_is_success = {
            let mut call_is_success_map = BTreeMap::new();
            let mut call_indices = Vec::new();
            for (index, geth_step) in geth_trace.struct_logs.iter().enumerate() {
                if let Some(geth_next_step) = geth_trace.struct_logs.get(index + 1) {
                    // Dive into call
                    if geth_step.depth + 1 == geth_next_step.depth {
                        call_indices.push(index);
                    // Emerge from call
                    } else if geth_step.depth - 1 == geth_next_step.depth {
                        let is_success = !geth_next_step.stack.last()?.is_zero();
                        call_is_success_map.insert(call_indices.pop().unwrap(), is_success);
                    // Callee with empty code
                    } else if CallKind::try_from(geth_step.op).is_ok() {
                        let is_success = !geth_next_step.stack.last()?.is_zero();
                        call_is_success_map.insert(index, is_success);
                    }
                }
            }

            std::iter::once(!geth_trace.failed)
                .chain(call_is_success_map.into_values())
                .collect()
        };

        let mut tx_ctx = Self {
            id: eth_tx
                .transaction_index
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?
                .as_u64() as usize
                + 1,
            is_last_tx,
            call_is_success,
            calls: Vec::new(),
            reversion_groups: Vec::new(),
        };
        tx_ctx.push_call_ctx(0, eth_tx.input.to_vec());

        Ok(tx_ctx)
    }

    /// Return id of the this transaction.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Return is_last_tx of the this transaction.
    pub fn is_last_tx(&self) -> bool {
        self.is_last_tx
    }

    /// Return the calls in this transaction.
    pub fn calls(&self) -> &[CallContext] {
        &self.calls
    }

    /// Return the index of the current call (the last call in the call stack).
    fn call_index(&self) -> Result<usize, Error> {
        self.calls
            .last()
            .ok_or(Error::InvalidGethExecTrace(
                "Call stack is empty but call is used",
            ))
            .map(|call| call.index)
    }

    fn call_ctx(&self) -> Result<&CallContext, Error> {
        self.calls.last().ok_or(Error::InvalidGethExecTrace(
            "Call stack is empty but call is used",
        ))
    }

    fn call_ctx_mut(&mut self) -> Result<&mut CallContext, Error> {
        self.calls.last_mut().ok_or(Error::InvalidGethExecTrace(
            "Call stack is empty but call is used",
        ))
    }

    /// Push a new call context and its index into the call stack.
    fn push_call_ctx(&mut self, call_idx: usize, call_data: Vec<u8>) {
        if !self.call_is_success[call_idx] {
            self.reversion_groups.push(ReversionGroup {
                calls: vec![(call_idx, 0)],
                op_refs: Vec::new(),
            })
        } else if let Some(reversion_group) = self.reversion_groups.last_mut() {
            let caller_ctx = self.calls.last().expect("calls should not be empty");
            let caller_reversible_write_counter = self
                .calls
                .last()
                .expect("calls should not be empty")
                .reversible_write_counter;
            let caller_reversible_write_counter_offset = reversion_group
                .calls
                .iter()
                .find(|(call_idx, _)| *call_idx == caller_ctx.index)
                .expect("calls should not be empty")
                .1;
            reversion_group.calls.push((
                call_idx,
                caller_reversible_write_counter + caller_reversible_write_counter_offset,
            ));
        }

        self.calls.push(CallContext {
            index: call_idx,
            reversible_write_counter: 0,
            call_data,
        });
    }

    /// Pop the last entry in the call stack.
    fn pop_call_ctx(&mut self) {
        let call = self.calls.pop().expect("calls should not be empty");
        // Accumulate reversible_write_counter if call is success
        if self.call_is_success[call.index] {
            if let Some(caller) = self.calls.last_mut() {
                caller.reversible_write_counter += call.reversible_write_counter;
            }
        }
    }
}

#[derive(Debug, Clone)]
/// Result of the parsing of an Ethereum Transaction.
pub struct Transaction {
    /// Nonce
    pub nonce: u64,
    /// Gas
    pub gas: u64,
    /// Gas price
    pub gas_price: Word,
    /// From / Caller Address
    pub from: Address, // caller_address
    /// To / Callee Address
    pub to: Address, // callee_address
    /// Value
    pub value: Word,
    /// Input / Call Data
    pub input: Vec<u8>,
    /// Calls made in the transaction
    calls: Vec<Call>,
    /// Execution steps
    steps: Vec<ExecStep>,
}

impl Transaction {
    /// Create a new Self.
    pub fn new(
        call_id: usize,
        sdb: &StateDB,
        code_db: &mut CodeDB,
        eth_tx: &eth_types::Transaction,
        is_success: bool,
    ) -> Result<Self, Error> {
        let (found, _) = sdb.get_account(&eth_tx.from);
        if !found {
            return Err(Error::AccountNotFound(eth_tx.from));
        }

        let call = if let Some(address) = eth_tx.to {
            // Contract Call / Transfer
            let (found, account) = sdb.get_account(&address);
            if !found {
                return Err(Error::AccountNotFound(address));
            }
            let code_hash = account.code_hash;
            Call {
                call_id,
                kind: CallKind::Call,
                is_root: true,
                is_persistent: is_success,
                is_success,
                caller_address: eth_tx.from,
                address,
                code_source: CodeSource::Address(address),
                code_hash,
                depth: 1,
                value: eth_tx.value,
                call_data_length: eth_tx.input.as_ref().len() as u64,
                ..Default::default()
            }
        } else {
            // Contract creation
            let code_hash = code_db.insert(eth_tx.input.to_vec());
            Call {
                call_id,
                kind: CallKind::Create,
                is_root: true,
                is_persistent: is_success,
                is_success,
                caller_address: eth_tx.from,
                address: get_contract_address(eth_tx.from, eth_tx.nonce),
                code_source: CodeSource::Tx,
                code_hash,
                depth: 1,
                value: eth_tx.value,
                ..Default::default()
            }
        };

        Ok(Self {
            nonce: eth_tx.nonce.as_u64(),
            gas: eth_tx.gas.as_u64(),
            gas_price: eth_tx.gas_price.unwrap_or_default(),
            from: eth_tx.from,
            to: eth_tx.to.unwrap_or_default(),
            value: eth_tx.value,
            input: eth_tx.input.to_vec(),
            calls: vec![call],
            steps: Vec::new(),
        })
    }

    /// Wether this [`Transaction`] is a create one
    pub fn is_create(&self) -> bool {
        self.calls[0].is_create()
    }

    /// Return the list of execution steps of this transaction.
    pub fn steps(&self) -> &[ExecStep] {
        &self.steps
    }

    #[cfg(test)]
    pub fn steps_mut(&mut self) -> &mut Vec<ExecStep> {
        &mut self.steps
    }

    /// Return the list of calls of this transaction.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    fn push_call(&mut self, call: Call) {
        self.calls.push(call);
    }
}

/// Reference to the internal state of the CircuitInputBuilder in a particular
/// [`ExecStep`].
pub struct CircuitInputStateRef<'a> {
    /// StateDB
    pub sdb: &'a mut StateDB,
    /// CodeDB
    pub code_db: &'a mut CodeDB,
    /// Block
    pub block: &'a mut Block,
    /// Block Context
    pub block_ctx: &'a mut BlockContext,
    /// Transaction
    pub tx: &'a mut Transaction,
    /// Transaction Context
    pub tx_ctx: &'a mut TransactionContext,
}

impl<'a> CircuitInputStateRef<'a> {
    /// Create a new step from a `GethExecStep`
    pub fn new_step(&self, geth_step: &GethExecStep) -> Result<ExecStep, Error> {
        let call_ctx = self.tx_ctx.call_ctx()?;
        Ok(ExecStep::new(
            geth_step,
            call_ctx.index,
            self.block_ctx.rwc,
            call_ctx.reversible_write_counter,
        ))
    }

    /// Create a new BeginTx step
    pub fn new_begin_tx_step(&self) -> ExecStep {
        ExecStep {
            exec_state: ExecState::BeginTx,
            gas_left: Gas(self.tx.gas),
            rwc: self.block_ctx.rwc,
            ..Default::default()
        }
    }

    /// Create a new EndTx step
    pub fn new_end_tx_step(&self) -> ExecStep {
        let prev_step = self
            .tx
            .steps()
            .last()
            .expect("steps should have at least one BeginTx step");
        ExecStep {
            exec_state: ExecState::EndTx,
            gas_left: Gas(prev_step.gas_left.0 - prev_step.gas_cost.0),
            rwc: self.block_ctx.rwc,
            // For tx without code execution
            reversible_write_counter: if let Some(call_ctx) = self.tx_ctx.calls().last() {
                call_ctx.reversible_write_counter
            } else {
                0
            },
            ..Default::default()
        }
    }

    /// Push an [`Operation`] into the [`OperationContainer`] with the next
    /// [`RWCounter`] and then adds a reference to the stored operation
    /// ([`OperationRef`]) inside the bus-mapping instance of the current
    /// [`ExecStep`].  Then increase the block_ctx [`RWCounter`] by one.
    pub fn push_op<T: Op>(&mut self, step: &mut ExecStep, rw: RW, op: T) {
        let op_ref =
            self.block
                .container
                .insert(Operation::new(self.block_ctx.rwc.inc_pre(), rw, op));
        step.bus_mapping_instance.push(op_ref);
    }

    /// Push an [`Operation`] with reversible to be true into the
    /// [`OperationContainer`] with the next [`RWCounter`] and then adds a
    /// reference to the stored operation ([`OperationRef`]) inside the
    /// bus-mapping instance of the current [`ExecStep`]. Then increase the
    /// block_ctx [`RWCounter`] by one.
    /// This method should be used in `Opcode::gen_associated_ops` instead of
    /// `push_op` when the operation is `RW::WRITE` and it can be reverted (for
    /// example, a write `StorageOp`).
    pub fn push_op_reversible<T: Op>(
        &mut self,
        step: &mut ExecStep,
        rw: RW,
        op: T,
    ) -> Result<(), Error> {
        if matches!(rw, RW::WRITE) {
            self.apply_op(&op.clone().into_enum());
        }
        let op_ref = self.block.container.insert(Operation::new_reversible(
            self.block_ctx.rwc.inc_pre(),
            rw,
            op,
        ));
        step.bus_mapping_instance.push(op_ref);

        // Increase reversible_write_counter
        self.call_ctx_mut()?.reversible_write_counter += 1;

        // Add the operation into reversible_ops if this call is not persistent
        if !self.call()?.is_persistent {
            self.tx_ctx
                .reversion_groups
                .last_mut()
                .expect("reversion_groups should not be empty for non-persistent call")
                .op_refs
                .push((self.tx.steps.len(), op_ref));
        }

        Ok(())
    }

    /// Push a [`MemoryOp`] into the [`OperationContainer`] with the next
    /// [`RWCounter`] and `call_id`, and then adds a reference to
    /// the stored operation ([`OperationRef`]) inside the bus-mapping
    /// instance of the current [`ExecStep`].  Then increase the `block_ctx`
    /// [`RWCounter`] by one.
    pub fn push_memory_op(
        &mut self,
        step: &mut ExecStep,
        rw: RW,
        address: MemoryAddress,
        value: u8,
    ) -> Result<(), Error> {
        let call_id = self.call()?.call_id;
        self.push_op(step, rw, MemoryOp::new(call_id, address, value));
        Ok(())
    }

    /// Push a [`StackOp`] into the [`OperationContainer`] with the next
    /// [`RWCounter`] and `call_id`, and then adds a reference to
    /// the stored operation ([`OperationRef`]) inside the bus-mapping
    /// instance of the current [`ExecStep`].  Then increase the `block_ctx`
    /// [`RWCounter`] by one.
    pub fn push_stack_op(
        &mut self,
        step: &mut ExecStep,
        rw: RW,
        address: StackAddress,
        value: Word,
    ) -> Result<(), Error> {
        let call_id = self.call()?.call_id;
        self.push_op(step, rw, StackOp::new(call_id, address, value));
        Ok(())
    }

    /// Fetch and return code for the given code hash from the code DB.
    pub fn code(&self, code_hash: H256) -> Result<Vec<u8>, Error> {
        self.code_db
            .0
            .get(&code_hash)
            .cloned()
            .ok_or(Error::CodeNotFound(code_hash))
    }

    /// Reference to the current Call
    pub fn call(&self) -> Result<&Call, Error> {
        self.tx_ctx
            .call_index()
            .map(|call_idx| &self.tx.calls[call_idx])
    }

    /// Mutable reference to the current Call
    pub fn call_mut(&mut self) -> Result<&mut Call, Error> {
        self.tx_ctx
            .call_index()
            .map(|call_idx| &mut self.tx.calls[call_idx])
    }

    /// Reference to the current CallContext
    pub fn call_ctx(&self) -> Result<&CallContext, Error> {
        self.tx_ctx.call_ctx()
    }

    /// Mutable reference to the call CallContext
    pub fn call_ctx_mut(&mut self) -> Result<&mut CallContext, Error> {
        self.tx_ctx.call_ctx_mut()
    }

    /// Push a new [`Call`] into the [`Transaction`], and add its index and
    /// [`CallContext`] in the `call_stack` of the [`TransactionContext`]
    pub fn push_call(&mut self, call: Call, step: &GethExecStep) {
        let call_data = match call.kind {
            CallKind::Call | CallKind::CallCode | CallKind::DelegateCall | CallKind::StaticCall => {
                let call_data = if step.memory.0.len() < call.call_data_offset as usize {
                    &[]
                } else {
                    &step.memory.0[call.call_data_offset as usize..]
                };
                if call_data.len() < call.call_data_length as usize {
                    // Expand call_data to expected size
                    call_data
                        .iter()
                        .cloned()
                        .pad_using(call.call_data_length as usize, |_| 0)
                        .collect()
                } else {
                    call_data[..call.call_data_length as usize].to_vec()
                }
            }
            CallKind::Create | CallKind::Create2 => Vec::new(),
        };

        let call_id = call.call_id;
        let call_idx = self.tx.calls.len();

        self.tx_ctx.push_call_ctx(call_idx, call_data);
        self.tx.push_call(call);

        self.block_ctx
            .call_map
            .insert(call_id, (self.block.txs.len(), call_idx));
    }

    /// Return the contract address of a CREATE step.  This is calculated by
    /// inspecting the current address and its nonce from the StateDB.
    fn create_address(&self) -> Result<Address, Error> {
        let sender = self.call()?.address;
        let (found, account) = self.sdb.get_account(&sender);
        if !found {
            return Err(Error::AccountNotFound(sender));
        }
        Ok(get_contract_address(sender, account.nonce))
    }

    /// Return the contract address of a CREATE2 step.  This is calculated
    /// deterministically from the arguments in the stack.
    fn create2_address(&self, step: &GethExecStep) -> Result<Address, Error> {
        let salt = step.stack.nth_last(3)?;
        let init_code = get_create_init_code(step)?;
        Ok(get_create2_address(
            self.call()?.address,
            salt.to_be_bytes().to_vec(),
            init_code.to_vec(),
        ))
    }

    /// Check if address is a precompiled or not.
    pub fn is_precompiled(&self, address: &Address) -> bool {
        address.0[0..19] == [0u8; 19] && (1..=9).contains(&address.0[19])
    }

    /// Parse [`Call`] from a *CALL*/CREATE* step.
    pub fn parse_call(&mut self, step: &GethExecStep) -> Result<Call, Error> {
        let is_success = *self
            .tx_ctx
            .call_is_success
            .get(self.tx.calls().len())
            .unwrap();
        let kind = CallKind::try_from(step.op)?;
        let caller = self.call()?;

        let (caller_address, address, value) = match kind {
            CallKind::Call => (
                caller.address,
                step.stack.nth_last(1)?.to_address(),
                step.stack.nth_last(2)?,
            ),
            CallKind::CallCode => (caller.address, caller.address, step.stack.nth_last(2)?),
            CallKind::DelegateCall => (caller.caller_address, caller.address, 0.into()),
            CallKind::StaticCall => (
                caller.address,
                step.stack.nth_last(1)?.to_address(),
                Word::zero(),
            ),
            CallKind::Create => (caller.address, self.create_address()?, step.stack.last()?),
            CallKind::Create2 => (
                caller.address,
                self.create2_address(step)?,
                step.stack.last()?,
            ),
        };

        let (code_source, code_hash) = match kind {
            CallKind::Create | CallKind::Create2 => {
                let init_code = get_create_init_code(step)?;
                let code_hash = self.code_db.insert(init_code.to_vec());
                (CodeSource::Memory, code_hash)
            }
            _ => {
                let code_address = match kind {
                    CallKind::CallCode | CallKind::DelegateCall => {
                        step.stack.nth_last(1)?.to_address()
                    }
                    _ => address,
                };
                let (found, account) = self.sdb.get_account(&code_address);
                if !found {
                    return Err(Error::AccountNotFound(code_address));
                }
                (CodeSource::Address(code_address), account.code_hash)
            }
        };

        let (call_data_offset, call_data_length, return_data_offset, return_data_length) =
            match kind {
                CallKind::Call | CallKind::CallCode => {
                    let call_data = get_call_memory_offset_length(step, 3)?;
                    let return_data = get_call_memory_offset_length(step, 5)?;
                    (call_data.0, call_data.1, return_data.0, return_data.1)
                }
                CallKind::DelegateCall | CallKind::StaticCall => {
                    let call_data = get_call_memory_offset_length(step, 2)?;
                    let return_data = get_call_memory_offset_length(step, 4)?;
                    (call_data.0, call_data.1, return_data.0, return_data.1)
                }
                CallKind::Create | CallKind::Create2 => (0, 0, 0, 0),
            };

        let caller = self.call()?;
        let call = Call {
            call_id: self.block_ctx.rwc.0,
            caller_id: caller.call_id,
            kind,
            is_static: kind == CallKind::StaticCall || caller.is_static,
            is_root: false,
            is_persistent: caller.is_persistent && is_success,
            is_success,
            rw_counter_end_of_reversion: 0,
            caller_address,
            address,
            code_source,
            code_hash,
            depth: caller.depth + 1,
            value,
            call_data_offset,
            call_data_length,
            return_data_offset,
            return_data_length,
        };

        Ok(call)
    }

    /// Return the reverted version of an op by op_ref only if the original op
    /// was reversible.
    fn get_rev_op_by_ref(&self, op_ref: &OperationRef) -> Option<OpEnum> {
        match op_ref {
            OperationRef(Target::Storage, idx) => {
                let operation = &self.block.container.storage[*idx];
                if operation.rw().is_write() && operation.reversible() {
                    Some(OpEnum::Storage(operation.op().reverse()))
                } else {
                    None
                }
            }
            OperationRef(Target::TxAccessListAccount, idx) => {
                let operation = &self.block.container.tx_access_list_account[*idx];
                if operation.rw().is_write() && operation.reversible() {
                    Some(OpEnum::TxAccessListAccount(operation.op().reverse()))
                } else {
                    None
                }
            }
            OperationRef(Target::TxAccessListAccountStorage, idx) => {
                let operation = &self.block.container.tx_access_list_account_storage[*idx];
                if operation.rw().is_write() && operation.reversible() {
                    Some(OpEnum::TxAccessListAccountStorage(operation.op().reverse()))
                } else {
                    None
                }
            }
            OperationRef(Target::TxRefund, idx) => {
                let operation = &self.block.container.tx_refund[*idx];
                if operation.rw().is_write() && operation.reversible() {
                    Some(OpEnum::TxRefund(operation.op().reverse()))
                } else {
                    None
                }
            }
            OperationRef(Target::Account, idx) => {
                let operation = &self.block.container.account[*idx];
                if operation.rw().is_write() && operation.reversible() {
                    Some(OpEnum::Account(operation.op().reverse()))
                } else {
                    None
                }
            }
            OperationRef(Target::AccountDestructed, idx) => {
                let operation = &self.block.container.account_destructed[*idx];
                if operation.rw().is_write() && operation.reversible() {
                    Some(OpEnum::AccountDestructed(operation.op().reverse()))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Apply op to state.
    fn apply_op(&mut self, op: &OpEnum) {
        match &op {
            OpEnum::Storage(op) => {
                self.sdb.set_storage(&op.address, &op.key, &op.value);
            }
            OpEnum::TxAccessListAccount(op) => {
                if !op.value_prev && op.value {
                    self.sdb.add_account_to_access_list(op.address);
                }
                if op.value_prev && !op.value {
                    self.sdb.remove_account_from_access_list(&op.address);
                }
            }
            OpEnum::TxAccessListAccountStorage(op) => {
                if !op.value_prev && op.value {
                    self.sdb
                        .add_account_storage_to_access_list((op.address, op.key));
                }
                if op.value_prev && !op.value {
                    self.sdb
                        .remove_account_storage_from_access_list(&(op.address, op.key));
                }
            }
            OpEnum::Account(op) => {
                let (_, account) = self.sdb.get_account_mut(&op.address);
                match op.field {
                    AccountField::Nonce => account.nonce = op.value,
                    AccountField::Balance => account.balance = op.value,
                    AccountField::CodeHash => {
                        account.code_hash = op.value.to_be_bytes().into();
                    }
                }
            }
            OpEnum::TxRefund(op) => {
                self.sdb.set_refund(op.value);
            }
            OpEnum::AccountDestructed(_) => unimplemented!(),
            _ => unreachable!(),
        };
    }

    /// Handle a reversion group
    fn handle_reversion(&mut self) {
        let reversion_group = self
            .tx_ctx
            .reversion_groups
            .pop()
            .expect("reversion_groups should not be empty for non-persistent call");

        // Apply reversions
        for (step_index, op_ref) in reversion_group.op_refs.into_iter().rev() {
            if let Some(op) = self.get_rev_op_by_ref(&op_ref) {
                self.apply_op(&op);
                let rev_op_ref = self.block.container.insert_op_enum(
                    self.block_ctx.rwc.inc_pre(),
                    RW::WRITE,
                    false,
                    op,
                );
                self.tx.steps[step_index]
                    .bus_mapping_instance
                    .push(rev_op_ref);
            }
        }

        // Set calls' `rw_counter_end_of_reversion`
        let rwc = self.block_ctx.rwc.0 - 1;
        for (call_idx, reversible_write_counter_offset) in reversion_group.calls {
            self.tx.calls[call_idx].rw_counter_end_of_reversion =
                rwc - reversible_write_counter_offset;
        }
    }

    /// Handle a return step caused by any opcode that causes a return to the
    /// previous call context.
    pub fn handle_return(&mut self) -> Result<(), Error> {
        // Handle reversion if this call doens't end successfully
        if !self.call()?.is_success {
            self.handle_reversion();
        }

        self.tx_ctx.pop_call_ctx();

        Ok(())
    }

    fn get_step_err(
        &self,
        step: &GethExecStep,
        next_step: Option<&GethExecStep>,
    ) -> Result<Option<ExecError>, Error> {
        if let Some(error) = &step.error {
            return Ok(Some(get_step_reported_error(&step.op, error)));
        }

        if matches!(step.op, OpcodeId::INVALID(_)) {
            return Ok(Some(ExecError::InvalidOpcode));
        }

        // When last step has opcodes that halt, there's no error.
        if matches!(next_step, None)
            && matches!(
                step.op,
                OpcodeId::STOP | OpcodeId::RETURN | OpcodeId::REVERT | OpcodeId::SELFDESTRUCT
            )
        {
            return Ok(None);
        }

        let next_depth = next_step.map(|s| s.depth).unwrap_or(0);
        let next_result = next_step
            .map(|s| s.stack.last().unwrap_or_else(|_| Word::zero()))
            .unwrap_or_else(Word::zero);

        let call = self.call()?;

        // Return from a call with a failure
        if step.depth != next_depth && next_result.is_zero() {
            if !matches!(step.op, OpcodeId::RETURN) {
                // Without calling RETURN
                return Ok(match step.op {
                    OpcodeId::JUMP | OpcodeId::JUMPI => Some(ExecError::InvalidJump),
                    OpcodeId::RETURNDATACOPY => Some(ExecError::ReturnDataOutOfBounds),
                    // Break write protection (CALL with value will be handled below)
                    OpcodeId::SSTORE
                    | OpcodeId::CREATE
                    | OpcodeId::CREATE2
                    | OpcodeId::SELFDESTRUCT
                    | OpcodeId::LOG0
                    | OpcodeId::LOG1
                    | OpcodeId::LOG2
                    | OpcodeId::LOG3
                    | OpcodeId::LOG4
                        if call.is_static =>
                    {
                        Some(ExecError::WriteProtection)
                    }
                    OpcodeId::REVERT => None,
                    _ => {
                        return Err(Error::UnexpectedExecStepError(
                            "call failure without return",
                            step.clone(),
                        ));
                    }
                });
            } else {
                // Return from a {CREATE, CREATE2} with a failure, via RETURN
                if !call.is_root && call.is_create() {
                    let offset = step.stack.nth_last(0)?;
                    let length = step.stack.nth_last(1)?;
                    if length > Word::from(0x6000u64) {
                        return Ok(Some(ExecError::MaxCodeSizeExceeded));
                    } else if length > Word::zero()
                        && !step.memory.0.is_empty()
                        && step.memory.0.get(offset.low_u64() as usize) == Some(&0xef)
                    {
                        return Ok(Some(ExecError::InvalidCreationCode));
                    } else if Word::from(200u64) * length > Word::from(step.gas.0) {
                        return Ok(Some(ExecError::CodeStoreOutOfGas));
                    } else {
                        return Err(Error::UnexpectedExecStepError(
                            "failure in RETURN from {CREATE, CREATE2}",
                            step.clone(),
                        ));
                    }
                } else {
                    return Err(Error::UnexpectedExecStepError(
                        "failure in RETURN",
                        step.clone(),
                    ));
                }
            }
        }

        // Return from a call via RETURN or STOP and having a success result is
        // OK.

        // Return from a call without calling RETURN or STOP and having success
        // is unexpected.
        if step.depth != next_depth
            && next_result != Word::zero()
            && !matches!(step.op, OpcodeId::RETURN | OpcodeId::STOP)
        {
            return Err(Error::UnexpectedExecStepError(
                "success result without {RETURN, STOP}",
                step.clone(),
            ));
        }

        // The *CALL*/CREATE* code was not executed
        let next_pc = next_step.map(|s| s.pc.0).unwrap_or(1);
        if matches!(
            step.op,
            OpcodeId::CALL
                | OpcodeId::CALLCODE
                | OpcodeId::DELEGATECALL
                | OpcodeId::STATICCALL
                | OpcodeId::CREATE
                | OpcodeId::CREATE2
        ) && next_result.is_zero()
            && next_pc != 0
        {
            if step.depth == 1025 {
                return Ok(Some(ExecError::Depth));
            }

            // Insufficient_balance
            let value = match step.op {
                OpcodeId::CALL | OpcodeId::CALLCODE => step.stack.nth_last(2)?,
                OpcodeId::CREATE | OpcodeId::CREATE2 => step.stack.nth_last(0)?,
                _ => Word::zero(),
            };

            // CALL with value
            if matches!(step.op, OpcodeId::CALL) && !value.is_zero() && self.call()?.is_static {
                return Ok(Some(ExecError::WriteProtection));
            }

            let sender = self.call()?.address;
            let (found, account) = self.sdb.get_account(&sender);
            if !found {
                return Err(Error::AccountNotFound(sender));
            }
            if account.balance < value {
                return Ok(Some(ExecError::InsufficientBalance));
            }

            // Address collision
            if matches!(step.op, OpcodeId::CREATE | OpcodeId::CREATE2) {
                let address = match step.op {
                    OpcodeId::CREATE => self.create_address()?,
                    OpcodeId::CREATE2 => self.create2_address(step)?,
                    _ => unreachable!(),
                };
                let (found, _) = self.sdb.get_account(&address);
                if found {
                    return Ok(Some(ExecError::ContractAddressCollision));
                }
            }

            return Err(Error::UnexpectedExecStepError(
                "*CALL*/CREATE* code not executed",
                step.clone(),
            ));
        }

        Ok(None)
    }
}

#[derive(Debug)]
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
                op.value = self.block.txs[*tx_idx].calls[*call_idx]
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
        for (tx_index, tx) in eth_block.transactions.iter().enumerate() {
            let geth_trace = &geth_traces[tx_index];
            self.handle_tx(tx, geth_trace, tx_index + 1 == eth_block.transactions.len())?;
        }
        self.set_value_ops_call_context_rwc_eor();
        Ok(())
    }

    /// Handle a transaction with its corresponding execution trace to generate
    /// all the associated operations.  Each operation is registered in
    /// `self.block.container`, and each step stores the [`OperationRef`] to
    /// each of the generated operations.
    fn handle_tx(
        &mut self,
        eth_tx: &eth_types::Transaction,
        geth_trace: &GethExecTrace,
        is_last_tx: bool,
    ) -> Result<(), Error> {
        let mut tx = self.new_tx(eth_tx, !geth_trace.failed)?;
        let mut tx_ctx = TransactionContext::new(eth_tx, geth_trace, is_last_tx)?;

        // TODO: Move into gen_associated_steps with
        // - execution_state: BeginTx
        // - op: None
        // Generate BeginTx step
        let begin_tx_step = gen_begin_tx_ops(&mut self.state_ref(&mut tx, &mut tx_ctx))?;
        tx.steps.push(begin_tx_step);

        for (index, geth_step) in geth_trace.struct_logs.iter().enumerate() {
            let mut state_ref = self.state_ref(&mut tx, &mut tx_ctx);
            log::trace!("handle {}th opcode {:?} ", index, geth_step.op);
            let exec_steps = gen_associated_ops(
                &geth_step.op,
                &mut state_ref,
                &geth_trace.struct_logs[index..],
            )?;
            tx.steps.extend(exec_steps);
        }

        // TODO: Move into gen_associated_steps with
        // - execution_state: EndTx
        // - op: None
        // Generate EndTx step
        let end_tx_step = gen_end_tx_ops(&mut self.state_ref(&mut tx, &mut tx_ctx))?;
        tx.steps.push(end_tx_step);

        self.sdb.commit_tx();
        self.block.txs.push(tx);

        Ok(())
    }
}

fn get_step_reported_error(op: &OpcodeId, error: &str) -> ExecError {
    if error == GETH_ERR_OUT_OF_GAS || error == GETH_ERR_GAS_UINT_OVERFLOW {
        // NOTE: We report a GasUintOverflow error as an OutOfGas error
        let oog_err = match op {
            OpcodeId::MLOAD | OpcodeId::MSTORE | OpcodeId::MSTORE8 => {
                OogError::StaticMemoryExpansion
            }
            OpcodeId::CREATE | OpcodeId::RETURN | OpcodeId::REVERT => {
                OogError::DynamicMemoryExpansion
            }
            OpcodeId::CALLDATACOPY | OpcodeId::CODECOPY | OpcodeId::RETURNDATACOPY => {
                OogError::MemoryCopy
            }
            OpcodeId::BALANCE | OpcodeId::EXTCODESIZE | OpcodeId::EXTCODEHASH => {
                OogError::AccountAccess
            }
            OpcodeId::LOG0 | OpcodeId::LOG1 | OpcodeId::LOG2 | OpcodeId::LOG3 | OpcodeId::LOG4 => {
                OogError::Log
            }
            OpcodeId::EXP => OogError::Exp,
            OpcodeId::SHA3 => OogError::Sha3,
            OpcodeId::EXTCODECOPY => OogError::ExtCodeCopy,
            OpcodeId::SLOAD => OogError::Sload,
            OpcodeId::SSTORE => OogError::Sstore,
            OpcodeId::CALL => OogError::Call,
            OpcodeId::CALLCODE => OogError::CallCode,
            OpcodeId::DELEGATECALL => OogError::DelegateCall,
            OpcodeId::CREATE2 => OogError::Create2,
            OpcodeId::STATICCALL => OogError::StaticCall,
            OpcodeId::SELFDESTRUCT => OogError::SelfDestruct,
            _ => OogError::Constant,
        };
        ExecError::OutOfGas(oog_err)
    } else if error.starts_with(GETH_ERR_STACK_OVERFLOW) {
        ExecError::StackOverflow
    } else if error.starts_with(GETH_ERR_STACK_UNDERFLOW) {
        ExecError::StackUnderflow
    } else {
        panic!("Unknown GethExecStep.error: {}", error);
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

/// State and Code Access with "keys/index" used in the access operation.
#[derive(Debug, PartialEq)]
pub enum AccessValue {
    /// Account access
    Account {
        /// Account address
        address: Address,
    },
    /// Storage access
    Storage {
        /// Storage account address
        address: Address,
        /// Storage key
        key: Word,
    },
    /// Code access
    Code {
        /// Code address
        address: Address,
    },
}

/// State Access caused by a transaction or an execution step
#[derive(Debug, PartialEq)]
pub struct Access {
    step_index: Option<usize>,
    rw: RW,
    value: AccessValue,
}

impl Access {
    fn new(step_index: Option<usize>, rw: RW, value: AccessValue) -> Self {
        Self {
            step_index,
            rw,
            value,
        }
    }
}

/// Given a trace and assuming that the first step is a *CALL*/CREATE* kind
/// opcode, return the result if found.
fn get_call_result(trace: &[GethExecStep]) -> Option<Word> {
    let depth = trace[0].depth;
    trace[1..]
        .iter()
        .find(|s| s.depth == depth)
        .map(|s| s.stack.nth_last(0).ok())
        .flatten()
}

/// State and Code Access set.
#[derive(Debug, PartialEq)]
pub struct AccessSet {
    /// Set of accounts
    pub state: HashMap<Address, HashSet<Word>>,
    /// Set of accounts code
    pub code: HashSet<Address>,
}

impl From<Vec<Access>> for AccessSet {
    fn from(list: Vec<Access>) -> Self {
        let mut state: HashMap<Address, HashSet<Word>> = HashMap::new();
        let mut code: HashSet<Address> = HashSet::new();
        for access in list {
            match access.value {
                AccessValue::Account { address } => {
                    state.entry(address).or_insert_with(HashSet::new);
                }
                AccessValue::Storage { address, key } => match state.entry(address) {
                    Entry::Vacant(entry) => {
                        let mut storage = HashSet::new();
                        storage.insert(key);
                        entry.insert(storage);
                    }
                    Entry::Occupied(mut entry) => {
                        entry.get_mut().insert(key);
                    }
                },
                AccessValue::Code { address } => {
                    state.entry(address).or_insert_with(HashSet::new);
                    code.insert(address);
                }
            }
        }
        Self { state, code }
    }
}

/// Source of the code in the EVM execution.
#[derive(Debug, Clone, Copy)]
pub enum CodeSource {
    /// Code comes from a deployed contract at `Address`.
    Address(Address),
    /// Code comes from tx.data when tx.to == null.
    Tx,
    /// Code comes from Memory by a CREATE* opcode.
    Memory,
}

impl Default for CodeSource {
    fn default() -> Self {
        Self::Tx
    }
}

/// Generate the State Access trace from the given trace.  All state read/write
/// accesses are reported, without distinguishing those that happen in revert
/// sections.
pub fn gen_state_access_trace<TX>(
    _block: &eth_types::Block<TX>,
    tx: &eth_types::Transaction,
    geth_trace: &GethExecTrace,
) -> Result<Vec<Access>, Error> {
    use AccessValue::{Account, Code, Storage};
    use RW::{READ, WRITE};

    let mut call_stack: Vec<(Address, CodeSource)> = Vec::new();
    let mut accs = vec![Access::new(None, WRITE, Account { address: tx.from })];
    if let Some(to) = tx.to {
        call_stack.push((to, CodeSource::Address(to)));
        accs.push(Access::new(None, WRITE, Account { address: to }));
        // Code may be null if the account is not a contract
        accs.push(Access::new(None, READ, Code { address: to }));
    } else {
        let address = get_contract_address(tx.from, tx.nonce);
        call_stack.push((address, CodeSource::Tx));
        accs.push(Access::new(None, WRITE, Account { address }));
        accs.push(Access::new(None, WRITE, Code { address }));
    }

    for (index, step) in geth_trace.struct_logs.iter().enumerate() {
        let next_step = geth_trace.struct_logs.get(index + 1);
        let i = Some(index);
        let (contract_address, code_source) = &call_stack[call_stack.len() - 1];
        let (contract_address, code_source) = (*contract_address, *code_source);

        let (mut push_call_stack, mut pop_call_stack) = (false, false);
        if let Some(next_step) = next_step {
            push_call_stack = step.depth + 1 == next_step.depth;
            pop_call_stack = step.depth - 1 == next_step.depth;
        }

        match step.op {
            OpcodeId::SSTORE => {
                let address = contract_address;
                let key = step.stack.nth_last(0)?;
                accs.push(Access::new(i, WRITE, Storage { address, key }));
            }
            OpcodeId::SLOAD => {
                let address = contract_address;
                let key = step.stack.nth_last(0)?;
                accs.push(Access::new(i, READ, Storage { address, key }));
            }
            OpcodeId::SELFBALANCE => {
                let address = contract_address;
                accs.push(Access::new(i, READ, Account { address }));
            }
            OpcodeId::CODESIZE => {
                if let CodeSource::Address(address) = code_source {
                    accs.push(Access::new(i, READ, Code { address }));
                }
            }
            OpcodeId::CODECOPY => {
                if let CodeSource::Address(address) = code_source {
                    accs.push(Access::new(i, READ, Code { address }));
                }
            }
            OpcodeId::BALANCE => {
                let address = step.stack.nth_last(0)?.to_address();
                accs.push(Access::new(i, READ, Account { address }));
            }
            OpcodeId::EXTCODEHASH => {
                let address = step.stack.nth_last(0)?.to_address();
                accs.push(Access::new(i, READ, Account { address }));
            }
            OpcodeId::EXTCODESIZE => {
                let address = step.stack.nth_last(0)?.to_address();
                accs.push(Access::new(i, READ, Code { address }));
            }
            OpcodeId::EXTCODECOPY => {
                let address = step.stack.nth_last(0)?.to_address();
                accs.push(Access::new(i, READ, Code { address }));
            }
            OpcodeId::SELFDESTRUCT => {
                let address = contract_address;
                accs.push(Access::new(i, WRITE, Account { address }));
                let address = step.stack.nth_last(0)?.to_address();
                accs.push(Access::new(i, WRITE, Account { address }));
            }
            OpcodeId::CREATE => {
                if push_call_stack {
                    // Find CREATE result
                    let address = get_call_result(&geth_trace.struct_logs[index..])
                        .unwrap_or_else(Word::zero)
                        .to_address();
                    if !address.is_zero() {
                        accs.push(Access::new(i, WRITE, Account { address }));
                        accs.push(Access::new(i, WRITE, Code { address }));
                    }
                    call_stack.push((address, CodeSource::Address(address)));
                }
            }
            OpcodeId::CREATE2 => {
                if push_call_stack {
                    // Find CREATE2 result
                    let address = get_call_result(&geth_trace.struct_logs[index..])
                        .unwrap_or_else(Word::zero)
                        .to_address();
                    if !address.is_zero() {
                        accs.push(Access::new(i, WRITE, Account { address }));
                        accs.push(Access::new(i, WRITE, Code { address }));
                    }
                    call_stack.push((address, CodeSource::Address(address)));
                }
            }
            OpcodeId::CALL => {
                let address = contract_address;
                accs.push(Access::new(i, WRITE, Account { address }));

                let address = step.stack.nth_last(1)?.to_address();
                accs.push(Access::new(i, WRITE, Account { address }));
                accs.push(Access::new(i, READ, Code { address }));
                if push_call_stack {
                    call_stack.push((address, CodeSource::Address(address)));
                }
            }
            OpcodeId::CALLCODE => {
                let address = contract_address;
                accs.push(Access::new(i, WRITE, Account { address }));

                let address = step.stack.nth_last(1)?.to_address();
                accs.push(Access::new(i, WRITE, Account { address }));
                accs.push(Access::new(i, READ, Code { address }));
                if push_call_stack {
                    call_stack.push((address, CodeSource::Address(address)));
                }
            }
            OpcodeId::DELEGATECALL => {
                let address = step.stack.nth_last(1)?.to_address();
                accs.push(Access::new(i, READ, Code { address }));
                if push_call_stack {
                    call_stack.push((contract_address, CodeSource::Address(address)));
                }
            }
            OpcodeId::STATICCALL => {
                let address = step.stack.nth_last(1)?.to_address();
                accs.push(Access::new(i, READ, Code { address }));
                if push_call_stack {
                    call_stack.push((address, CodeSource::Address(address)));
                }
            }
            _ => {}
        }
        if pop_call_stack {
            if call_stack.len() == 1 {
                return Err(Error::InvalidGethExecStep(
                    "gen_state_access_trace: call stack will be empty",
                    step.clone(),
                ));
            }
            call_stack.pop().expect("call stack is empty");
        }
    }
    Ok(accs)
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
        let mut block_access_trace = vec![Access {
            step_index: None,
            rw: RW::WRITE,
            value: AccessValue::Account {
                address: eth_block.author,
            },
        }];
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

#[cfg(test)]
mod tracer_tests {
    use crate::state_db::Account;

    use super::*;
    use eth_types::evm_types::{stack::Stack, Gas, OpcodeId};
    use eth_types::{address, bytecode, geth_types::GethData, word, Bytecode, ToWord, Word};
    use lazy_static::lazy_static;
    use mock::test_ctx::{helpers::*, TestContext};
    use mock::MOCK_COINBASE;
    use pretty_assertions::assert_eq;
    use std::iter::FromIterator;

    // Helper struct that contains a CircuitInputBuilder, a particuar tx and a
    // particular execution step so that we can easily get a
    // CircuitInputStateRef to have a context in order to get the error at a
    // given step.
    struct CircuitInputBuilderTx {
        builder: CircuitInputBuilder,
        tx: Transaction,
        tx_ctx: TransactionContext,
        step: ExecStep,
    }

    impl CircuitInputBuilderTx {
        fn new(geth_data: &GethData, geth_step: &GethExecStep) -> Self {
            let block = crate::mock::BlockData::new_from_geth_data(geth_data.clone());
            let mut builder = block.new_circuit_input_builder();
            let tx = builder
                .new_tx(&block.eth_block.transactions[0], true)
                .unwrap();
            let tx_ctx = TransactionContext::new(
                &block.eth_block.transactions[0],
                &GethExecTrace {
                    gas: Gas(0),
                    failed: false,
                    return_value: "".to_owned(),
                    struct_logs: vec![geth_step.clone()],
                },
                false,
            )
            .unwrap();
            Self {
                builder,
                tx,
                tx_ctx,
                step: ExecStep::new(geth_step, 0, RWCounter::new(), 0),
            }
        }

        fn state_ref(&mut self) -> CircuitInputStateRef {
            self.builder.state_ref(&mut self.tx, &mut self.tx_ctx)
        }
    }

    lazy_static! {
        static ref ADDR_A: Address = Address::zero();
        static ref WORD_ADDR_A: Word = ADDR_A.to_word();
        static ref ADDR_B: Address = address!("0x0000000000000000000000000000000000000123");
        static ref WORD_ADDR_B: Word = ADDR_B.to_word();
    }

    fn mock_internal_create() -> Call {
        Call {
            call_id: 0,
            caller_id: 0,
            kind: CallKind::Create,
            is_static: false,
            is_root: false,
            is_persistent: false,
            is_success: false,
            rw_counter_end_of_reversion: 0,
            caller_address: *ADDR_A,
            address: *ADDR_B,
            code_source: CodeSource::Memory,
            code_hash: Hash::zero(),
            depth: 2,
            value: Word::zero(),
            call_data_offset: 0,
            call_data_length: 0,
            return_data_offset: 0,
            return_data_length: 0,
        }
    }

    //
    // Geth Errors ignored
    //
    // These errors happen in a CALL, CALLCODE, DELEGATECALL or STATICCALL, and
    // are used internally but not propagated in geth to the scope where the
    // tracer is used.

    fn check_err_depth(step: &GethExecStep, next_step: Option<&GethExecStep>) -> bool {
        matches!(
            step.op,
            OpcodeId::CALL
                | OpcodeId::CALLCODE
                | OpcodeId::DELEGATECALL
                | OpcodeId::STATICCALL
                | OpcodeId::CREATE
                | OpcodeId::CREATE2
        ) && step.error.is_none()
            && result(next_step).is_zero()
            && step.depth == 1025
    }

    #[test]
    fn tracer_err_depth() {
        // Recursive CALL will exaust the call depth
        let code = bytecode! {
                 PUSH1(0x0) // retLength
                 PUSH1(0x0) // retOffset
                 PUSH1(0x0) // argsLength
                 PUSH1(0x0) // argsOffset
                 PUSH1(0x42) // value
                 PUSH32(*WORD_ADDR_A) // addr
                 PUSH32(0x8_0000_0000_0000_u64) // gas
                 CALL
                 PUSH2(0xab)
                 STOP
        };

        // Create a custom tx setting Gas to
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(*ADDR_A)
                    .balance(Word::from(1u64 << 20))
                    .code(code);
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(10u64.pow(19)));
            },
            |mut txs, accs| {
                txs[0]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .gas(Word::from(10u64.pow(15)));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let struct_logs = &block.geth_traces[0].struct_logs;

        // get last CALL
        let (index, step) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .rev()
            .find(|(_, s)| s.op == OpcodeId::CALL)
            .unwrap();
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert_eq!(step.op, OpcodeId::CALL);
        assert_eq!(step.depth, 1025u16);
        assert_eq!(step.error, None);
        // Some sanity checks
        assert_eq!(struct_logs[index + 1].op, OpcodeId::PUSH2);
        assert_eq!(struct_logs[index + 1].depth, 1025u16);
        assert_eq!(struct_logs[index + 1].stack, Stack(vec![Word::zero()])); // success = 0
        assert_eq!(struct_logs[index + 2].op, OpcodeId::STOP);
        assert_eq!(struct_logs[index + 2].depth, 1025u16);

        assert!(check_err_depth(step, next_step));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::Depth)
        );
    }

    #[test]
    fn tracer_err_insufficient_balance() {
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH32(Word::from(0x1000)) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };
        let code_b = bytecode! {
            PUSH1(0x01) // value
            PUSH1(0x02) // key
            SSTORE

            PUSH3(0xbb)
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1]
                    .address(address!("0x000000000000000000000000000000000cafe001"))
                    .code(code_b);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        // get last CALL
        let (index, step) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .rev()
            .find(|(_, s)| s.op == OpcodeId::CALL)
            .unwrap();
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert_eq!(step.error, None);
        assert_eq!(next_step.unwrap().op, OpcodeId::PUSH2);
        assert_eq!(next_step.unwrap().stack, Stack(vec![Word::zero()])); // success = 0

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        builder.builder.sdb.set_account(
            &ADDR_A,
            Account {
                nonce: Word::zero(),
                balance: Word::from(555u64), /* same value as in
                                              * `mock::new_tracer_account` */
                storage: HashMap::new(),
                code_hash: Hash::zero(),
            },
        );
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::InsufficientBalance)
        );
    }

    #[test]
    fn tracer_err_address_collision() {
        // We do CREATE2 twice with the same parameters, with a code_creater
        // that outputs the same, which will lead to the same new
        // contract address.
        let code_creator = bytecode! {
            PUSH1(0x00) // value
            PUSH1(0x00) // offset
            MSTORE
            PUSH1(0x01) // length
            PUSH1(0x00) // offset
            RETURN
        };

        // code_a calls code_b which executes code_creator in CREATE2
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };

        let mut code_b = Bytecode::default();
        // pad code_creator to multiple of 32 bytes
        let len = code_creator.code().len();
        let code_creator: Vec<u8> = code_creator
            .code()
            .iter()
            .cloned()
            .chain(0u8..((32 - len % 32) as u8))
            .collect();
        for (index, word) in code_creator.chunks(32).enumerate() {
            code_b.push(32, Word::from_big_endian(word));
            code_b.push(32, Word::from(index * 32));
            code_b.write_op(OpcodeId::MSTORE);
        }
        let code_b_end = bytecode! {
            PUSH3(0x123456) // salt
            PUSH1(len) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // value
            CREATE2

            PUSH3(0x123456) // salt
            PUSH1(len) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // value
            CREATE2

            PUSH3(0xbb)
        };
        code_b.append(&code_b_end);
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code_b);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        // get last CREATE2
        let (index, step) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .rev()
            .find(|(_, s)| s.op == OpcodeId::CREATE2)
            .unwrap();
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);

        let create2_address: Address = {
            // get first RETURN
            let (index, _) = block.geth_traces[0]
                .struct_logs
                .iter()
                .enumerate()
                .find(|(_, s)| s.op == OpcodeId::RETURN)
                .unwrap();
            let next_step = block.geth_traces[0].struct_logs.get(index + 1);
            let addr_word = next_step.unwrap().stack.last().unwrap();
            addr_word.to_address()
        };

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        // Set up call context at CREATE2
        builder.tx_ctx.call_is_success.push(false);
        builder.state_ref().push_call(mock_internal_create(), step);
        // Set up account and contract that exist during the second CREATE2
        builder.builder.sdb.set_account(
            &ADDR_B,
            Account {
                nonce: Word::zero(),
                balance: Word::from(555u64), /* same value as in
                                              * `mock::new_tracer_account` */
                storage: HashMap::new(),
                code_hash: Hash::zero(),
            },
        );
        builder.builder.sdb.set_account(
            &create2_address,
            Account {
                nonce: Word::zero(),
                balance: Word::zero(),
                storage: HashMap::new(),
                code_hash: Hash::zero(),
            },
        );
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::ContractAddressCollision)
        );
    }

    fn check_err_code_store_out_of_gas(
        step: &GethExecStep,
        next_step: Option<&GethExecStep>,
    ) -> bool {
        let length = step.stack.nth_last(1).unwrap();
        step.op == OpcodeId::RETURN
            && step.error.is_none()
            && result(next_step).is_zero()
            && Word::from(200) * length > Word::from(step.gas.0)
    }

    #[test]
    fn tracer_err_code_store_out_of_gas() {
        // code_creator outputs an empty array of length 0x100, which will
        // exhaust the gas to store the code.
        let code_len = 0x100;
        let code_creator = bytecode! {
            PUSH1(Word::zero()) // value
            PUSH32(code_len) // offset
            MSTORE
            PUSH32(code_len) // length
            PUSH1(0x00) // offset
            RETURN
        };

        // code_a calls code_b which executes code_creator in CREATE
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };

        let mut code_b = Bytecode::default();
        // pad code_creator to multiple of 32 bytes
        let len = code_creator.code().len();
        let code_creator: Vec<u8> = code_creator
            .code()
            .iter()
            .cloned()
            .chain(0..(32 - len % 32) as u8)
            .collect();
        for (index, word) in code_creator.chunks(32).enumerate() {
            code_b.push(32, Word::from_big_endian(word));
            code_b.push(32, Word::from(index * 32));
            code_b.write_op(OpcodeId::MSTORE);
        }
        let code_b_end = bytecode! {
            PUSH32(len) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // value
            CREATE

            PUSH3(0xbb)
        };
        code_b.append(&code_b_end);
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code_b);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        // get last RETURN
        let (index, step) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .rev()
            .find(|(_, s)| s.op == OpcodeId::RETURN)
            .unwrap();
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert!(check_err_code_store_out_of_gas(step, next_step));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        // Set up call context at CREATE
        builder.tx_ctx.call_is_success.push(false);
        builder.state_ref().push_call(mock_internal_create(), step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::CodeStoreOutOfGas)
        );
    }

    fn check_err_invalid_code(step: &GethExecStep, next_step: Option<&GethExecStep>) -> bool {
        let offset = step.stack.nth_last(0).unwrap();
        let length = step.stack.nth_last(1).unwrap();
        step.op == OpcodeId::RETURN
            && step.error.is_none()
            && result(next_step).is_zero()
            && length > Word::zero()
            && !step.memory.0.is_empty()
            && step.memory.0.get(offset.low_u64() as usize) == Some(&0xef)
    }

    #[test]
    fn tracer_err_invalid_code() {
        // code_creator outputs byte array that starts with 0xef, which is
        // invalid code.
        let code_creator = bytecode! {
            PUSH32(word!("0xef00000000000000000000000000000000000000000000000000000000000000")) // value
            PUSH1(0x00) // offset
            MSTORE
            PUSH1(0x01) // length
            PUSH1(0x00) // offset
            RETURN
        };

        // code_a calls code_b which executes code_creator in CREATE
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };

        let mut code_b = Bytecode::default();
        // pad code_creator to multiple of 32 bytes
        let len = code_creator.code().len();
        let code_creator: Vec<u8> = code_creator
            .code()
            .iter()
            .cloned()
            .chain(0u8..((32 - len % 32) as u8))
            .collect();
        for (index, word) in code_creator.chunks(32).enumerate() {
            code_b.push(32, Word::from_big_endian(word));
            code_b.push(32, Word::from(index * 32));
            code_b.write_op(OpcodeId::MSTORE);
        }
        let code_b_end = bytecode! {
            PUSH1(len) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // value
            CREATE

            PUSH3(0xbb)
        };
        code_b.append(&code_b_end);
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code_b);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        // get last RETURN
        let (index, step) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .rev()
            .find(|(_, s)| s.op == OpcodeId::RETURN)
            .unwrap();
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert!(check_err_invalid_code(step, next_step));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        // Set up call context at RETURN
        builder.tx_ctx.call_is_success.push(false);
        builder.state_ref().push_call(mock_internal_create(), step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::InvalidCreationCode)
        );
    }

    fn check_err_max_code_size_exceeded(
        step: &GethExecStep,
        next_step: Option<&GethExecStep>,
    ) -> bool {
        let length = step.stack.nth_last(1).unwrap();
        step.op == OpcodeId::RETURN
            && step.error.is_none()
            && result(next_step).is_zero()
            && length > Word::from(0x6000)
    }

    #[test]
    fn tracer_err_max_code_size_exceeded() {
        // code_creator outputs an empty array of length 0x6000 + 1, which will
        // trigger the max code size limit.
        let code_len = 0x6000 + 1;
        let code_creator = bytecode! {
            PUSH1(Word::zero()) // value
            PUSH32(code_len) // offset
            MSTORE
            PUSH32(code_len) // length
            PUSH1(0x00) // offset
            RETURN
        };

        // code_a calls code_b which executes code_creator in CREATE
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x10_0000) // gas
            CALL

            PUSH2(0xaa)
        };

        let mut code_b = Bytecode::default();
        // pad code_creator to multiple of 32 bytes
        let len = code_creator.code().len();
        let code_creator: Vec<u8> = code_creator
            .code()
            .iter()
            .cloned()
            .chain(0u8..((32 - len % 32) as u8))
            .collect();
        for (index, word) in code_creator.chunks(32).enumerate() {
            code_b.push(32, Word::from_big_endian(word));
            code_b.push(32, Word::from(index * 32));
            code_b.write_op(OpcodeId::MSTORE);
        }
        let code_b_end = bytecode! {
            PUSH32(len) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // value
            CREATE

            PUSH3(0xbb)
        };
        code_b.append(&code_b_end);
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code_b);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        // get last RETURN
        let (index, step) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .rev()
            .find(|(_, s)| s.op == OpcodeId::RETURN)
            .unwrap();
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert!(check_err_max_code_size_exceeded(step, next_step));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        // Set up call context at RETURN
        builder.tx_ctx.call_is_success.push(false);
        builder.state_ref().push_call(mock_internal_create(), step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::MaxCodeSizeExceeded)
        );
    }

    #[test]
    fn tracer_create_stop() {
        // code_creator doesn't output anything because it stops.
        let code_creator = bytecode! {
            PUSH32(word!("0xef00000000000000000000000000000000000000000000000000000000000000")) // value
            PUSH1(0x00) // offset
            MSTORE
            PUSH1(0x01) // length
            PUSH1(0x00) // offset
            STOP
        };

        // code_a calls code_b which executes code_creator in CREATE
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };

        let mut code_b = Bytecode::default();
        // pad code_creator to multiple of 32 bytes
        let len = code_creator.code().len();
        let code_creator: Vec<u8> = code_creator
            .code()
            .iter()
            .cloned()
            .chain(0u8..((32 - len % 32) as u8))
            .collect();
        for (index, word) in code_creator.chunks(32).enumerate() {
            code_b.push(32, Word::from_big_endian(word));
            code_b.push(32, Word::from(index * 32));
            code_b.write_op(OpcodeId::MSTORE);
        }
        let code_b_end = bytecode! {
            PUSH1(len) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // value
            CREATE

            PUSH3(0xbb)
        };
        code_b.append(&code_b_end);
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1]
                    .address(address!("0x000000000000000000000000000000000cafe001"))
                    .code(code_b);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        // get first STOP
        let (index, step) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .find(|(_, s)| s.op == OpcodeId::STOP)
            .unwrap();
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        // Set up call context at STOP
        builder.tx_ctx.call_is_success.push(false);
        builder.state_ref().push_call(mock_internal_create(), step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            None
        );
    }

    //
    // Geth Errors not reported
    //
    // These errors are specific to some opcodes and due to the way the tracing
    // works, they are never captured, because the trace is made before the
    // step is executed, so when these errors happen, the trace step
    // contains error = null.

    fn result(step: Option<&GethExecStep>) -> Word {
        step.map(|s| s.stack.last().unwrap_or_else(|_| Word::zero()))
            .unwrap_or_else(Word::zero)
    }

    fn check_err_invalid_jump(step: &GethExecStep, next_step: Option<&GethExecStep>) -> bool {
        let next_depth = next_step.map(|s| s.depth).unwrap_or(0);
        matches!(step.op, OpcodeId::JUMP | OpcodeId::JUMPI)
            && step.error.is_none()
            && result(next_step).is_zero()
            && step.depth != next_depth
    }

    #[test]
    fn tracer_err_invalid_jump() {
        // jump to 0x10 which is outside the code (and also not marked with
        // JUMPDEST)
        let code = bytecode! {
            PUSH1(0x10)
            JUMP
            STOP
        };
        let index = 1; // JUMP
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20))
                    .code(code.clone());
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[1].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        assert_eq!(block.geth_traces[0].struct_logs.len(), 2);
        let step = &block.geth_traces[0].struct_logs[index];
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert!(check_err_invalid_jump(step, next_step));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::InvalidJump)
        );

        // With CALL

        // code_a calls code
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            STATICCALL

            PUSH2(0xaa)
        };
        let index = 8; // JUMP

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let step = &block.geth_traces[0].struct_logs[index];
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert!(check_err_invalid_jump(step, next_step));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::InvalidJump)
        );
    }

    fn check_err_execution_reverted(step: &GethExecStep, next_step: Option<&GethExecStep>) -> bool {
        let next_depth = next_step.map(|s| s.depth).unwrap_or(0);
        step.op == OpcodeId::REVERT
            && step.error.is_none()
            && result(next_step).is_zero()
            && step.depth != next_depth
    }

    #[test]
    fn tracer_err_execution_reverted() {
        // Do a REVERT
        let code = bytecode! {
            PUSH1(0x0)
            PUSH2(0x0)
            REVERT
            PUSH3(0x12)
            STOP
        };
        let index = 2; // REVERT
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20))
                    .code(code.clone());
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[1].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        assert_eq!(block.geth_traces[0].struct_logs.len(), 3);
        let step = &block.geth_traces[0].struct_logs[index];
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert!(check_err_execution_reverted(step, next_step));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            None
        );

        // With CALL

        // code_a calls code
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };
        let index = 10; // REVERT

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let step = &block.geth_traces[0].struct_logs[index];
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert!(check_err_execution_reverted(step, next_step));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            None
        );
    }

    #[test]
    fn tracer_stop() {
        // Do a STOP
        let code = bytecode! {
            PUSH1(0x0)
            PUSH2(0x0)
            STOP
            PUSH3(0x12)
            STOP
        };

        // code_a calls code
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };
        let index = 10; // STOP

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let step = &block.geth_traces[0].struct_logs[index];
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            None
        );
    }

    fn check_err_return_data_out_of_bounds(
        step: &GethExecStep,
        next_step: Option<&GethExecStep>,
    ) -> bool {
        let next_depth = next_step.map(|s| s.depth).unwrap_or(0);
        step.op == OpcodeId::RETURNDATACOPY
            && step.error.is_none()
            && result(next_step).is_zero()
            && step.depth != next_depth
    }

    #[test]
    fn tracer_err_return_data_out_of_bounds() {
        // code_a calls code_b and gets the return data with a length 0x02 but
        // code_b returns data with length 0x01.
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH1(0x02) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // destOffset
            RETURNDATACOPY

            PUSH2(0xaa)
        };
        let code_b = bytecode! {
            PUSH2(0x42) // value
            PUSH2(0x00) // offset
            MSTORE
            PUSH1(0x01) // length
            PUSH1(0x00) // offset
            RETURN
        };
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1]
                    .address(address!("0x000000000000000000000000000000000cafe001"))
                    .code(code_b);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        // get last RETURNDATACOPY
        let (index, step) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .rev()
            .find(|(_, s)| s.op == OpcodeId::RETURNDATACOPY)
            .unwrap();
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert!(check_err_return_data_out_of_bounds(step, next_step));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::ReturnDataOutOfBounds)
        );
    }

    //
    // Geth Errors Reported
    //
    // These errors can be found in the trace step error field.

    #[test]
    fn tracer_err_gas_uint_overflow() {
        // MSTORE a value at an offset so high that the gast cost is big enough
        // to overflow an uint64
        let code = bytecode! {
            PUSH32(0x42) // value
            PUSH32(0x100_0000_0000_0000_0000_u128) // offset
            MSTORE
        };
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20))
                    .code(code);
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[1].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let index = 2; // MSTORE
        let step = &block.geth_traces[0].struct_logs[index];
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert_eq!(step.op, OpcodeId::MSTORE);
        assert_eq!(step.error, Some(GETH_ERR_GAS_UINT_OVERFLOW.to_string()));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::OutOfGas(OogError::StaticMemoryExpansion))
        );
    }

    #[test]
    fn tracer_err_invalid_opcode() {
        // The second opcode is invalid (0x0f)
        let mut code = bytecode::Bytecode::default();
        code.write_op(OpcodeId::PC);
        code.write(0x0f);
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20))
                    .code(code);
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[1].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let index = block.geth_traces[0].struct_logs.len() - 1; // 0x0f
        let step = &block.geth_traces[0].struct_logs[index];
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert_eq!(step.op, OpcodeId::INVALID(0x0f));

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::InvalidOpcode)
        );
    }

    #[test]
    fn tracer_err_write_protection() {
        // code_a calls code_b via static call, which tries to SSTORE and fails.
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            STATICCALL

            PUSH2(0xaa)
        };
        let code_b = bytecode! {
            PUSH1(0x01) // value
            PUSH1(0x02) // key
            SSTORE

            PUSH3(0xbb)
        };
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code_b);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let index = 9; // SSTORE
        let step = &block.geth_traces[0].struct_logs[index];
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert_eq!(step.op, OpcodeId::SSTORE);

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        builder.tx_ctx.call_is_success.push(false);
        builder.state_ref().push_call(
            Call {
                call_id: 0,
                caller_id: 0,
                kind: CallKind::StaticCall,
                is_static: true,
                is_root: false,
                is_persistent: false,
                is_success: false,
                rw_counter_end_of_reversion: 0,
                caller_address: *ADDR_A,
                address: *ADDR_B,
                code_source: CodeSource::Address(*ADDR_B),
                code_hash: Hash::zero(),
                depth: 2,
                value: Word::zero(),
                call_data_offset: 0,
                call_data_length: 0,
                return_data_offset: 0,
                return_data_length: 0,
            },
            step,
        );

        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::WriteProtection)
        );
    }

    #[test]
    fn tracer_err_out_of_gas() {
        // Do 3 PUSH1 with gas = 4, which causes out of gas
        let code = bytecode! {
            PUSH1(0x0)
            PUSH1(0x1)
            PUSH1(0x2)
        };
        // Create a custom tx setting Gas to
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, accs| {
                txs[0]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .gas(Word::from(21004u64));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        let struct_logs = &block.geth_traces[0].struct_logs;

        assert_eq!(struct_logs[1].error, Some(GETH_ERR_OUT_OF_GAS.to_string()));
    }

    #[test]
    fn tracer_err_stack_overflow() {
        // PUSH2 1025 times, causing a stack overflow
        let mut code = bytecode::Bytecode::default();
        for i in 0..1025 {
            code.push(2, Word::from(i));
        }
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let index = block.geth_traces[0].struct_logs.len() - 1; // PUSH2
        let step = &block.geth_traces[0].struct_logs[index];
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert_eq!(
            step.error,
            Some(format!("{} 1024 (1023)", GETH_ERR_STACK_OVERFLOW))
        );

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::StackOverflow)
        );
    }

    #[test]
    fn tracer_err_stack_underflow() {
        // SWAP5 with an empty stack, which causes a stack underflow
        let code = bytecode! {
            SWAP5
        };
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let index = 0; // SWAP5
        let step = &block.geth_traces[0].struct_logs[index];
        let next_step = block.geth_traces[0].struct_logs.get(index + 1);
        assert_eq!(
            step.error,
            Some(format!("{} (0 <=> 6)", GETH_ERR_STACK_UNDERFLOW))
        );

        let mut builder = CircuitInputBuilderTx::new(&block, step);
        assert_eq!(
            builder.state_ref().get_step_err(step, next_step).unwrap(),
            Some(ExecError::StackUnderflow)
        );
    }

    //
    // Circuit Input Builder tests
    //

    #[test]
    fn create2_address() {
        // code_creator outputs 0x6050.
        let code_creator = bytecode! {
            PUSH32(word!("0x6050000000000000000000000000000000000000000000000000000000000000")) // value
            PUSH1(0x00) // offset
            MSTORE
            PUSH1(0x02) // length
            PUSH1(0x00) // offset
            RETURN
        };

        // code_a calls code_b which executes code_creator in CREATE
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };

        let mut code_b = Bytecode::default();
        // pad code_creator to multiple of 32 bytes
        let len = code_creator.code().len();
        let code_creator: Vec<u8> = code_creator
            .code()
            .iter()
            .cloned()
            .chain(0u8..((32 - len % 32) as u8))
            .collect();
        for (index, word) in code_creator.chunks(32).enumerate() {
            code_b.push(32, Word::from_big_endian(word));
            code_b.push(32, Word::from(index * 32));
            code_b.write_op(OpcodeId::MSTORE);
        }
        let code_b_end = bytecode! {
            PUSH3(0x123456) // salt
            PUSH1(len) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // value
            CREATE2

            PUSH3(0xbb)
        };
        code_b.append(&code_b_end);
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code_b);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        // get RETURN
        let (index_return, _) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .find(|(_, s)| s.op == OpcodeId::RETURN)
            .unwrap();
        let next_step_return = block.geth_traces[0].struct_logs.get(index_return + 1);
        let addr_expect = next_step_return.unwrap().stack.last().unwrap();

        // get CREATE2
        let step_create2 = block.geth_traces[0]
            .struct_logs
            .iter()
            .find(|s| s.op == OpcodeId::CREATE2)
            .unwrap();
        let mut builder = CircuitInputBuilderTx::new(&block, step_create2);
        // Set up call context at CREATE2
        builder.tx_ctx.call_is_success.push(false);
        builder
            .state_ref()
            .push_call(mock_internal_create(), step_create2);
        let addr = builder.state_ref().create2_address(step_create2).unwrap();

        assert_eq!(addr.to_word(), addr_expect);
    }

    #[test]
    fn create_address() {
        // code_creator outputs 0x6050.
        let code_creator = bytecode! {
            PUSH32(word!("0x6050000000000000000000000000000000000000000000000000000000000000")) // value
            PUSH1(0x00) // offset
            MSTORE
            PUSH1(0x02) // length
            PUSH1(0x00) // offset
            RETURN
        };

        // code_a calls code_b which executes code_creator in CREATE
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };

        let mut code_b = Bytecode::default();
        // pad code_creator to multiple of 32 bytes
        let len = code_creator.code().len();
        let code_creator: Vec<u8> = code_creator
            .code()
            .iter()
            .cloned()
            .chain(0u8..((32 - len % 32) as u8))
            .collect();
        for (index, word) in code_creator.chunks(32).enumerate() {
            code_b.push(32, Word::from_big_endian(word));
            code_b.push(32, Word::from(index * 32));
            code_b.write_op(OpcodeId::MSTORE);
        }
        // We do CREATE 2 times to use a nonce != 0 in the second one.
        let code_b_end = bytecode! {
            PUSH1(len) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // value
            CREATE

            PUSH1(len) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // value
            CREATE

            PUSH3(0xbb)
        };
        code_b.append(&code_b_end);
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code_b);
                accs[2]
                    .address(address!("0x000000000000000000000000000000000cafe002"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        // get last RETURN
        let (index_return, _) = block.geth_traces[0]
            .struct_logs
            .iter()
            .enumerate()
            .rev()
            .find(|(_, s)| s.op == OpcodeId::RETURN)
            .unwrap();
        let next_step_return = block.geth_traces[0].struct_logs.get(index_return + 1);
        let addr_expect = next_step_return.unwrap().stack.last().unwrap();

        // get last CREATE
        let step_create = block.geth_traces[0]
            .struct_logs
            .iter()
            .rev()
            .find(|s| s.op == OpcodeId::CREATE)
            .unwrap();
        let mut builder = CircuitInputBuilderTx::new(&block, step_create);
        // Set up call context at CREATE
        builder.tx_ctx.call_is_success.push(false);
        builder
            .state_ref()
            .push_call(mock_internal_create(), step_create);
        builder.builder.sdb.set_account(
            &ADDR_B,
            Account {
                nonce: Word::from(1),
                balance: Word::zero(),
                storage: HashMap::new(),
                code_hash: Hash::zero(),
            },
        );
        let addr = builder.state_ref().create_address().unwrap();

        assert_eq!(addr.to_word(), addr_expect);
    }

    #[test]
    fn test_gen_access_trace() {
        use AccessValue::{Account, Code, Storage};
        use RW::{READ, WRITE};
        let ADDR_0 = address!("0x00000000000000000000000000000000c014ba5e");

        // code_a calls code_b via static call, which tries to SSTORE and fails.
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };
        let code_b = bytecode! {
            PUSH32(word!("0x1234567890000000000000000000abcdef000000000000000000112233445566")) // value
            PUSH1(0x01) // offset
            MSTORE
            PUSH1(0x01) // value
            PUSH1(0x02) // key
            SSTORE
            PUSH1(0x03) // key
            SLOAD

            PUSH3(0xbb)
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .code(code_a);
                accs[1].address(*ADDR_B).code(code_b);
                accs[2].address(ADDR_0).balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let access_trace = gen_state_access_trace(
            &block.eth_block,
            &block.eth_block.transactions[0],
            &block.geth_traces[0],
        )
        .unwrap();

        assert_eq!(
            access_trace,
            vec![
                Access {
                    step_index: None,
                    rw: WRITE,
                    value: Account { address: ADDR_0 }
                },
                Access {
                    step_index: None,
                    rw: WRITE,
                    value: Account { address: *ADDR_A }
                },
                Access {
                    step_index: None,
                    rw: READ,
                    value: Code { address: *ADDR_A }
                },
                Access {
                    step_index: Some(7),
                    rw: WRITE,
                    value: Account { address: *ADDR_A }
                },
                Access {
                    step_index: Some(7),
                    rw: WRITE,
                    value: Account { address: *ADDR_B }
                },
                Access {
                    step_index: Some(7),
                    rw: READ,
                    value: Code { address: *ADDR_B }
                },
                Access {
                    step_index: Some(13),
                    rw: WRITE,
                    value: Storage {
                        address: *ADDR_B,
                        key: Word::from(2),
                    }
                },
                Access {
                    step_index: Some(15),
                    rw: READ,
                    value: Storage {
                        address: *ADDR_B,
                        key: Word::from(3),
                    }
                },
            ]
        );

        let access_set = AccessSet::from(access_trace);
        assert_eq!(
            access_set,
            AccessSet {
                state: HashMap::from_iter([
                    (ADDR_0, HashSet::new()),
                    (*ADDR_A, HashSet::new()),
                    (*ADDR_B, HashSet::from_iter([Word::from(2), Word::from(3)]))
                ]),
                code: HashSet::from_iter([*ADDR_A, *ADDR_B]),
            }
        )
    }

    #[test]
    fn test_gen_access_trace_call_EOA_no_new_stack_frame() {
        use AccessValue::{Account, Code, Storage};
        use RW::{READ, WRITE};

        // code calls an EOA with not code, so it won't push new stack frame.
        let code = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL
            PUSH1(0x01) // value
            PUSH1(0x02) // key
            SSTORE
            PUSH1(0x03) // key
            SLOAD

            PUSH2(0xaa)
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0].address(*MOCK_COINBASE).code(code);
                accs[1].address(*ADDR_B).balance(Word::from(1u64 << 30));
            },
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let access_trace = gen_state_access_trace(
            &block.eth_block,
            &block.eth_block.transactions[0],
            &block.geth_traces[0],
        )
        .unwrap();

        assert_eq!(
            access_trace,
            vec![
                Access {
                    step_index: None,
                    rw: WRITE,
                    value: Account { address: *ADDR_B }
                },
                Access {
                    step_index: None,
                    rw: WRITE,
                    value: Account {
                        address: *MOCK_COINBASE
                    }
                },
                Access {
                    step_index: None,
                    rw: READ,
                    value: Code {
                        address: *MOCK_COINBASE
                    }
                },
                Access {
                    step_index: Some(7),
                    rw: WRITE,
                    value: Account {
                        address: *MOCK_COINBASE
                    }
                },
                Access {
                    step_index: Some(7),
                    rw: WRITE,
                    value: Account { address: *ADDR_B }
                },
                Access {
                    step_index: Some(7),
                    rw: READ,
                    value: Code { address: *ADDR_B }
                },
                Access {
                    step_index: Some(10),
                    rw: WRITE,
                    value: Storage {
                        address: *MOCK_COINBASE,
                        key: Word::from(2u64),
                    }
                },
                Access {
                    step_index: Some(12),
                    rw: READ,
                    value: Storage {
                        address: *MOCK_COINBASE,
                        key: Word::from(3u64),
                    }
                },
            ]
        );

        let access_set = AccessSet::from(access_trace);
        assert_eq!(
            access_set,
            AccessSet {
                state: HashMap::from_iter([
                    (
                        *MOCK_COINBASE,
                        HashSet::from_iter([Word::from(2u64), Word::from(3u64)])
                    ),
                    (*ADDR_B, HashSet::new()),
                ]),
                code: HashSet::from_iter([*ADDR_B, *MOCK_COINBASE]),
            }
        );
    }

    #[test]
    fn test_gen_access_trace_create_push_call_stack() {
        use AccessValue::{Account, Code};
        use RW::{READ, WRITE};

        // revert
        let code_creator = bytecode! {
            PUSH1(0x00) // length
            PUSH1(0x00) // offset
            REVERT
        };

        // code_a calls code_b which executes code_creator in CREATE
        let code_a = bytecode! {
            PUSH1(0x0) // retLength
            PUSH1(0x0) // retOffset
            PUSH1(0x0) // argsLength
            PUSH1(0x0) // argsOffset
            PUSH1(0x0) // value
            PUSH32(*WORD_ADDR_B) // addr
            PUSH32(0x1_0000) // gas
            CALL

            PUSH2(0xaa)
        };

        let mut code_b = Bytecode::default();
        // pad code_creator to multiple of 32 bytes
        let len = code_creator.code().len();
        let code_creator: Vec<u8> = code_creator
            .code()
            .iter()
            .cloned()
            .chain(0u8..((32 - len % 32) as u8))
            .collect();
        for (index, word) in code_creator.chunks(32).enumerate() {
            code_b.push(32, Word::from_big_endian(word));
            code_b.push(32, Word::from(index * 32));
            code_b.write_op(OpcodeId::MSTORE);
        }
        let code_b_end = bytecode! {
            PUSH1(len) // length
            PUSH1(0x00) // offset
            PUSH1(0x00) // value
            CREATE

            PUSH3(0xbb)
        };
        code_b.append(&code_b_end);

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 2>::new(
            None,
            |accs| {
                accs[0].address(*MOCK_COINBASE).code(code_a);
                accs[1].address(*ADDR_B).code(code_b);
                accs[2].balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
                txs[1]
                    .to(accs[1].address)
                    .from(accs[2].address)
                    .nonce(Word::one());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let access_trace = gen_state_access_trace(
            &block.eth_block,
            &block.eth_block.transactions[0],
            &block.geth_traces[0],
        )
        .unwrap();

        assert_eq!(
            access_trace,
            vec![
                Access {
                    step_index: None,
                    rw: WRITE,
                    value: Account {
                        address: Address::zero()
                    }
                },
                Access {
                    step_index: None,
                    rw: WRITE,
                    value: Account {
                        address: *MOCK_COINBASE
                    }
                },
                Access {
                    step_index: None,
                    rw: READ,
                    value: Code {
                        address: *MOCK_COINBASE
                    }
                },
                Access {
                    step_index: Some(7),
                    rw: WRITE,
                    value: Account {
                        address: *MOCK_COINBASE
                    }
                },
                Access {
                    step_index: Some(7),
                    rw: WRITE,
                    value: Account { address: *ADDR_B }
                },
                Access {
                    step_index: Some(7),
                    rw: READ,
                    value: Code { address: *ADDR_B }
                },
            ]
        );

        let access_set = AccessSet::from(access_trace);
        assert_eq!(
            access_set,
            AccessSet {
                state: HashMap::from_iter([
                    (*MOCK_COINBASE, HashSet::new()),
                    (*ADDR_A, HashSet::new()),
                    (*ADDR_B, HashSet::new()),
                ]),
                code: HashSet::from_iter([*MOCK_COINBASE, *ADDR_B]),
            }
        )
    }
}
