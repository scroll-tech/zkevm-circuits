//! CircuitInput builder tooling module.

use super::{
    get_call_memory_offset_length, get_create_init_code, Block, BlockContext, Call, CallContext,
    CallKind, CodeSource, ExecState, ExecStep, Transaction, TransactionContext,
};
use crate::{
    error::{get_step_reported_error, ExecError},
    exec_trace::OperationRef,
    operation::{
        AccountField, CallContextField, CallContextOp, MemoryOp, Op, OpEnum, Operation, StackOp,
        Target, RW,
    },
    state_db::{CodeDB, StateDB},
    Error,
};
use eth_types::{
    evm_types::{Gas, MemoryAddress, OpcodeId, StackAddress},
    Address, GethExecStep, ToAddress, ToBigEndian, Word, H256,
};
use ethers_core::utils::{get_contract_address, get_create2_address};
use itertools::Itertools;

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

    /// Push an [`Operation`](crate::operation::Operation) into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and then adds a
    /// reference to the stored operation ([`OperationRef`]) inside the
    /// bus-mapping instance of the current [`ExecStep`].  Then increase the
    /// block_ctx [`RWCounter`](crate::operation::RWCounter) by one.
    pub fn push_op<T: Op>(&mut self, step: &mut ExecStep, rw: RW, op: T) {
        let op_ref =
            self.block
                .container
                .insert(Operation::new(self.block_ctx.rwc.inc_pre(), rw, op));
        step.bus_mapping_instance.push(op_ref);
    }

    /// Push a read type [`CallContextOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with
    /// the next [`RWCounter`](crate::operation::RWCounter)  and then adds a
    /// reference to the stored operation ([`OperationRef`]) inside the
    /// bus-mapping instance of the current [`ExecStep`].  Then increase the
    /// block_ctx [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn call_context_read(
        &mut self,
        step: &mut ExecStep,
        call_id: usize,
        field: CallContextField,
        value: Word,
    ) {
        let op = CallContextOp {
            call_id,
            field,
            value,
        };

        self.push_op(step, RW::READ, op);
    }

    /// Push an [`Operation`](crate::operation::Operation) with reversible to be
    /// true into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and then adds a
    /// reference to the stored operation
    /// ([`OperationRef`]) inside the
    /// bus-mapping instance of the current [`ExecStep`]. Then increase the
    /// block_ctx [`RWCounter`](crate::operation::RWCounter) by one.
    /// This method should be used in `Opcode::gen_associated_ops` instead of
    /// `push_op` when the operation is `RW::WRITE` and it can be reverted (for
    /// example, a write [`StorageOp`](crate::operation::StorageOp)).
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
                .push((self.tx.steps().len(), op_ref));
        }

        Ok(())
    }

    /// Push a [`MemoryOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and `call_id`, and
    /// then adds a reference to the stored operation ([`OperationRef`])
    /// inside the bus-mapping instance of the current [`ExecStep`].  Then
    /// increase the `block_ctx` [`RWCounter`](crate::operation::RWCounter) by
    /// one.
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

    /// Push a read type [`MemoryOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and `call_id`, and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter) by one.
    pub fn memory_read(
        &mut self,
        step: &mut ExecStep,
        address: MemoryAddress,
        value: u8,
    ) -> Result<(), Error> {
        let call_id = self.call()?.call_id;
        self.push_op(step, RW::READ, MemoryOp::new(call_id, address, value));
        Ok(())
    }

    /// Push a write type [`MemoryOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and `call_id`, and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn memory_write(
        &mut self,
        step: &mut ExecStep,
        address: MemoryAddress,
        value: u8,
    ) -> Result<(), Error> {
        let call_id = self.call()?.call_id;
        self.push_op(step, RW::WRITE, MemoryOp::new(call_id, address, value));
        Ok(())
    }

    /// Push a [`StackOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and `call_id`, and
    /// then adds a reference to the stored operation ([`OperationRef`])
    /// inside the bus-mapping instance of the current [`ExecStep`].  Then
    /// increase the `block_ctx` [`RWCounter`](crate::operation::RWCounter)
    /// by one.
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

    /// Push a write type [`StackOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter)  and `call_id`, and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter) by one.
    pub fn stack_write(
        &mut self,
        step: &mut ExecStep,
        address: StackAddress,
        value: Word,
    ) -> Result<(), Error> {
        let call_id = self.call()?.call_id;
        self.push_op(step, RW::WRITE, StackOp::new(call_id, address, value));
        Ok(())
    }

    /// Push a read type [`StackOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter)  and `call_id`, and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn stack_read(
        &mut self,
        step: &mut ExecStep,
        address: StackAddress,
        value: Word,
    ) -> Result<(), Error> {
        let call_id = self.call()?.call_id;
        self.push_op(step, RW::READ, StackOp::new(call_id, address, value));
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

    /// Reference to the caller's Call
    pub fn caller(&self) -> Result<&Call, Error> {
        self.tx_ctx
            .caller_index()
            .map(|caller_idx| &self.tx.calls()[caller_idx])
    }

    /// Reference to the current Call
    pub fn call(&self) -> Result<&Call, Error> {
        self.tx_ctx
            .call_index()
            .map(|call_idx| &self.tx.calls()[call_idx])
    }

    /// Mutable reference to the current Call
    pub fn call_mut(&mut self) -> Result<&mut Call, Error> {
        self.tx_ctx
            .call_index()
            .map(|call_idx| &mut self.tx.calls_mut()[call_idx])
    }

    /// Reference to the current CallContext
    pub fn call_ctx(&self) -> Result<&CallContext, Error> {
        self.tx_ctx.call_ctx()
    }

    /// Reference to the current CallContext
    pub fn caller_ctx(&self) -> Result<&CallContext, Error> {
        self.tx_ctx.caller_ctx()
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
        let call_idx = self.tx.calls().len();

        self.tx_ctx.push_call_ctx(call_idx, call_data);
        self.tx.push_call(call);

        self.block_ctx
            .call_map
            .insert(call_id, (self.block.txs.len(), call_idx));
    }

    /// Return the contract address of a CREATE step.  This is calculated by
    /// inspecting the current address and its nonce from the StateDB.
    pub(crate) fn create_address(&self) -> Result<Address, Error> {
        let sender = self.call()?.address;
        let (found, account) = self.sdb.get_account(&sender);
        if !found {
            return Err(Error::AccountNotFound(sender));
        }
        Ok(get_contract_address(sender, account.nonce))
    }

    /// Return the contract address of a CREATE2 step.  This is calculated
    /// deterministically from the arguments in the stack.
    pub(crate) fn create2_address(&self, step: &GethExecStep) -> Result<Address, Error> {
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

    // TODO: Remove unwrap() and add err handling.
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
            CallKind::DelegateCall => (caller.caller_address, caller.address, Word::zero()),
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
                if !op.is_warm_prev && op.is_warm {
                    self.sdb.add_account_to_access_list(op.address);
                }
                if op.is_warm_prev && !op.is_warm {
                    self.sdb.remove_account_from_access_list(&op.address);
                }
            }
            OpEnum::TxAccessListAccountStorage(op) => {
                if !op.is_warm_prev && op.is_warm {
                    self.sdb
                        .add_account_storage_to_access_list((op.address, op.key));
                }
                if op.is_warm_prev && !op.is_warm {
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
        for (step_index, op_ref) in reversion_group.op_refs.iter().rev().copied() {
            if let Some(op) = self.get_rev_op_by_ref(&op_ref) {
                self.apply_op(&op);
                let rev_op_ref = self.block.container.insert_op_enum(
                    self.block_ctx.rwc.inc_pre(),
                    RW::WRITE,
                    false,
                    op,
                );
                self.tx.steps_mut()[step_index]
                    .bus_mapping_instance
                    .push(rev_op_ref);
            }
        }

        // Set calls' `rw_counter_end_of_reversion`
        let rwc = self.block_ctx.rwc.0 - 1;
        for (call_idx, reversible_write_counter_offset) in reversion_group.calls {
            self.tx.calls_mut()[call_idx].rw_counter_end_of_reversion =
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

    pub(crate) fn get_step_err(
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
