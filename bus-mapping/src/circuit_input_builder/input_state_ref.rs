//! CircuitInput builder tooling module.

use super::{
    get_call_memory_offset_length, get_create_init_code, Block, BlockContext, Call, CallContext,
    CallKind, CodeSource, CopyEvent, ExecState, ExecStep, ExpEvent, PrecompileEvent, Transaction,
    TransactionContext,
};
#[cfg(feature = "scroll")]
use crate::util::KECCAK_CODE_HASH_EMPTY;
use crate::{
    circuit_input_builder::execution::{CopyEventPrevBytes, CopyEventSteps, CopyEventStepsBuilder},
    error::{
        get_step_reported_error, ContractAddressCollisionError, DepthError, ExecError,
        InsufficientBalanceError, NonceUintOverflowError,
    },
    exec_trace::OperationRef,
    operation::{
        AccountField, AccountOp, CallContextField, CallContextOp, MemoryOp, Op, OpEnum, Operation,
        StackOp, Target, TxAccessListAccountOp, TxLogField, TxLogOp, TxReceiptField, TxReceiptOp,
        RW,
    },
    precompile::{is_precompiled, PrecompileCalls},
    state_db::{CodeDB, StateDB},
    Error,
};
use eth_types::{
    bytecode::BytecodeElement,
    evm_types::{
        gas_utils::memory_expansion_gas_cost,
        memory::{MemoryRange, MemoryWordRange},
        Gas, GasCost, Memory, MemoryAddress, MemoryRef, OpcodeId, StackAddress, MAX_CODE_SIZE,
    },
    Address, Bytecode, GethExecStep, ToAddress, ToBigEndian, ToWord, Word, H256, U256,
};
use ethers_core::utils::{get_contract_address, get_create2_address};
use log::trace;
use std::{cmp::max, iter::repeat};

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
            call_ctx,
            self.block_ctx.rwc,
            call_ctx.reversible_write_counter,
            self.tx_ctx.log_id,
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
            gas_left: if prev_step.error.is_none() {
                let mut gas_left = prev_step.gas_left.0 - prev_step.gas_cost.0;
                // handling for contract creation tx
                let call = self.tx.calls()[0].clone();
                if call.is_create()
                    && call.is_success()
                    && prev_step.exec_state == ExecState::Op(OpcodeId::RETURN)
                {
                    let code_hash = self.sdb.get_account(&call.address).1.code_hash;
                    if code_hash != CodeDB::empty_code_hash() {
                        let bytecode_len = self.code(code_hash).unwrap().len() as u64;
                        let deposit_cost = bytecode_len * GasCost::CODE_DEPOSIT_BYTE_COST.as_u64();
                        assert!(
                            gas_left >= deposit_cost,
                            "gas left {gas_left} is not enough for deposit cost {deposit_cost}"
                        );
                        gas_left -= deposit_cost;
                    }
                }

                Gas(gas_left)
            } else {
                // consume all remaining gas when non revert err happens
                Gas(0)
            },
            rwc: self.block_ctx.rwc,
            // For tx without code execution
            reversible_write_counter: if let Some(call_ctx) = self.tx_ctx.calls().last() {
                call_ctx.reversible_write_counter
            } else {
                0
            },
            log_id: self.tx_ctx.log_id,
            ..Default::default()
        }
    }

    /// Push an [`Operation`](crate::operation::Operation) into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and then adds a
    /// reference to the stored operation ([`OperationRef`]) inside the
    /// bus-mapping instance of the current [`ExecStep`].  Then increase the
    /// block_ctx [`RWCounter`](crate::operation::RWCounter) by one.
    pub fn push_op<T: Op>(&mut self, step: &mut ExecStep, rw: RW, op: T) -> Result<(), Error> {
        if let OpEnum::Account(op) = op.clone().into_enum() {
            self.check_update_sdb_account(rw, &op)
        }
        let op_ref =
            self.block
                .container
                .insert(Operation::new(self.block_ctx.rwc.inc_pre(), rw, op));
        step.bus_mapping_instance.push(op_ref);
        self.check_rw_num_limit()
    }

    /// Check whether rws will overflow circuit limit.
    pub fn check_rw_num_limit(&self) -> Result<(), Error> {
        let max_rws = self.block.circuits_params.max_rws;
        let effective_limit = if max_rws == 0 {
            // even for dynamic case, we don't want to handle > 1M rows.
            1_000_000
        } else {
            max_rws
        };
        let rwc = self.block_ctx.rwc.0;
        if rwc > effective_limit {
            log::error!("rwc > max_rws, rwc={}, max_rws={}", rwc, max_rws);
            return Err(Error::InternalError("rws not enough"));
        };
        Ok(())
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
    ) -> Result<(), Error> {
        let op = CallContextOp {
            call_id,
            field,
            value,
        };

        self.push_op(step, RW::READ, op)
    }

    /// Push a write type [`CallContextOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with
    /// the next [`RWCounter`](crate::operation::RWCounter)  and then adds a
    /// reference to the stored operation ([`OperationRef`]) inside the
    /// bus-mapping instance of the current [`ExecStep`].  Then increase the
    /// block_ctx [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn call_context_write(
        &mut self,
        step: &mut ExecStep,
        call_id: usize,
        field: CallContextField,
        value: Word,
    ) -> Result<(), Error> {
        let op = CallContextOp {
            call_id,
            field,
            value,
        };

        self.push_op(step, RW::WRITE, op)
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
    pub fn push_op_reversible<T: Op>(&mut self, step: &mut ExecStep, op: T) -> Result<(), Error> {
        self.check_apply_op(&op.clone().into_enum());
        let op_ref = self.block.container.insert(Operation::new_reversible(
            self.block_ctx.rwc.inc_pre(),
            RW::WRITE,
            op,
        ));
        step.bus_mapping_instance.push(op_ref);

        // Increase reversible_write_counter
        self.call_ctx_mut()?.reversible_write_counter += 1;
        step.reversible_write_counter_delta += 1;

        // Add the operation into reversible_ops if this call is not persistent
        if !self.call()?.is_persistent {
            self.tx_ctx
                .reversion_groups
                .last_mut()
                .expect("reversion_groups should not be empty for non-persistent call")
                .op_refs
                .push((self.tx.steps().len(), op_ref));
        }

        self.check_rw_num_limit()
    }

    /// Push a read type [`MemoryOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and `call_id`, and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter) by one.
    pub fn memory_read_word(
        &mut self,
        step: &mut ExecStep,
        address: MemoryAddress,
    ) -> Result<Word, Error> {
        let mem = &self.call_ctx()?.memory;
        let value = mem.read_word(address);

        let call_id = self.call()?.call_id;
        self.push_op(step, RW::READ, MemoryOp::new(call_id, address, value))?;
        Ok(value)
    }

    /// Push a read type [`MemoryOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and `caller_id`, and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter) by one.
    pub fn memory_read_caller(
        &mut self,
        step: &mut ExecStep,
        address: MemoryAddress,
    ) -> Result<Word, Error> {
        let mem = &self.caller_ctx()?.memory;
        let value = mem.read_word(address);

        let caller_id = self.call()?.caller_id;
        self.push_op(step, RW::READ, MemoryOp::new(caller_id, address, value))?;
        Ok(value)
    }

    /// Push a write type [`MemoryOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and `call_id`, and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn memory_write_word(
        &mut self,
        step: &mut ExecStep,
        address: MemoryAddress, //Caution: make sure this address = slot passing
        value: Word,
    ) -> Result<Vec<u8>, Error> {
        assert_eq!(address.0 % 32, 0);
        let mem = &mut self.call_ctx_mut()?.memory;
        let value_prev = mem.read_word(address);
        let value_prev_bytes = value_prev.to_be_bytes();

        let value_bytes = value.to_be_bytes();
        mem.write_chunk(address, &value_bytes);

        let call_id = self.call()?.call_id;
        self.push_op(
            step,
            RW::WRITE,
            MemoryOp::new_write(call_id, address, value, value_prev),
        )?;
        Ok(value_prev_bytes.to_vec())
    }

    /// Push a write type [`MemoryOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter) and `caller_id`, and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn memory_write_caller(
        &mut self,
        step: &mut ExecStep,
        address: MemoryAddress, //Caution: make sure this address = slot passing
        value: Word,
    ) -> Result<Vec<u8>, Error> {
        let mem = &mut self.caller_ctx_mut()?.memory;
        let value_prev = mem.read_word(address);
        let value_prev_bytes = value_prev.to_be_bytes();

        let value_bytes = value.to_be_bytes();
        mem.write_chunk(address, &value_bytes);

        let call_id = self.call()?.caller_id;
        self.push_op(
            step,
            RW::WRITE,
            MemoryOp::new_write(call_id, address, value, value_prev),
        )?;
        Ok(value_prev_bytes.to_vec())
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
        self.push_op(step, RW::WRITE, StackOp::new(call_id, address, value))?;
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
        self.push_op(step, RW::READ, StackOp::new(call_id, address, value))?;
        Ok(())
    }

    /// First check the validity and consistency of the rw operation against the
    /// account in the StateDB, then if the rw operation is a write, apply
    /// it to the corresponding account in the StateDB.
    fn check_update_sdb_account(&mut self, rw: RW, op: &AccountOp) {
        let mut account = self.sdb.get_account_mut(&op.address).1.clone();
        // -- sanity check begin --
        // Verify that a READ doesn't change the field value
        if matches!(rw, RW::READ) && op.value_prev != op.value {
            panic!(
                "RWTable Account field read where value_prev != value rwc: {}, op: {:?}",
                self.block_ctx.rwc.0, op
            )
        }
        // NOTE: In the State Circuit we use code_hash=0 to encode non-existing
        // accounts, but the corresponding account in the state DB is empty
        // (which means code_hash=EMPTY_HASH).
        let account_value_prev = match op.field {
            AccountField::Nonce => account.nonce,
            AccountField::Balance => account.balance,
            AccountField::KeccakCodeHash => {
                if account.is_empty() {
                    if op.value.is_zero() {
                        // Writing code_hash=0 to empty account is a noop to the StateDB.
                        return;
                    }
                    // Reading a code_hash=EMPTY_HASH of an empty account in the StateDB is encoded
                    // as code_hash=0 (non-existing account encoding) in the State Circuit.
                    Word::zero()
                } else {
                    account.keccak_code_hash.to_word()
                }
            }
            AccountField::CodeHash => {
                if account.is_empty() {
                    if op.value.is_zero() {
                        // Writing code_hash=0 to empty account is a noop to the StateDB.
                        return;
                    }
                    // Reading a code_hash=EMPTY_HASH of an empty account in the StateDB is encoded
                    // as code_hash=0 (non-existing account encoding) in the State Circuit.
                    Word::zero()
                } else {
                    account.code_hash.to_word()
                }
            }
            AccountField::CodeSize => account.code_size,
        };

        // Verify that the previous value matches the account field value in the StateDB
        if op.value_prev != account_value_prev {
            panic!(
                "RWTable Account field {:?} lookup doesn't match account value
        account: {:?}, rwc: {}, op: {:?}",
                rw, account, self.block_ctx.rwc.0, op
            );
        }
        // Verify that no rw is done to a field other than CodeHash to a non-existing
        // account (only CodeHash reads with value=0 can be done to non-existing
        // accounts, which the State Circuit translates to MPT
        // AccountNonExisting proofs lookups).
        if (account.is_empty() && !self.sdb.is_touched(&op.address))
            && !matches!(op.field, AccountField::CodeHash)
        {
            panic!(
                "RWTable Account field {:?} lookup to non-existing account rwc: {}, op: {:?}",
                rw, self.block_ctx.rwc.0, op
            );
        }
        // -- sanity check end --
        // Perform the write to the account in the StateDB
        if matches!(rw, RW::WRITE) {
            match op.field {
                AccountField::Nonce => account.nonce = op.value,
                AccountField::Balance => {
                    log::trace!("update balance of {:?} to {:?}", &op.address, op.value);
                    account.balance = op.value;
                }
                AccountField::KeccakCodeHash => {
                    let value = H256::from(op.value.to_be_bytes());
                    account.keccak_code_hash = value;
                }
                AccountField::CodeHash => {
                    self.sdb.set_touched(&op.address);
                    let value = H256::from(op.value.to_be_bytes());
                    account.code_hash = value;
                }
                AccountField::CodeSize => {
                    account.code_size = op.value;
                }
            }
        }
        self.sdb.set_account(&op.address, account);
    }

    /// Push a read type [`AccountOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter), and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn account_read(
        &mut self,
        step: &mut ExecStep,
        address: Address,
        field: AccountField,
        value: Word,
    ) -> Result<(), Error> {
        let op = AccountOp::new(address, field, value, value);
        self.push_op(step, RW::READ, op)
    }

    /// Push a write type [`AccountOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter), and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn account_write(
        &mut self,
        step: &mut ExecStep,
        address: Address,
        field: AccountField,
        value: Word,
        value_prev: Word,
    ) -> Result<(), Error> {
        let op = AccountOp::new(address, field, value, value_prev);
        self.push_op(step, RW::WRITE, op)
    }

    /// Push a write type [`TxLogOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter), and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn tx_log_write(
        &mut self,
        step: &mut ExecStep,
        tx_id: usize,
        log_id: usize,
        field: TxLogField,
        index: usize,
        value: Word,
    ) -> Result<(), Error> {
        self.push_op(
            step,
            RW::WRITE,
            TxLogOp::new(tx_id, log_id, field, index, value),
        )
    }

    /// Push a read type [`TxReceiptOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter), and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn tx_receipt_read(
        &mut self,
        step: &mut ExecStep,
        tx_id: usize,
        field: TxReceiptField,
        value: u64,
    ) -> Result<(), Error> {
        self.push_op(
            step,
            RW::READ,
            TxReceiptOp {
                tx_id,
                field,
                value,
            },
        )
    }

    /// Push a write type [`TxReceiptOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter), and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn tx_receipt_write(
        &mut self,
        step: &mut ExecStep,
        tx_id: usize,
        field: TxReceiptField,
        value: u64,
    ) -> Result<(), Error> {
        self.push_op(
            step,
            RW::WRITE,
            TxReceiptOp {
                tx_id,
                field,
                value,
            },
        )
    }

    /// Add address to access list for the current transaction.
    pub fn tx_access_list_write(
        &mut self,
        step: &mut ExecStep,
        address: Address,
    ) -> Result<(), Error> {
        let is_warm = self.sdb.check_account_in_access_list(&address);
        self.push_op_reversible(
            step,
            TxAccessListAccountOp {
                tx_id: self.tx_ctx.id(),
                address,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )
    }

    /// Push a write type [`TxAccessListAccountOp`] into the
    /// [`OperationContainer`](crate::operation::OperationContainer) with the
    /// next [`RWCounter`](crate::operation::RWCounter), and then
    /// adds a reference to the stored operation ([`OperationRef`]) inside
    /// the bus-mapping instance of the current [`ExecStep`].  Then increase
    /// the `block_ctx` [`RWCounter`](crate::operation::RWCounter)  by one.
    pub fn tx_accesslist_account_write(
        &mut self,
        step: &mut ExecStep,
        tx_id: usize,
        address: Address,
        is_warm: bool,
        is_warm_prev: bool,
    ) -> Result<(), Error> {
        self.push_op(
            step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id,
                address,
                is_warm,
                is_warm_prev,
            },
        )
    }

    /// Push 2 reversible [`AccountOp`] to update `sender` and `receiver`'s
    /// balance by `value`. If `fee` is existing (not None), also need to push 1
    /// non-reversible [`AccountOp`] to update `sender` balance by `fee`.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_with_fee(
        &mut self,
        step: &mut ExecStep,
        sender: Address,
        receiver: Address,
        receiver_exists: bool,
        must_create: bool,
        value: Word,
        fee: Option<Word>,
    ) -> Result<(), Error> {
        self.transfer_from_with_fee(step, sender, value, fee)?;
        self.transfer_to(step, receiver, receiver_exists, must_create, value, true)?;
        Ok(())
    }

    /// Push 1 reversible [`AccountOp`] to update `sender`'s balance by
    /// `value`. If `fee` is existing (not None), also need to push 1
    /// non-reversible [`AccountOp`] to update `sender` balance by `fee`.
    pub fn transfer_from_with_fee(
        &mut self,
        step: &mut ExecStep,
        sender: Address,
        value: Word,
        fee: Option<Word>,
    ) -> Result<(), Error> {
        let (found, sender_account) = self.sdb.get_account(&sender);
        if !found {
            return Err(Error::AccountNotFound(sender));
        }
        let mut sender_balance_prev = sender_account.balance;
        debug_assert!(
            sender_account.balance >= value + fee.unwrap_or_default(),
            "invalid amount balance {sender_balance_prev:?} value {value:?} fee {fee:?}",
        );
        if let Some(fee) = fee {
            let sender_balance = sender_balance_prev - fee;
            log::trace!(
                "sender balance update with fee (not reversible): {:?} {:?}->{:?}",
                sender,
                sender_balance_prev,
                sender_balance
            );
            self.push_op(
                step,
                RW::WRITE,
                AccountOp {
                    address: sender,
                    field: AccountField::Balance,
                    value: sender_balance,
                    value_prev: sender_balance_prev,
                },
            )?;
            sender_balance_prev = sender_balance;
        }
        let sender_balance = sender_balance_prev - value;
        log::trace!(
            "sender balance update with value: {:?} {:?}->{:?}",
            sender,
            sender_balance_prev,
            sender_balance
        );
        if !value.is_zero() {
            self.push_op_reversible(
                step,
                AccountOp {
                    address: sender,
                    field: AccountField::Balance,
                    value: sender_balance,
                    value_prev: sender_balance_prev,
                },
            )?;
        }
        Ok(())
    }

    /// Push 1 [`AccountOp`] to update `receiver`'s balance by `value`.
    /// If `receiver` doesn't exist, also need to push 1 [`AccountOp`]
    /// to create `receiver`.
    pub fn transfer_to(
        &mut self,
        step: &mut ExecStep,
        receiver: Address,
        receiver_exists: bool,
        must_create: bool,
        value: Word,
        reversible: bool,
    ) -> Result<(), Error> {
        // If receiver doesn't exist, create it
        if (!receiver_exists && !value.is_zero()) || must_create {
            let account = self.sdb.get_account(&receiver).1.clone();
            let prev_code_hash = if account.is_empty() {
                Word::zero()
            } else {
                CodeDB::empty_code_hash().to_word()
            };
            self.account_read(step, receiver, AccountField::CodeHash, prev_code_hash)?;
            let write_op = AccountOp::new(
                receiver,
                AccountField::CodeHash,
                CodeDB::empty_code_hash().to_word(),
                prev_code_hash,
            );
            if reversible {
                self.push_op_reversible(step, write_op)?;
            } else {
                self.push_op(step, RW::WRITE, write_op)?;
            }
            #[cfg(feature = "scroll")]
            {
                let prev_keccak_code_hash = if account.is_empty() {
                    Word::zero()
                } else {
                    KECCAK_CODE_HASH_EMPTY.to_word()
                };
                self.account_read(
                    step,
                    receiver,
                    AccountField::KeccakCodeHash,
                    prev_keccak_code_hash,
                )?;
                let write_op = AccountOp::new(
                    receiver,
                    AccountField::KeccakCodeHash,
                    KECCAK_CODE_HASH_EMPTY.to_word(),
                    prev_keccak_code_hash,
                );
                if reversible {
                    self.push_op_reversible(step, write_op)?;
                } else {
                    self.push_op(step, RW::WRITE, write_op)?;
                }
                // TODO: set code size to 0?
            }
        }
        if value.is_zero() {
            // Skip transfer if value == 0
            return Ok(());
        }

        let (_found, receiver_account) = self.sdb.get_account(&receiver);
        let receiver_balance_prev = receiver_account.balance;
        let receiver_balance = receiver_account.balance + value;
        log::trace!(
            "receiver balance update: {:?} {:?}->{:?}",
            receiver,
            receiver_balance_prev,
            receiver_balance
        );
        let write_op = AccountOp::new(
            receiver,
            AccountField::Balance,
            receiver_balance,
            receiver_balance_prev,
        );
        if reversible {
            self.push_op_reversible(step, write_op)?;
        } else {
            self.push_op(step, RW::WRITE, write_op)?;
        }

        Ok(())
    }

    /// Same functionality with `transfer_with_fee` but with `fee` set zero.
    pub fn transfer(
        &mut self,
        step: &mut ExecStep,
        sender: Address,
        receiver: Address,
        receiver_exists: bool,
        must_create: bool,
        value: Word,
    ) -> Result<(), Error> {
        self.transfer_with_fee(
            step,
            sender,
            receiver,
            receiver_exists,
            must_create,
            value,
            None,
        )
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

    /// Mutable reference to the current call's caller Call
    pub fn caller_mut(&mut self) -> Result<&mut Call, Error> {
        self.tx_ctx
            .caller_index()
            .map(|caller_idx| &mut self.tx.calls_mut()[caller_idx])
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
    pub fn caller_ctx(&self) -> Result<&CallContext, Error> {
        self.tx_ctx.caller_ctx()
    }

    /// Reference to the current CallContext
    pub fn call_ctx(&self) -> Result<&CallContext, Error> {
        self.tx_ctx.call_ctx()
    }

    /// Mutable reference to the call CallContext
    pub fn call_ctx_mut(&mut self) -> Result<&mut CallContext, Error> {
        self.tx_ctx.call_ctx_mut()
    }

    /// Mutable reference to the caller CallContext
    pub fn caller_ctx_mut(&mut self) -> Result<&mut CallContext, Error> {
        self.tx_ctx
            .calls
            .iter_mut()
            .rev()
            .nth(1)
            .ok_or(Error::InternalError("caller id not found in call map"))
    }

    /// Push a new [`Call`] into the [`Transaction`], and add its index and
    /// [`CallContext`] in the `call_stack` of the [`TransactionContext`]
    pub fn push_call(&mut self, call: Call) {
        let caller_call = self.call_ctx().expect("current call not found");
        let call_data = match call.kind {
            CallKind::Call | CallKind::CallCode | CallKind::DelegateCall | CallKind::StaticCall => {
                caller_call.memory.read_chunk(MemoryRange::new_with_length(
                    call.call_data_offset,
                    call.call_data_length,
                ))
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
        let address = get_contract_address(sender, account.nonce);
        log::trace!(
            "create_address {:?}, from {:?}, nonce {:?}",
            address,
            self.call()?.address,
            account.nonce
        );
        Ok(address)
    }

    /// Return the contract address of a CREATE2 step.  This is calculated
    /// deterministically from the arguments in the stack.
    pub(crate) fn create2_address(&self, step: &GethExecStep) -> Result<Address, Error> {
        let salt = step.stack.nth_last(3)?;
        let call_ctx = self.call_ctx()?;
        let init_code = get_create_init_code(call_ctx, step)?.to_vec();
        let address = get_create2_address(self.call()?.address, salt.to_be_bytes(), init_code);
        log::trace!(
            "create2_address {:?}, from {:?}, salt {:?}",
            address,
            self.call()?.address,
            salt
        );
        Ok(address)
    }

    pub(crate) fn reversion_info_read(
        &mut self,
        step: &mut ExecStep,
        call: &Call,
    ) -> Result<(), Error> {
        for (field, value) in [
            (
                CallContextField::RwCounterEndOfReversion,
                call.rw_counter_end_of_reversion.to_word(),
            ),
            (CallContextField::IsPersistent, call.is_persistent.to_word()),
        ] {
            self.call_context_read(step, call.call_id, field, value)?;
        }
        Ok(())
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
        let caller_ctx = self.call_ctx()?;

        let (caller_address, address, value) = match kind {
            CallKind::Call => (
                caller.address,
                step.stack.nth_last(1)?.to_address(),
                step.stack.nth_last(2)?,
            ),
            CallKind::CallCode => (caller.address, caller.address, step.stack.nth_last(2)?),
            CallKind::DelegateCall => (caller.caller_address, caller.address, caller.value),
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
                let init_code = get_create_init_code(caller_ctx, step)?.to_vec();
                let code_hash = self.code_db.insert(init_code);
                (CodeSource::Memory, code_hash)
            }
            _ => {
                let code_address = match kind {
                    CallKind::CallCode | CallKind::DelegateCall => {
                        step.stack.nth_last(1)?.to_address()
                    }
                    _ => address,
                };
                if is_precompiled(&code_address) {
                    (CodeSource::Address(code_address), CodeDB::empty_code_hash())
                } else {
                    let (found, account) = self.sdb.get_account(&code_address);
                    if !found {
                        (CodeSource::Address(code_address), CodeDB::empty_code_hash())
                    } else {
                        (CodeSource::Address(code_address), account.code_hash)
                    }
                }
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
            last_callee_id: 0,
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
            last_callee_return_data_offset: 0,
            last_callee_return_data_length: 0,
            last_callee_memory: Memory::default(),
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
            _ => None,
        }
    }

    /// Check and apply op to state.
    fn check_apply_op(&mut self, op: &OpEnum) {
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
            OpEnum::Account(op) => self.check_update_sdb_account(RW::WRITE, op),
            OpEnum::TxRefund(op) => {
                self.sdb.set_refund(op.value);
            }
            _ => unreachable!(),
        };
    }

    /// Handle a reversion group
    pub fn handle_reversion(&mut self, current_exec_steps: &mut [&mut ExecStep]) {
        // we already know that the call has reverted. Only the precompile failure case must be
        // handled differently as the ExecSteps associated with those calls haven't yet been pushed
        // to the tx's steps.

        let reversion_group = self
            .tx_ctx
            .reversion_groups
            .pop()
            .expect("reversion_groups should not be empty for non-persistent call");

        // Apply reversions
        for (step_index, op_ref) in reversion_group.op_refs.iter().rev().copied() {
            if let Some(op) = self.get_rev_op_by_ref(&op_ref) {
                self.check_apply_op(&op);
                let rev_op_ref = self.block.container.insert_op_enum(
                    self.block_ctx.rwc.inc_pre(),
                    RW::WRITE,
                    false,
                    op,
                );
                let step: &mut ExecStep = if step_index >= self.tx.steps_mut().len() {
                    // the `current_exec_steps` will be appended after self.tx.steps
                    // So here we do an index-mapping.
                    current_exec_steps[step_index - self.tx.steps_mut().len()]
                } else {
                    &mut self.tx.steps_mut()[step_index]
                };
                step.bus_mapping_instance.push(rev_op_ref);
            }
        }

        // Set calls' `rw_counter_end_of_reversion`
        let rwc = self.block_ctx.rwc.0 - 1;
        for (call_idx, reversible_write_counter_offset) in reversion_group.calls {
            self.tx.calls_mut()[call_idx].rw_counter_end_of_reversion =
                rwc - reversible_write_counter_offset;
        }
    }

    /// Handle a restore and a return step caused by any opcode that causes a return to the
    /// previous call context.
    /// `caller_ctx.return_data` should be updated **before** this method (except error cases).
    pub fn handle_return(
        &mut self,
        current_exec_steps: &mut [&mut ExecStep],
        geth_steps: &[GethExecStep],
        need_restore: bool,
    ) -> Result<(), Error> {
        let step = &geth_steps[0];

        // For these 6 opcodes, the return data should be handled in opcodes respectively.
        // For other opcodes/states, return data must be empty.
        if !matches!(
            step.op,
            OpcodeId::RETURN
                | OpcodeId::REVERT
                | OpcodeId::CALL
                | OpcodeId::CALLCODE
                | OpcodeId::DELEGATECALL
                | OpcodeId::STATICCALL
        ) || current_exec_steps[0].error.is_some()
        {
            if let Ok(caller) = self.caller_ctx_mut() {
                caller.return_data.clear();
            }
        }
        if need_restore {
            // only precompile needs more than 1 current_exec_steps
            if current_exec_steps.len() > 1 {
                debug_assert!(
                    current_exec_steps[1].is_precompiled()
                        || current_exec_steps[1].is_precompile_oog_err()
                );
            }
            self.handle_restore_context(
                current_exec_steps[current_exec_steps.len() - 1],
                geth_steps,
            )?;
        }
        let call = self.call()?.clone();
        let call_ctx = self.call_ctx()?;
        let callee_memory = call_ctx.memory.clone();
        let call_success_create: bool =
            call.is_create() && call.is_success && step.op == OpcodeId::RETURN;

        // Store deployed code if it's a successful create
        if call_success_create {
            let offset = step.stack.nth_last(0)?;
            let length = step.stack.nth_last(1)?;
            let code = callee_memory.read_chunk(MemoryRange::new_with_length(
                offset.low_u64(),
                length.low_u64(),
            ));

            #[cfg(feature = "scroll")]
            let keccak_code_hash = H256(ethers_core::utils::keccak256(&code));
            let code_hash = self.code_db.insert(code);

            let (found, callee_account) = self.sdb.get_account_mut(&call.address);
            if !found {
                return Err(Error::AccountNotFound(call.address));
            }

            // already updated in return_revert.rs with check_update_sdb_account
            debug_assert_eq!(callee_account.code_hash, code_hash);
            #[cfg(feature = "scroll")]
            {
                debug_assert_eq!(callee_account.code_size, length);
                debug_assert_eq!(callee_account.keccak_code_hash, keccak_code_hash);
            }
        }

        // Handle reversion if this call doesn't end successfully
        if !call.is_success {
            self.handle_reversion(current_exec_steps);
        }

        let return_data_length = self
            .caller_ctx()
            .map(|c| c.return_data.len() as u64)
            .unwrap_or_default();
        // If current call has caller.
        if let Ok(caller) = self.caller_mut() {
            let return_data_offset = if matches!(step.op, OpcodeId::RETURN | OpcodeId::REVERT)
                && step.error.is_none()
                && !call_success_create
            {
                step.stack.nth_last(0)?.low_u64()
            } else {
                // common err, call empty, call precompile
                0
            };

            caller.last_callee_id = call.call_id;
            caller.last_callee_return_data_length = return_data_length;
            caller.last_callee_return_data_offset = return_data_offset;
            caller.last_callee_memory = callee_memory;
        }

        self.tx_ctx.pop_call_ctx();

        Ok(())
    }

    // The returned (return_data_offset, return_data_len) pair, is the values used to calculate
    // memory expansion cost when successful case. So for "successful deployment" case, it will
    // be non 0 while the call_ctx.return should be empty for this case. EIP-211: CREATE/CREATE2
    // call successful case should set RETURNDATASIZE = 0
    fn get_return_data_offset_and_len(
        exec_step: &ExecStep,
        geth_step: &GethExecStep,
        caller_ctx: &CallContext,
    ) -> Result<(U256, U256), Error> {
        let is_err = exec_step.error.is_some();
        let [last_callee_return_data_offset, last_callee_return_data_length] = if is_err {
            [Word::zero(), Word::zero()]
        } else {
            match geth_step.op {
                OpcodeId::STOP => [Word::zero(); 2],
                OpcodeId::CALL
                | OpcodeId::CALLCODE
                | OpcodeId::STATICCALL
                | OpcodeId::DELEGATECALL => {
                    let return_data_length = match exec_step.exec_state {
                        ExecState::Precompile(_) => {
                            // successful precompile call
                            caller_ctx.return_data.len().into()
                        }
                        _ => Word::zero(),
                    };
                    [Word::zero(), return_data_length]
                }
                OpcodeId::REVERT | OpcodeId::RETURN => {
                    let offset = geth_step.stack.nth_last(0)?;
                    let length = geth_step.stack.nth_last(1)?;
                    // This is the convention we are using for memory addresses so that there is no
                    // memory expansion cost when the length is 0.
                    // https://github.com/privacy-scaling-explorations/zkevm-circuits/pull/279/files#r787806678
                    if length.is_zero() {
                        [Word::zero(); 2]
                    } else {
                        [offset, length]
                    }
                }
                _ => [Word::zero(), Word::zero()],
            }
        };
        Ok((
            last_callee_return_data_offset,
            last_callee_return_data_length,
        ))
    }

    /// Bus mapping for the RestoreContextGadget as used in RETURN.
    pub fn handle_restore_context(
        &mut self,
        exec_step: &mut ExecStep,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let call = self.call()?.clone();
        let geth_step = steps
            .get(0)
            .ok_or(Error::InternalError("invalid index 0"))?;
        let is_err = exec_step.error.is_some();
        let is_return_revert_succ = (geth_step.op == OpcodeId::REVERT
            || geth_step.op == OpcodeId::RETURN)
            && exec_step.error.is_none();

        // successful revert also makes call.is_success == false
        // but this "successful revert" should not be handled here
        if !is_return_revert_succ
            && !call.is_success
            && !exec_step.is_precompiled()
            && !exec_step.is_precompile_oog_err()
        {
            // add call failure ops for exception cases
            self.call_context_read(
                exec_step,
                call.call_id,
                CallContextField::IsSuccess,
                0u64.into(),
            )?;

            // Even call.rw_counter_end_of_reversion is zero for now, it will set in
            // set_value_ops_call_context_rwc_eor later
            // if call fails, no matter root or internal, read RwCounterEndOfReversion for
            // circuit constraint.
            self.call_context_read(
                exec_step,
                call.call_id,
                CallContextField::RwCounterEndOfReversion,
                call.rw_counter_end_of_reversion.into(),
            )?;

            if call.is_root {
                return Ok(());
            }
        }
        let caller = self.caller()?.clone();
        let geth_step_next = steps
            .get(1)
            .ok_or(Error::InternalError("invalid index 1"))?;
        self.call_context_read(
            exec_step,
            call.call_id,
            CallContextField::CallerId,
            caller.call_id.into(),
        )?;

        let (last_callee_return_data_offset, last_callee_return_data_length) =
            Self::get_return_data_offset_and_len(exec_step, geth_step, self.caller_ctx()?)?;

        let gas_refund = if is_err {
            0
        } else if exec_step.is_precompiled() {
            exec_step.gas_left.0 - exec_step.gas_cost.0
        } else {
            let curr_memory_word_size = (exec_step.memory_size as u64) / 32;
            let next_memory_word_size = if !last_callee_return_data_length.is_zero() {
                std::cmp::max(
                    (last_callee_return_data_offset + last_callee_return_data_length + 31).as_u64()
                        / 32,
                    curr_memory_word_size,
                )
            } else {
                curr_memory_word_size
            };

            let memory_expansion_gas_cost =
                memory_expansion_gas_cost(curr_memory_word_size, next_memory_word_size);
            let code_deposit_cost = if call.is_create() && call.is_success {
                GasCost::CODE_DEPOSIT_BYTE_COST.as_u64() * last_callee_return_data_length.as_u64()
            } else {
                0
            };
            let constant_step_gas = match geth_step.op {
                OpcodeId::SELFDESTRUCT => geth_step.gas_cost.0,
                _ => 0, // RETURN/STOP/REVERT have no "constant_step_gas"
            };

            geth_step.gas.0 - memory_expansion_gas_cost - code_deposit_cost - constant_step_gas
        };

        let caller_gas_left = geth_step_next.gas.0.checked_sub(gas_refund).unwrap_or_else(
            || {
                panic!("caller_gas_left underflow geth_step_next {geth_step_next:?}, gas_refund {gas_refund:?}, exec_step {exec_step:?}, geth_step {geth_step:?}"); 
            }
        );
        for (field, value) in [
            (CallContextField::IsRoot, (caller.is_root as u64).into()),
            (
                CallContextField::IsCreate,
                (caller.is_create() as u64).into(),
            ),
            (CallContextField::CodeHash, caller.code_hash.to_word()),
            (CallContextField::ProgramCounter, geth_step_next.pc.0.into()),
            (
                CallContextField::StackPointer,
                geth_step_next.stack.stack_pointer().0.into(),
            ),
            (CallContextField::GasLeft, caller_gas_left.into()),
            (
                CallContextField::MemorySize,
                self.caller_ctx()?.memory.word_size().into(),
            ),
            (
                CallContextField::ReversibleWriteCounter,
                self.caller_ctx()?.reversible_write_counter.into(),
            ),
        ] {
            self.call_context_read(exec_step, caller.call_id, field, value)?;
        }

        // EIP-211: CREATE/CREATE2 call successful case should set RETURNDATASIZE = 0
        let discard_return_data = call.is_create() && geth_step.op == OpcodeId::RETURN || is_err;
        for (field, value) in [
            (CallContextField::LastCalleeId, call.call_id.into()),
            (
                CallContextField::LastCalleeReturnDataOffset,
                if discard_return_data {
                    U256::zero()
                } else {
                    last_callee_return_data_offset
                },
            ),
            (
                CallContextField::LastCalleeReturnDataLength,
                if discard_return_data {
                    U256::zero()
                } else {
                    last_callee_return_data_length
                },
            ),
        ] {
            self.call_context_write(exec_step, caller.call_id, field, value)?;
        }

        Ok(())
    }

    /// Push a copy event to the state.
    pub fn push_copy(&mut self, step: &mut ExecStep, event: CopyEvent) {
        step.copy_rw_counter_delta += event.rw_counter_delta();
        self.block.add_copy_event(event);
    }

    /// Push a exponentiation event to the state.
    pub fn push_exponentiation(&mut self, event: ExpEvent) {
        self.block.add_exp_event(event)
    }

    /// Push an event representing auxiliary data for a precompile call to the state.
    pub fn push_precompile_event(&mut self, event: PrecompileEvent) {
        self.block.add_precompile_event(event)
    }

    pub(crate) fn get_step_err(
        &self,
        step: &GethExecStep,
        next_step: Option<&GethExecStep>,
    ) -> Result<Option<ExecError>, Error> {
        if matches!(step.op, OpcodeId::INVALID(_)) {
            return Ok(Some(ExecError::InvalidOpcode));
        }

        if let Some(error) = &step.error {
            return Ok(Some(get_step_reported_error(&step.op, error)));
        }

        let call = self.call()?;

        if matches!(next_step, None) {
            // enumerating call scope successful cases
            // case 1: call with normal halt opcode termination
            if matches!(
                step.op,
                OpcodeId::STOP | OpcodeId::REVERT | OpcodeId::SELFDESTRUCT
            ) {
                return Ok(None);
            }
            // case 2: call is NOT Create (Create represented by empty tx.to) and halt by
            // opcode::Return
            if !call.is_create() && step.op == OpcodeId::RETURN {
                return Ok(None);
            }
            // case 3 Create with successful RETURN
            if call.is_create() && call.is_success && step.op == OpcodeId::RETURN {
                return Ok(None);
            }
            // more other case...
        }

        let next_depth = next_step.map(|s| s.depth).unwrap_or(0);
        let next_result = next_step
            .map(|s| s.stack.last().unwrap_or_else(|_| Word::zero()))
            .unwrap_or_else(Word::zero);

        let call_ctx = self.call_ctx()?;
        // get value first if call/create
        let value = match step.op {
            OpcodeId::CALL | OpcodeId::CALLCODE => step.stack.nth_last(2)?,
            OpcodeId::CREATE | OpcodeId::CREATE2 => step.stack.nth_last(0)?,
            _ => Word::zero(),
        };

        // Return from a call with a failure
        if step.depth == next_depth + 1 && next_result.is_zero() {
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
                    OpcodeId::CALL if call.is_static && !value.is_zero() => {
                        Some(ExecError::WriteProtection)
                    }

                    OpcodeId::REVERT => None,
                    _ => {
                        return Err(Error::UnexpectedExecStepError(
                            "call failure without return",
                            Box::new(step.clone()),
                        ));
                    }
                });
            } else {
                // Return from a {CREATE, CREATE2} with a failure, via RETURN
                if call.is_create() {
                    let offset = step.stack.nth_last(0)?;
                    let length = step.stack.nth_last(1)?;
                    if length > Word::from(MAX_CODE_SIZE) {
                        return Ok(Some(ExecError::MaxCodeSizeExceeded));
                    } else if length > Word::zero()
                        && !call_ctx.memory.is_empty()
                        && call_ctx.memory.0.get(offset.low_u64() as usize) == Some(&0xef)
                    {
                        return Ok(Some(ExecError::InvalidCreationCode));
                    } else if Word::from(200u64) * length > Word::from(step.gas.0) {
                        return Ok(Some(ExecError::CodeStoreOutOfGas));
                    } else {
                        return Err(Error::UnexpectedExecStepError(
                            "failure in RETURN from {CREATE, CREATE2}",
                            Box::new(step.clone()),
                        ));
                    }
                } else {
                    return Err(Error::UnexpectedExecStepError(
                        "failure in RETURN",
                        Box::new(step.clone()),
                    ));
                }
            }
        }

        // Return from a call via RETURN or STOP and having a success result is
        // OK.

        // Return from a call without calling RETURN or STOP and having success
        // is unexpected.
        if step.depth == next_depth + 1
            && next_result != Word::zero()
            && !matches!(
                step.op,
                OpcodeId::RETURN | OpcodeId::STOP | OpcodeId::SELFDESTRUCT
            )
        {
            return Err(Error::UnexpectedExecStepError(
                "success result without {RETURN, STOP, SELFDESTRUCT}",
                Box::new(step.clone()),
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
                return Ok(Some(ExecError::Depth(match step.op {
                    OpcodeId::CALL
                    | OpcodeId::CALLCODE
                    | OpcodeId::DELEGATECALL
                    | OpcodeId::STATICCALL => DepthError::Call,
                    OpcodeId::CREATE => DepthError::Create,
                    OpcodeId::CREATE2 => DepthError::Create2,
                    op => unreachable!("ErrDepth cannot occur in {op}"),
                })));
            }

            let sender = self.call()?.address;
            let (found, account) = self.sdb.get_account(&sender);
            if !found {
                return Err(Error::AccountNotFound(sender));
            }
            if account.balance < value {
                return Ok(Some(ExecError::InsufficientBalance(match step.op {
                    OpcodeId::CALL | OpcodeId::CALLCODE => InsufficientBalanceError::Call,
                    OpcodeId::CREATE => InsufficientBalanceError::Create,
                    OpcodeId::CREATE2 => InsufficientBalanceError::Create2,
                    op => {
                        unreachable!("insufficient balance error unexpected for opcode: {:?}", op)
                    }
                })));
            }

            //  Nonce Uint overflow
            if account.nonce >= u64::MAX.into() {
                return Ok(Some(ExecError::NonceUintOverflow(match step.op {
                    OpcodeId::CREATE => NonceUintOverflowError::Create,
                    OpcodeId::CREATE2 => NonceUintOverflowError::Create2,
                    op => unreachable!("Nonce Uint overflow error unexpected for opcode: {:?}", op),
                })));
            }

            // Address collision
            if matches!(step.op, OpcodeId::CREATE | OpcodeId::CREATE2) {
                let (address, contract_addr_collision_err) = match step.op {
                    OpcodeId::CREATE => (
                        self.create_address()?,
                        ContractAddressCollisionError::Create,
                    ),
                    OpcodeId::CREATE2 => (
                        self.create2_address(step)?,
                        ContractAddressCollisionError::Create2,
                    ),
                    _ => unreachable!(),
                };
                let (found, _) = self.sdb.get_account(&address);
                if found {
                    log::debug!(
                        "create address collision at {:?}, step {:?}, next_step {:?}",
                        address,
                        step,
                        next_step
                    );
                    return Ok(Some(ExecError::ContractAddressCollision(
                        contract_addr_collision_err,
                    )));
                }
            }

            // Precompile call failures.
            if matches!(
                step.op,
                OpcodeId::CALL | OpcodeId::CALLCODE | OpcodeId::DELEGATECALL | OpcodeId::STATICCALL
            ) {
                let code_address = step.stack.nth_last(1)?.to_address();
                // NOTE: we do not know the amount of gas that precompile got here
                //   because the callGasTemp might probably be smaller than the gas
                //   on top of the stack (step.stack.last())
                // Therefore we postpone the oog handling to the implementor of callop.
                if is_precompiled(&code_address) {
                    let precompile_call: PrecompileCalls = code_address[19].into();
                    match precompile_call {
                        PrecompileCalls::Sha256
                        | PrecompileCalls::Ripemd160
                        | PrecompileCalls::Blake2F => {
                            // Log the precompile address and gas left. Since this failure is mainly
                            // caused by out of gas.
                            log::trace!(
                                "Precompile failed: code_address = {}, step.gas = {}",
                                code_address,
                                step.gas.0,
                            );
                            return Ok(Some(ExecError::PrecompileFailed));
                        }
                        pre_call => {
                            log::trace!(
                                "Precompile call failed: addr={:?}, step.gas={:?}",
                                pre_call,
                                step.gas.0
                            );
                            return Ok(None);
                        }
                    }
                }
            }

            return Err(Error::UnexpectedExecStepError(
                "*CALL*/CREATE* code not executed",
                Box::new(step.clone()),
            ));
        }

        Ok(None)
    }

    /// Expand memory of the call context when entering a new call context in
    /// case the call arguments or return arguments go beyond the call
    /// context current memory.
    pub(crate) fn call_expand_memory(
        &mut self,
        args_offset: usize,
        args_length: usize,
        ret_offset: usize,
        ret_length: usize,
    ) -> Result<(), Error> {
        let call_ctx = self.call_ctx_mut()?;
        let args_minimal = if args_length != 0 {
            args_offset + args_length
        } else {
            0
        };
        let ret_minimal = if ret_length != 0 {
            ret_offset + ret_length
        } else {
            0
        };
        if args_minimal != 0 || ret_minimal != 0 {
            let minimal_length = max(args_minimal, ret_minimal);
            call_ctx.memory.extend_at_least(minimal_length);
        }
        Ok(())
    }

    /// Generate copy steps for bytecode.
    pub(crate) fn gen_copy_steps_for_bytecode(
        &mut self,
        exec_step: &mut ExecStep,
        bytecode: &Bytecode,
        src_addr: impl Into<MemoryAddress>,
        dst_addr: impl Into<MemoryAddress>,
        copy_length: impl Into<MemoryAddress>,
    ) -> Result<(CopyEventSteps, CopyEventPrevBytes), Error> {
        let copy_length = copy_length.into().0;
        if copy_length == 0 {
            return Ok((vec![], vec![]));
        }

        let src_addr = src_addr.into().0;
        let (_, range, slot_bytes) = combine_copy_slot_bytes(
            src_addr,
            dst_addr.into().0,
            copy_length,
            &bytecode.code,
            &mut self.call_ctx_mut()?.memory,
        );

        let copy_steps = CopyEventStepsBuilder::new()
            .source(&bytecode.code[..])
            .mapper(|code: &BytecodeElement| (code.value, code.is_code))
            .padding_byte_getter(|_: &[BytecodeElement], idx| slot_bytes[idx])
            .read_offset(src_addr)
            .write_offset(range.shift())
            .step_length(range.full_length())
            .length(copy_length)
            .build();
        let mut prev_bytes: Vec<u8> = vec![];
        self.write_chunks(
            exec_step,
            &slot_bytes,
            range.start_slot().0,
            range.full_length().0,
            &mut prev_bytes,
        )?;

        Ok((copy_steps, prev_bytes))
    }

    pub(crate) fn gen_copy_steps_for_precompile_calldata(
        &mut self,
        exec_step: &mut ExecStep,
        src_addr: u64,
        copy_length: u64,
    ) -> Result<CopyEventSteps, Error> {
        if copy_length == 0 {
            return Ok(vec![]);
        }

        let range = MemoryWordRange::align_range(src_addr, copy_length);
        let slot_bytes = &self.caller_ctx()?.memory.read_chunk(range);

        let copy_steps = CopyEventStepsBuilder::memory_range(range)
            .source(slot_bytes.as_slice())
            .build();

        let mut chunk_index = range.start_slot().0;
        for chunk in slot_bytes.chunks(32) {
            let value = self.memory_read_caller(exec_step, chunk_index.into())?;
            debug_assert_eq!(Word::from_big_endian(chunk), value);
            chunk_index += 32;
        }

        Ok(copy_steps)
    }

    pub(crate) fn gen_copy_steps_for_precompile_callee_memory(
        &mut self,
        exec_step: &mut ExecStep,
        result: &[u8],
    ) -> Result<(CopyEventSteps, CopyEventPrevBytes), Error> {
        if result.is_empty() {
            return Ok((vec![], vec![]));
        }

        let range = MemoryWordRange::align_range(0, result.len());
        let copy_steps = CopyEventStepsBuilder::memory_range(range)
            .source(result)
            .build();

        let mut prev_bytes = vec![];
        self.write_chunks(exec_step, result, 0, range.full_length().0, &mut prev_bytes)?;

        Ok((copy_steps, prev_bytes))
    }

    pub(crate) fn gen_copy_steps_for_precompile_returndata(
        &mut self,
        exec_step: &mut ExecStep,
        dst_addr: impl Into<MemoryAddress>,
        copy_length: impl Into<MemoryAddress>,
        result: &[u8],
    ) -> Result<(CopyEventSteps, CopyEventSteps, CopyEventPrevBytes), Error> {
        let copy_length = copy_length.into().0;
        if copy_length == 0 {
            return Ok((vec![], vec![], vec![]));
        }
        assert!(copy_length <= result.len());

        let (src_range, dst_range, write_slot_bytes) = combine_copy_slot_bytes(
            0,
            dst_addr.into().0,
            copy_length,
            result,
            &mut self.caller_ctx_mut()?.memory,
        );

        let read_slot_bytes = MemoryRef(result).read_chunk(src_range);
        debug_assert_eq!(read_slot_bytes.len(), write_slot_bytes.len());

        let read_steps = CopyEventStepsBuilder::memory_range(src_range)
            .source(read_slot_bytes.as_slice())
            .build();

        let write_steps = CopyEventStepsBuilder::memory_range(dst_range)
            .source(write_slot_bytes.as_slice())
            .build();

        let mut src_chunk_index = src_range.start_slot().0;
        let mut dst_chunk_index = dst_range.start_slot().0;

        let mut prev_bytes = vec![];
        for (read_chunk, write_chunk) in read_slot_bytes.chunks(32).zip(write_slot_bytes.chunks(32))
        {
            let value = self.memory_read_word(exec_step, src_chunk_index.into())?;
            debug_assert_eq!(Word::from_big_endian(read_chunk), value);
            src_chunk_index += 32;

            let mut prev_bytes_write = self.memory_write_caller(
                exec_step,
                dst_chunk_index.into(),
                Word::from_big_endian(write_chunk),
            )?;
            prev_bytes.append(&mut prev_bytes_write);
            dst_chunk_index += 32;
        }

        Ok((read_steps, write_steps, prev_bytes))
    }

    /// Generate copy steps for call data.
    pub(crate) fn gen_copy_steps_for_call_data_root(
        &mut self,
        exec_step: &mut ExecStep,
        src_addr: impl Into<MemoryAddress>,
        dst_addr: impl Into<MemoryAddress>,
        copy_length: impl Into<MemoryAddress>,
    ) -> Result<(CopyEventSteps, CopyEventPrevBytes), Error> {
        assert!(self.call()?.is_root);

        let copy_length = copy_length.into().0;
        if copy_length == 0 {
            return Ok((vec![], vec![]));
        }

        let call_ctx = self.call_ctx_mut()?;
        let (_, range, slot_bytes) = combine_copy_slot_bytes(
            src_addr.into().0,
            dst_addr.into().0,
            copy_length,
            &call_ctx.call_data,
            &mut call_ctx.memory,
        );

        let copy_steps = CopyEventStepsBuilder::memory_range(range)
            .source(slot_bytes.as_slice())
            .build();
        let chunk_index = range.start_slot().0;
        let mut prev_bytes: Vec<u8> = vec![];
        self.write_chunks(
            exec_step,
            &slot_bytes,
            chunk_index,
            range.full_length().0,
            &mut prev_bytes,
        )?;

        Ok((copy_steps, prev_bytes))
    }

    pub(crate) fn gen_copy_steps_for_call_data_non_root(
        &mut self,
        exec_step: &mut ExecStep,
        src_addr: impl Into<MemoryAddress>,
        dst_addr: impl Into<MemoryAddress>,
        copy_length: impl Into<MemoryAddress>,
    ) -> Result<(CopyEventSteps, CopyEventSteps, Vec<u8>), Error> {
        assert!(!self.call()?.is_root);

        let copy_length = copy_length.into().0;
        if copy_length == 0 {
            return Ok((vec![], vec![], vec![]));
        }

        let caller_memory = self.caller_ctx()?.memory.clone();
        let call_data_length = self.call()?.call_data_length;
        let call_data_offset = self.call()?.call_data_offset;
        let call_data = if call_data_length != 0 {
            let ends = call_data_offset + call_data_length;
            &caller_memory.0[..ends as usize]
        } else {
            &caller_memory.0[..call_data_offset as usize]
        };
        let call_ctx = self.call_ctx_mut()?;
        let (src_range, dst_range, write_slot_bytes) = combine_copy_slot_bytes(
            src_addr.into().0,
            dst_addr.into().0,
            copy_length,
            call_data,
            &mut call_ctx.memory,
        );

        let read_slot_bytes = self.caller_ctx()?.memory.read_chunk(src_range);
        debug_assert_eq!(read_slot_bytes.len(), write_slot_bytes.len());

        let read_steps = CopyEventStepsBuilder::memory_range(src_range)
            .source(read_slot_bytes.as_slice())
            .build();
        let write_steps = CopyEventStepsBuilder::memory_range(dst_range)
            .source(write_slot_bytes.as_slice())
            .build();

        let mut src_chunk_index = src_range.start_slot().0;
        let mut dst_chunk_index = dst_range.start_slot().0;
        let mut prev_bytes: Vec<u8> = vec![];
        // memory word reads from source and writes to destination word
        for write_chunk in write_slot_bytes.chunks(32) {
            self.memory_read_caller(exec_step, src_chunk_index.into())?;

            src_chunk_index += 32;
            self.write_chunk_for_copy_step(
                exec_step,
                write_chunk,
                dst_chunk_index,
                &mut prev_bytes,
            )?;

            dst_chunk_index += 32;
        }

        Ok((read_steps, write_steps, prev_bytes))
    }

    pub(crate) fn gen_copy_steps_for_return_data(
        &mut self,
        exec_step: &mut ExecStep,
        src_addr: impl Into<MemoryAddress>,
        dst_addr: impl Into<MemoryAddress>,
        copy_length: impl Into<MemoryAddress>,
    ) -> Result<(CopyEventSteps, CopyEventSteps, Vec<u8>), Error> {
        let copy_length = copy_length.into().0;
        if copy_length == 0 {
            return Ok((vec![], vec![], vec![]));
        }

        let last_callee_memory = self.call()?.last_callee_memory.clone();
        let return_data_length = self.call()?.last_callee_return_data_length;
        let return_data_offset = self.call()?.last_callee_return_data_offset;
        let return_data: &[u8] = if return_data_length != 0 {
            let ends = return_data_offset + return_data_length;
            &last_callee_memory.0[..ends as usize]
        } else {
            &last_callee_memory.0[..return_data_offset as usize]
        };
        let call_ctx = self.call_ctx_mut()?;
        let (src_range, dst_range, write_slot_bytes) = combine_copy_slot_bytes(
            src_addr.into().0,
            dst_addr.into().0,
            copy_length,
            return_data,
            &mut call_ctx.memory,
        );
        let read_slot_bytes = self.call()?.last_callee_memory.read_chunk(src_range);

        let read_steps = CopyEventStepsBuilder::memory_range(src_range)
            .source(read_slot_bytes.as_slice())
            .build();
        let write_steps = CopyEventStepsBuilder::memory_range(dst_range)
            .source(write_slot_bytes.as_slice())
            .build();

        let mut src_chunk_index = src_range.start_slot().0;
        let mut dst_chunk_index = dst_range.start_slot().0;
        let mut prev_bytes: Vec<u8> = vec![];
        // memory word reads from source and writes to destination word
        let last_callee_id = self.call()?.last_callee_id;
        for (read_chunk, write_chunk) in read_slot_bytes.chunks(32).zip(write_slot_bytes.chunks(32))
        {
            self.push_op(
                exec_step,
                RW::READ,
                MemoryOp::new(
                    last_callee_id,
                    src_chunk_index.into(),
                    Word::from_big_endian(read_chunk),
                ),
            )?;
            trace!("read chunk: {last_callee_id} {src_chunk_index} {read_chunk:?}");
            src_chunk_index += 32;

            self.write_chunk_for_copy_step(
                exec_step,
                write_chunk,
                dst_chunk_index,
                &mut prev_bytes,
            )?;

            dst_chunk_index += 32;
        }

        Ok((read_steps, write_steps, prev_bytes))
    }

    pub(crate) fn gen_copy_steps_for_log(
        &mut self,
        exec_step: &mut ExecStep,
        src_addr: u64,
        bytes_left: u64,
    ) -> Result<(CopyEventSteps, CopyEventSteps), Error> {
        if bytes_left == 0 {
            return Ok((vec![], vec![]));
        }

        let src_range = MemoryWordRange::align_range(src_addr, bytes_left);

        // Read the aligned memory content.
        let memory = &self.call_ctx()?.memory;
        let read_slot_bytes = memory.read_chunk(src_range);

        // Read the actual log data and pad it with zeros.
        let mut log_slot_bytes =
            memory.read_chunk(MemoryRange::new_with_length(src_addr, bytes_left));
        log_slot_bytes.resize(src_range.full_length().0, 0);

        let mut chunk_index = src_range.start_slot().0;
        // memory word writes to destination word
        for chunk in log_slot_bytes.chunks(32) {
            let dest_word = Word::from_big_endian(chunk);
            // read memory
            self.memory_read_word(exec_step, chunk_index.into())?;
            // write log
            // TODO: this write an empty log slot when memory was not aligned. Should we skip it?
            self.tx_log_write(
                exec_step,
                self.tx_ctx.id(),
                self.tx_ctx.log_id + 1,
                TxLogField::Data,
                chunk_index - src_range.start_slot().0,
                dest_word,
            )?;
            chunk_index += 32;
        }

        let read_steps = CopyEventStepsBuilder::memory_range(src_range)
            .source(read_slot_bytes.as_slice())
            .build();

        let write_steps = CopyEventStepsBuilder::memory()
            .source(log_slot_bytes.as_slice())
            .read_offset(0)
            .write_offset(0)
            .step_length(log_slot_bytes.len())
            .length(bytes_left)
            .build();

        Ok((read_steps, write_steps))
    }

    /// write work chunk to RW table and add prev bytes
    pub(crate) fn write_chunk_for_copy_step(
        &mut self,
        exec_step: &mut ExecStep,
        write_chunk: &[u8],
        dst_chunk_index: usize,
        prev_bytes: &mut Vec<u8>,
    ) -> Result<(), Error> {
        assert_eq!(write_chunk.len(), 32);
        let write_word = Word::from_big_endian(write_chunk);
        let mut prev_bytes_write =
            self.memory_write_word(exec_step, dst_chunk_index.into(), write_word)?;
        prev_bytes.append(&mut prev_bytes_write);
        //trace!("write chunk: {} {dst_chunk_index} {write_chunk:?}", self.call()?.call_id);

        Ok(())
    }

    // write all chunks to memroy word and add prev bytes
    pub(crate) fn write_chunks(
        &mut self,
        exec_step: &mut ExecStep,
        chunks: &[u8],
        chunk_index: usize,
        full_length: usize,
        result: &mut Vec<u8>,
    ) -> Result<(), Error> {
        assert!(full_length >= chunks.len() && full_length % 32 == 0);
        let padding: Vec<_> = repeat(0).take(full_length - chunks.len()).collect();

        let mut chunk_index = chunk_index;
        for chunk in [chunks, &padding].concat().chunks(32) {
            self.write_chunk_for_copy_step(exec_step, chunk, chunk_index, result)?;
            chunk_index += 32;
        }

        Ok(())
    }
}

// Return source range, destination range and destination slot bytes.
fn combine_copy_slot_bytes(
    src_addr: usize,
    dst_addr: usize,
    copy_length: usize,
    src_data: &[impl Into<u8> + Clone],
    dst_memory: &mut Memory,
) -> (MemoryWordRange, MemoryWordRange, Vec<u8>) {
    let mut src_range = MemoryWordRange::align_range(src_addr, copy_length);
    let mut dst_range = MemoryWordRange::align_range(dst_addr, copy_length);
    src_range.ensure_equal_length(&mut dst_range);

    // Extend call memory.
    dst_memory.extend_for_range(dst_addr.into(), copy_length.into());
    let dst_begin_slot = dst_range.start_slot().0;
    let dst_end_slot = dst_range.end_slot().0;

    let src_data_length = src_data.len();
    let src_addr = src_addr.min(src_data_length);
    let src_copy_end = src_addr + copy_length;
    let src_addr_end = src_copy_end.min(src_data_length);
    let dst_copy_end = dst_addr + copy_length;
    let dst_addr_end = dst_end_slot.min(dst_memory.len());

    // Combine the destination slot bytes.
    let bytes_to_copy: Vec<_> = src_data[src_addr..src_addr_end]
        .iter()
        .cloned()
        .map(Into::into)
        .collect();
    let copy_padding_bytes = repeat(0).take(src_copy_end - src_addr_end);
    let end_padding_bytes = repeat(0).take(dst_end_slot - dst_addr_end);
    let slot_bytes: Vec<u8> = dst_memory[dst_begin_slot..dst_addr]
        .iter()
        .cloned()
        .chain(bytes_to_copy)
        .chain(copy_padding_bytes)
        .chain(dst_memory[dst_copy_end..dst_addr_end].iter().cloned())
        .chain(end_padding_bytes)
        .collect();

    (src_range, dst_range, slot_bytes)
}
