use super::{
    from_bytes,
    math_gadget::{IsEqualGadget, IsZeroGadget},
    memory_gadget::{MemoryAddressGadget, MemoryExpansionGadget},
    CachedRegion,
};
use crate::{
    evm_circuit::{
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
        table::{FixedTableTag, Lookup},
        util::{
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, Same, To},
            },
            math_gadget::{AddWordsGadget, RangeCheckGadget},
            not, Cell, CellType, Word,
        },
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
    witness::{Block, Call, ExecStep},
};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar, U256};
use gadgets::util::{select, sum};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Construction of execution state that stays in the same call context, which
/// lookups the opcode and verifies the execution state is responsible for it,
/// then calculates the gas_cost and constrain the state transition.
#[derive(Clone, Debug)]
pub(crate) struct SameContextGadget<F> {
    opcode: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, N_BYTES_GAS>,
}

impl<F: Field> SameContextGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        opcode: Cell<F>,
        step_state_transition: StepStateTransition<F>,
    ) -> Self {
        cb.opcode_lookup(opcode.expr(), 1.expr());
        cb.add_lookup(
            "Responsible opcode lookup",
            Lookup::Fixed {
                tag: FixedTableTag::ResponsibleOpcode.expr(),
                values: [
                    cb.execution_state().as_u64().expr(),
                    opcode.expr(),
                    0.expr(),
                ],
            },
        );

        // Check gas_left is sufficient
        let sufficient_gas_left = RangeCheckGadget::construct(cb, cb.next.state.gas_left.expr());

        // Do step state transition
        cb.require_step_state_transition(step_state_transition);

        Self {
            opcode,
            sufficient_gas_left,
        }
    }

    pub(crate) fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        self.sufficient_gas_left.assign(
            region,
            offset,
            F::from((step.gas_left - step.gas_cost) as u64),
        )?;

        Ok(())
    }
}

/// Construction of step state transition that restores caller's state.
#[derive(Clone, Debug)]
pub(crate) struct RestoreContextGadget<F> {
    caller_id: Cell<F>,
    caller_is_root: Cell<F>,
    caller_is_create: Cell<F>,
    caller_code_hash: Cell<F>,
    caller_program_counter: Cell<F>,
    caller_stack_pointer: Cell<F>,
    caller_gas_left: Cell<F>,
    caller_memory_word_size: Cell<F>,
    caller_reversible_write_counter: Cell<F>,
}

impl<F: Field> RestoreContextGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        is_success: Expression<F>,
        // Expression for the number of rw lookups that occur after this gadget is constructed.
        subsequent_rw_lookups: Expression<F>,
        return_data_offset: Expression<F>,
        return_data_length: Expression<F>,
        memory_expansion_cost: Expression<F>,
        reversible_write_counter_increase: Expression<F>,
    ) -> Self {
        // Read caller's context for restore
        let caller_id = cb.call_context(None, CallContextFieldTag::CallerId);
        let [caller_is_root, caller_is_create, caller_code_hash, caller_program_counter, caller_stack_pointer, caller_gas_left, caller_memory_word_size, caller_reversible_write_counter] =
            [
                CallContextFieldTag::IsRoot,
                CallContextFieldTag::IsCreate,
                CallContextFieldTag::CodeHash,
                CallContextFieldTag::ProgramCounter,
                CallContextFieldTag::StackPointer,
                CallContextFieldTag::GasLeft,
                CallContextFieldTag::MemorySize,
                CallContextFieldTag::ReversibleWriteCounter,
            ]
            .map(|field_tag| cb.call_context(Some(caller_id.expr()), field_tag));

        // Update caller's last callee information
        for (field_tag, value) in [
            (
                CallContextFieldTag::LastCalleeId,
                cb.curr.state.call_id.expr(),
            ),
            (
                CallContextFieldTag::LastCalleeReturnDataOffset,
                return_data_offset,
            ),
            (
                CallContextFieldTag::LastCalleeReturnDataLength,
                return_data_length.clone(),
            ),
        ] {
            cb.call_context_lookup(true.expr(), Some(caller_id.expr()), field_tag, value);
        }

        let code_deposit_cost = cb.curr.state.is_create.expr()
            * is_success.clone()
            * GasCost::CODE_DEPOSIT_BYTE_COST.expr()
            * return_data_length;

        let gas_refund = if cb.execution_state().halts_in_exception() {
            0.expr() // no gas refund if call halts in exception
        } else {
            cb.curr.state.gas_left.expr() - memory_expansion_cost - code_deposit_cost
        };

        let gas_left = caller_gas_left.expr() + gas_refund;

        // Accumulate reversible_write_counter in case this call stack reverts in the
        // future even it itself succeeds. Note that when sub-call halts in
        // failure, we don't need to accumulate reversible_write_counter because
        // what happened in the sub-call has been reverted.
        let reversible_write_counter = caller_reversible_write_counter.expr()
            + reversible_write_counter_increase
            + is_success.clone() * cb.curr.state.reversible_write_counter.expr();

        let rw_counter_offset = cb.rw_counter_offset()
            + subsequent_rw_lookups
            + not::expr(is_success.expr()) * cb.curr.state.reversible_write_counter.expr();

        // Do step state transition
        cb.require_step_state_transition(StepStateTransition {
            rw_counter: Delta(rw_counter_offset),
            call_id: To(caller_id.expr()),
            is_root: To(caller_is_root.expr()),
            is_create: To(caller_is_create.expr()),
            code_hash: To(caller_code_hash.expr()),
            program_counter: To(caller_program_counter.expr()),
            stack_pointer: To(caller_stack_pointer.expr()),
            gas_left: To(gas_left),
            memory_word_size: To(caller_memory_word_size.expr()),
            reversible_write_counter: To(reversible_write_counter),
            log_id: Same,
        });

        Self {
            caller_id,
            caller_is_root,
            caller_is_create,
            caller_code_hash,
            caller_program_counter,
            caller_stack_pointer,
            caller_gas_left,
            caller_memory_word_size,
            caller_reversible_write_counter,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        call: &Call,
        step: &ExecStep,
        rw_offset: usize,
    ) -> Result<(), Error> {
        let [caller_id, caller_is_root, caller_is_create, caller_code_hash, caller_program_counter, caller_stack_pointer, caller_gas_left, caller_memory_word_size, caller_reversible_write_counter] =
            if call.is_root {
                [U256::zero(); 9]
            } else {
                [0, 1, 2, 3, 4, 5, 6, 7, 8]
                    .map(|i| step.rw_indices[i + rw_offset])
                    .map(|idx| block.rws[idx].call_context_value())
            };

        for (cell, value) in [
            (&self.caller_id, caller_id),
            (&self.caller_is_root, caller_is_root),
            (&self.caller_is_create, caller_is_create),
            (&self.caller_program_counter, caller_program_counter),
            (&self.caller_stack_pointer, caller_stack_pointer),
            (&self.caller_gas_left, caller_gas_left),
            (&self.caller_memory_word_size, caller_memory_word_size),
            (
                &self.caller_reversible_write_counter,
                caller_reversible_write_counter,
            ),
        ] {
            cell.assign(
                region,
                offset,
                Value::known(
                    value
                        .to_scalar()
                        .expect("unexpected U256 -> Scalar conversion failure"),
                ),
            )?;
        }

        self.caller_code_hash
            .assign(region, offset, region.word_rlc(caller_code_hash))?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UpdateBalanceGadget<F, const N_ADDENDS: usize, const INCREASE: bool> {
    add_words: AddWordsGadget<F, N_ADDENDS, true>,
}

impl<F: Field, const N_ADDENDS: usize, const INCREASE: bool>
    UpdateBalanceGadget<F, N_ADDENDS, INCREASE>
{
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        address: Expression<F>,
        updates: Vec<Word<F>>,
        reversion_info: Option<&mut ReversionInfo<F>>,
    ) -> Self {
        debug_assert!(updates.len() == N_ADDENDS - 1);

        let balance_addend = cb.query_word_rlc();
        let balance_sum = cb.query_word_rlc();

        let [value, value_prev] = if INCREASE {
            [balance_sum.expr(), balance_addend.expr()]
        } else {
            [balance_addend.expr(), balance_sum.expr()]
        };

        let add_words = AddWordsGadget::construct(
            cb,
            std::iter::once(balance_addend)
                .chain(updates.to_vec())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            balance_sum,
        );

        cb.account_write(
            address,
            AccountFieldTag::Balance,
            value,
            value_prev,
            reversion_info,
        );

        Self { add_words }
    }

    pub(crate) fn balance(&self) -> &Word<F> {
        if INCREASE {
            self.add_words.sum()
        } else {
            &self.add_words.addends()[0]
        }
    }

    pub(crate) fn balance_prev(&self) -> &Word<F> {
        if INCREASE {
            &self.add_words.addends()[0]
        } else {
            self.add_words.sum()
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value_prev: U256,
        updates: Vec<U256>,
        value: U256,
    ) -> Result<(), Error> {
        debug_assert!(updates.len() + 1 == N_ADDENDS);

        let [value, value_prev] = if INCREASE {
            [value, value_prev]
        } else {
            [value_prev, value]
        };
        let mut addends = vec![value_prev];
        addends.extend(updates);
        self.add_words
            .assign(region, offset, addends.try_into().unwrap(), value)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TransferWithGasFeeGadget<F> {
    sender: UpdateBalanceGadget<F, 3, false>,
    receiver: UpdateBalanceGadget<F, 2, true>,
}

impl<F: Field> TransferWithGasFeeGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        sender_address: Expression<F>,
        receiver_address: Expression<F>,
        value: Word<F>,
        gas_fee: Word<F>,
        reversion_info: &mut ReversionInfo<F>,
    ) -> Self {
        let sender = UpdateBalanceGadget::construct(
            cb,
            sender_address,
            vec![value.clone(), gas_fee],
            Some(reversion_info),
        );
        let receiver =
            UpdateBalanceGadget::construct(cb, receiver_address, vec![value], Some(reversion_info));

        Self { sender, receiver }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        (sender_balance, sender_balance_prev): (U256, U256),
        (receiver_balance, receiver_balance_prev): (U256, U256),
        value: U256,
        gas_fee: U256,
    ) -> Result<(), Error> {
        self.sender.assign(
            region,
            offset,
            sender_balance_prev,
            vec![value, gas_fee],
            sender_balance,
        )?;
        self.receiver.assign(
            region,
            offset,
            receiver_balance_prev,
            vec![value],
            receiver_balance,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TransferGadget<F> {
    sender: UpdateBalanceGadget<F, 2, false>,
    receiver: UpdateBalanceGadget<F, 2, true>,
}

impl<F: Field> TransferGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        sender_address: Expression<F>,
        receiver_address: Expression<F>,
        value: Word<F>,
        reversion_info: &mut ReversionInfo<F>,
    ) -> Self {
        let sender = UpdateBalanceGadget::construct(
            cb,
            sender_address,
            vec![value.clone()],
            Some(reversion_info),
        );
        let receiver =
            UpdateBalanceGadget::construct(cb, receiver_address, vec![value], Some(reversion_info));

        Self { sender, receiver }
    }

    pub(crate) fn sender(&self) -> &UpdateBalanceGadget<F, 2, false> {
        &self.sender
    }

    pub(crate) fn receiver(&self) -> &UpdateBalanceGadget<F, 2, true> {
        &self.receiver
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        (sender_balance, sender_balance_prev): (U256, U256),
        (receiver_balance, receiver_balance_prev): (U256, U256),
        value: U256,
    ) -> Result<(), Error> {
        self.sender.assign(
            region,
            offset,
            sender_balance_prev,
            vec![value],
            sender_balance,
        )?;
        self.receiver.assign(
            region,
            offset,
            receiver_balance_prev,
            vec![value],
            receiver_balance,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CommonCallGadget<F, const IS_SUCCESS_CALL: bool> {
    pub is_success: Cell<F>,

    pub gas: Word<F>,
    pub gas_is_u64: IsZeroGadget<F>,
    pub callee_address: Word<F>,
    pub value: Word<F>,
    pub cd_address: MemoryAddressGadget<F>,
    pub rd_address: MemoryAddressGadget<F>,
    pub memory_expansion: MemoryExpansionGadget<F, 2, N_BYTES_MEMORY_WORD_SIZE>,

    value_is_zero: IsZeroGadget<F>,
    pub has_value: Expression<F>,
    pub phase2_callee_code_hash: Cell<F>,
    pub is_empty_code_hash: IsEqualGadget<F>,

    pub callee_not_exists: IsZeroGadget<F>,
}

impl<F: Field, const IS_SUCCESS_CALL: bool> CommonCallGadget<F, IS_SUCCESS_CALL> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        is_call: Expression<F>,
        is_callcode: Expression<F>,
        is_delegatecall: Expression<F>,
        is_staticcall: Expression<F>,
    ) -> Self {
        // Constrain opcode must be one of CALL, CALLCODE, DELEGATECALL or STATICCALL.
        cb.require_equal(
            "Opcode should be CALL, CALLCODE, DELEGATECALL or STATICCALL",
            is_call.expr() + is_callcode.expr() + is_delegatecall.expr() + is_staticcall.expr(),
            1.expr(),
        );

        let gas_word = cb.query_word_rlc();
        let callee_address_word = cb.query_word_rlc();
        let value = cb.query_word_rlc();
        let cd_offset = cb.query_cell_phase2();
        let cd_length = cb.query_word_rlc();
        let rd_offset = cb.query_cell_phase2();
        let rd_length = cb.query_word_rlc();
        let is_success = cb.query_bool();

        // Lookup values from stack
        // `callee_address` is poped from stack and used to check if it exists in
        // access list and get code hash.
        // For CALLCODE, both caller and callee addresses are `current_callee_address`.
        // For DELEGATECALL, caller address is `current_caller_address` and
        // callee address is `current_callee_address`.
        // For both CALL and STATICCALL, caller address is
        // `current_callee_address` and callee address is `callee_address`.
        cb.stack_pop(gas_word.expr());
        cb.stack_pop(callee_address_word.expr());

        // `CALL` and `CALLCODE` opcodes have an additional stack pop `value`.
        cb.condition(is_call + is_callcode, |cb| cb.stack_pop(value.expr()));
        cb.stack_pop(cd_offset.expr());
        cb.stack_pop(cd_length.expr());
        cb.stack_pop(rd_offset.expr());
        cb.stack_pop(rd_length.expr());
        cb.stack_push(if IS_SUCCESS_CALL {
            is_success.expr()
        } else {
            0.expr()
        });

        // Recomposition of random linear combination to integer
        let gas_is_u64 = IsZeroGadget::construct(cb, sum::expr(&gas_word.cells[N_BYTES_GAS..]));
        let cd_address = MemoryAddressGadget::construct(cb, cd_offset, cd_length);
        let rd_address = MemoryAddressGadget::construct(cb, rd_offset, rd_length);
        let memory_expansion =
            MemoryExpansionGadget::construct(cb, [cd_address.address(), rd_address.address()]);

        // construct common gadget
        let value_is_zero = IsZeroGadget::construct(cb, sum::expr(&value.cells));
        let has_value = select::expr(
            is_delegatecall.expr() + is_staticcall.expr(),
            0.expr(),
            1.expr() - value_is_zero.expr(),
        );

        let phase2_callee_code_hash = cb.query_cell_with_type(CellType::StoragePhase2);
        cb.account_read(
            from_bytes::expr(&callee_address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]),
            AccountFieldTag::CodeHash,
            phase2_callee_code_hash.expr(),
        );
        let is_empty_code_hash =
            IsEqualGadget::construct(cb, phase2_callee_code_hash.expr(), cb.empty_hash_rlc());
        let callee_not_exists = IsZeroGadget::construct(cb, phase2_callee_code_hash.expr());

        Self {
            is_success,
            callee_address: callee_address_word,
            gas: gas_word,
            gas_is_u64,
            value,
            cd_address,
            rd_address,
            memory_expansion,
            value_is_zero,
            has_value,
            phase2_callee_code_hash,
            is_empty_code_hash,
            callee_not_exists,
        }
    }

    pub fn callee_address_expr(&self) -> Expression<F> {
        from_bytes::expr(&self.callee_address.cells[..N_BYTES_ACCOUNT_ADDRESS])
    }

    pub fn gas_expr(&self) -> Expression<F> {
        from_bytes::expr(&self.gas.cells[..N_BYTES_GAS])
    }

    pub fn gas_cost_expr(
        &self,
        is_warm_prev: Expression<F>,
        is_call: Expression<F>,
    ) -> Expression<F> {
        select::expr(
            is_warm_prev,
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        ) + self.has_value.clone()
            * (GasCost::CALL_WITH_VALUE.expr()
                // Only CALL opcode could invoke transfer to make empty account into non-empty.
                + is_call * self.callee_not_exists.expr() * GasCost::NEW_ACCOUNT.expr())
            + self.memory_expansion.gas_cost()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        gas: U256,
        callee_address: U256,
        value: U256,
        is_success: U256,
        cd_offset: U256,
        cd_length: U256,
        rd_offset: U256,
        rd_length: U256,
        memory_word_size: u64,
        phase2_callee_code_hash: Value<F>,
    ) -> Result<u64, Error> {
        self.gas.assign(region, offset, Some(gas.to_le_bytes()))?;
        self.callee_address
            .assign(region, offset, Some(callee_address.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;
        if IS_SUCCESS_CALL {
            self.is_success
                .assign(region, offset, Value::known(F::from(is_success.low_u64())))?;
            self.gas_is_u64.assign(
                region,
                offset,
                sum::value(&gas.to_le_bytes()[N_BYTES_GAS..]),
            )?;
        }
        let cd_address = self
            .cd_address
            .assign(region, offset, cd_offset, cd_length)?;
        let rd_address = self
            .rd_address
            .assign(region, offset, rd_offset, rd_length)?;
        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            memory_word_size,
            [cd_address, rd_address],
        )?;

        self.value_is_zero
            .assign(region, offset, sum::value(&value.to_le_bytes()))?;
        self.phase2_callee_code_hash
            .assign(region, offset, phase2_callee_code_hash)?;
        self.is_empty_code_hash.assign_value(
            region,
            offset,
            phase2_callee_code_hash,
            region.empty_hash_rlc(),
        )?;
        self.callee_not_exists
            .assign_value(region, offset, phase2_callee_code_hash)?;
        Ok(memory_expansion_gas_cost)
    }

    pub(crate) fn cal_gas_cost_for_assignment(
        &self,
        memory_expansion_gas_cost: u64,
        is_warm_prev: bool,
        is_call: bool,
        has_value: bool,
        is_empty_account: bool,
    ) -> Result<u64, Error> {
        let gas_cost = if is_warm_prev {
            GasCost::WARM_ACCESS.as_u64()
        } else {
            GasCost::COLD_ACCOUNT_ACCESS.as_u64()
        } + if has_value {
            GasCost::CALL_WITH_VALUE.as_u64()
                // Only CALL opcode could invoke transfer to make empty account into non-empty.
                + if is_call && is_empty_account {
                    GasCost::NEW_ACCOUNT.as_u64()
                } else {
                    0
                }
        } else {
            0
        } + memory_expansion_gas_cost;

        Ok(gas_cost)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SloadGasGadget<F> {
    is_warm: Expression<F>,
    gas_cost: Expression<F>,
}

impl<F: Field> SloadGasGadget<F> {
    pub(crate) fn construct(_cb: &mut ConstraintBuilder<F>, is_warm: Expression<F>) -> Self {
        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_SLOAD.expr(),
        );

        Self { is_warm, gas_cost }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        // Return the gas cost
        self.gas_cost.clone()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SstoreGasGadget<F> {
    value: Cell<F>,
    value_prev: Cell<F>,
    original_value: Cell<F>,
    is_warm: Cell<F>,
    gas_cost: Expression<F>,
    value_eq_prev: IsEqualGadget<F>,
    original_eq_prev: IsEqualGadget<F>,
    original_is_zero: IsZeroGadget<F>,
}

impl<F: Field> SstoreGasGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        value: Cell<F>,
        value_prev: Cell<F>,
        original_value: Cell<F>,
        is_warm: Cell<F>,
    ) -> Self {
        let value_eq_prev = IsEqualGadget::construct(cb, value.expr(), value_prev.expr());
        let original_eq_prev =
            IsEqualGadget::construct(cb, original_value.expr(), value_prev.expr());
        let original_is_zero = IsZeroGadget::construct(cb, original_value.expr());
        let warm_case_gas = select::expr(
            value_eq_prev.expr(),
            GasCost::WARM_ACCESS.expr(),
            select::expr(
                original_eq_prev.expr(),
                select::expr(
                    original_is_zero.expr(),
                    GasCost::SSTORE_SET.expr(),
                    GasCost::SSTORE_RESET.expr(),
                ),
                GasCost::WARM_ACCESS.expr(),
            ),
        );
        let gas_cost = select::expr(
            is_warm.expr(),
            warm_case_gas.expr(),
            warm_case_gas + GasCost::COLD_SLOAD.expr(),
        );

        Self {
            value,
            value_prev,
            original_value,
            is_warm,
            gas_cost,
            value_eq_prev,
            original_eq_prev,
            original_is_zero,
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        // Return the gas cost
        self.gas_cost.clone()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: eth_types::Word,
        value_prev: eth_types::Word,
        original_value: eth_types::Word,
        is_warm: bool,
    ) -> Result<(), Error> {
        self.value.assign(region, offset, region.word_rlc(value))?;
        self.value_prev
            .assign(region, offset, region.word_rlc(value_prev))?;
        self.original_value
            .assign(region, offset, region.word_rlc(original_value))?;
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;
        self.value_eq_prev.assign_value(
            region,
            offset,
            region.word_rlc(value),
            region.word_rlc(value_prev),
        )?;
        self.original_eq_prev.assign_value(
            region,
            offset,
            region.word_rlc(original_value),
            region.word_rlc(value_prev),
        )?;
        self.original_is_zero
            .assign_value(region, offset, region.word_rlc(original_value))?;
        Ok(())
    }
}

pub(crate) fn cal_sload_gas_cost_for_assignment(is_warm: bool) -> u64 {
    let gas_cost = if is_warm {
        GasCost::WARM_ACCESS
    } else {
        GasCost::COLD_SLOAD
    };

    gas_cost.0
}

pub(crate) fn cal_sstore_gas_cost_for_assignment(
    value: U256,
    value_prev: U256,
    original_value: U256,
    is_warm: bool,
) -> u64 {
    let warm_case_gas = if value_prev == value {
        GasCost::WARM_ACCESS
    } else if original_value == value_prev {
        if original_value.is_zero() {
            GasCost::SSTORE_SET
        } else {
            GasCost::SSTORE_RESET
        }
    } else {
        GasCost::WARM_ACCESS
    };
    if is_warm {
        warm_case_gas.0
    } else {
        warm_case_gas.0 + GasCost::COLD_SLOAD.0
    }
}
