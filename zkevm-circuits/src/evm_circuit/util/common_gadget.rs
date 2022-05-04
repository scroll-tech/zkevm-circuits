use crate::{
    evm_circuit::{
        param::N_BYTES_GAS,
        table::{AccountFieldTag, CallContextFieldTag, FixedTableTag, Lookup},
        util::{
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{self, To},
            },
            math_gadget::{AddWordsGadget, RangeCheckGadget},
            Cell, Word,
        },
        witness::{Block, Call, ExecStep},
    },
    util::Expr,
};
use eth_types::{Field, ToLittleEndian, ToScalar, U256};
use halo2_proofs::{
    circuit::Region,
    plonk::{Error, Expression},
};
use std::convert::TryInto;

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
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Some(F::from(opcode.as_u64())))?;

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
    caller_code_source: Cell<F>,
    caller_program_counter: Cell<F>,
    caller_stack_pointer: Cell<F>,
    caller_gas_left: Cell<F>,
    caller_memory_word_size: Cell<F>,
    caller_reversible_write_counter: Cell<F>,
}

impl<F: Field> RestoreContextGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        rw_counter: Transition<Expression<F>>,
        return_data_offset: Expression<F>,
        return_data_length: Expression<F>,
    ) -> Self {
        // Read caller's context for restore
        let caller_id = cb.call_context(None, CallContextFieldTag::CallerId);
        let [caller_is_root, caller_is_create, caller_code_source, caller_program_counter, caller_stack_pointer, caller_gas_left, caller_memory_word_size, caller_reversible_write_counter] =
            [
                CallContextFieldTag::IsRoot,
                CallContextFieldTag::IsCreate,
                CallContextFieldTag::CodeSource,
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
                return_data_length,
            ),
        ] {
            cb.call_context_lookup(true.expr(), Some(caller_id.expr()), field_tag, value);
        }

        // Consume all gas_left if call halts in exception
        let gas_left = if cb.execution_state().halts_in_exception() {
            caller_gas_left.expr()
        } else {
            caller_gas_left.expr() + cb.curr.state.gas_left.expr()
        };

        // Accumulate reversible_write_counter in case this call stack reverts in the
        // future even it itself succeeds. Note that when sub-call halts in
        // failure, we don't need to accumulate reversible_write_counter because
        // what happened in the sub-call has been reverted.
        let reversible_write_counter = if cb.execution_state().halts_in_success() {
            caller_reversible_write_counter.expr() + cb.curr.state.reversible_write_counter.expr()
        } else {
            caller_reversible_write_counter.expr()
        };

        // Do step state transition
        cb.require_step_state_transition(StepStateTransition {
            rw_counter,
            call_id: To(caller_id.expr()),
            is_root: To(caller_is_root.expr()),
            is_create: To(caller_is_create.expr()),
            code_source: To(caller_code_source.expr()),
            program_counter: To(caller_program_counter.expr()),
            stack_pointer: To(caller_stack_pointer.expr()),
            gas_left: To(gas_left.expr()),
            memory_word_size: To(caller_memory_word_size.expr()),
            reversible_write_counter: To(reversible_write_counter),
        });

        Self {
            caller_id,
            caller_is_root,
            caller_is_create,
            caller_code_source,
            caller_program_counter,
            caller_stack_pointer,
            caller_gas_left,
            caller_memory_word_size,
            caller_reversible_write_counter,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let [caller_id, caller_is_root, caller_is_create, caller_code_source, caller_program_counter, caller_stack_pointer, caller_gas_left, caller_memory_word_size, caller_reversible_write_counter] =
            if call.is_root {
                [U256::zero(); 9]
            } else {
                [
                    step.rw_indices[1],
                    step.rw_indices[2],
                    step.rw_indices[3],
                    step.rw_indices[4],
                    step.rw_indices[5],
                    step.rw_indices[6],
                    step.rw_indices[7],
                    step.rw_indices[8],
                    step.rw_indices[9],
                ]
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
            cell.assign(region, offset, value.to_scalar())?;
        }

        self.caller_code_source.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                caller_code_source.to_le_bytes(),
                block.randomness,
            )),
        )?;

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

        let balance_addend = cb.query_word();
        let balance_sum = cb.query_word();

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
        region: &mut Region<'_, F>,
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
        region: &mut Region<'_, F>,
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

    pub(crate) fn receiver(&self) -> &UpdateBalanceGadget<F, 2, true> {
        &self.receiver
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
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
