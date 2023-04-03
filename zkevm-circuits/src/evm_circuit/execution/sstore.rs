use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::{
                cal_sstore_gas_cost_for_assignment, SameContextGadget, SstoreGasGadget,
            },
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition, Transition::Delta,
            },
            math_gadget::{IsEqualGadget, IsZeroGadget, LtGadget},
            not, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};

use eth_types::{evm_types::GasCost, Field, ToScalar};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct SstoreGadget<F> {
    same_context: SameContextGadget<F>,
    tx_id: Cell<F>,
    is_static: Cell<F>,
    reversion_info: ReversionInfo<F>,
    callee_address: Cell<F>,
    phase2_key: Cell<F>,
    phase2_value: Cell<F>,
    phase2_value_prev: Cell<F>,
    phase2_original_value: Cell<F>,
    is_warm: Cell<F>,
    tx_refund_prev: Cell<F>,
    // Constrain for SSTORE reentrancy sentry.
    sufficient_gas_sentry: LtGadget<F, N_BYTES_GAS>,
    gas_cost: SstoreGasGadget<F>,
    tx_refund: SstoreTxRefundGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for SstoreGadget<F> {
    const NAME: &'static str = "SSTORE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SSTORE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);

        // constrain not in static call
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);
        cb.require_zero("is_static is false", is_static.expr());

        let mut reversion_info = cb.reversion_info_read(None);
        let callee_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);

        let phase2_key = cb.query_cell_phase2();
        // Pop the key from the stack
        cb.stack_pop(phase2_key.expr());

        let phase2_value = cb.query_cell_phase2();
        // Pop the value from the stack
        cb.stack_pop(phase2_value.expr());

        let phase2_value_prev = cb.query_cell_phase2();
        let phase2_original_value = cb.query_cell_phase2();
        cb.account_storage_write(
            callee_address.expr(),
            phase2_key.expr(),
            phase2_value.expr(),
            phase2_value_prev.expr(),
            tx_id.expr(),
            phase2_original_value.expr(),
            Some(&mut reversion_info),
        );

        let is_warm = cb.query_bool();
        cb.account_storage_access_list_read(
            tx_id.expr(),
            callee_address.expr(),
            phase2_key.expr(),
            is_warm.expr(),
        );
        cb.account_storage_access_list_write(
            tx_id.expr(),
            callee_address.expr(),
            phase2_key.expr(),
            true.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );

        // Constrain for SSTORE reentrancy sentry.
        let sufficient_gas_sentry = LtGadget::construct(
            cb,
            GasCost::SSTORE_SENTRY.0.expr(),
            cb.curr.state.gas_left.expr(),
        );
        cb.require_equal(
            "Gas left must be greater than gas sentry",
            sufficient_gas_sentry.expr(),
            1.expr(),
        );

        let gas_cost = SstoreGasGadget::construct(
            cb,
            phase2_value.clone(),
            phase2_value_prev.clone(),
            phase2_original_value.clone(),
            is_warm.clone(),
        );

        let tx_refund_prev = cb.query_cell();
        let tx_refund = SstoreTxRefundGadget::construct(
            cb,
            tx_refund_prev.clone(),
            phase2_value.clone(),
            phase2_value_prev.clone(),
            phase2_original_value.clone(),
        );
        cb.tx_refund_write(
            tx_id.expr(),
            tx_refund.expr(),
            tx_refund_prev.expr(),
            Some(&mut reversion_info),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(11.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(2.expr()),
            reversible_write_counter: Delta(3.expr()),
            gas_left: Delta(-gas_cost.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            tx_id,
            is_static,
            reversion_info,
            callee_address,
            phase2_key,
            phase2_value,
            phase2_value_prev,
            phase2_original_value,
            is_warm,
            tx_refund_prev,
            sufficient_gas_sentry,
            gas_cost,
            tx_refund,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.is_static
            .assign(region, offset, Value::known(F::from(call.is_static as u64)))?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.callee_address.assign(
            region,
            offset,
            Value::known(
                call.callee_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;

        let [key, value] =
            [step.rw_indices[5], step.rw_indices[6]].map(|idx| block.rws[idx].stack_value());
        self.phase2_key
            .assign(region, offset, region.word_rlc(key))?;
        self.phase2_value
            .assign(region, offset, region.word_rlc(value))?;

        let (_, value_prev, _, original_value) = block.rws[step.rw_indices[7]].storage_value_aux();
        self.phase2_value_prev
            .assign(region, offset, region.word_rlc(value_prev))?;
        self.phase2_original_value
            .assign(region, offset, region.word_rlc(original_value))?;

        let (_, is_warm) = block.rws[step.rw_indices[8]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        let (tx_refund, tx_refund_prev) = block.rws[step.rw_indices[10]].tx_refund_value_pair();
        self.tx_refund_prev
            .assign(region, offset, Value::known(F::from(tx_refund_prev)))?;

        self.sufficient_gas_sentry.assign_value(
            region,
            offset,
            Value::known(F::from(GasCost::SSTORE_SENTRY.0)),
            Value::known(F::from(step.gas_left)),
        )?;

        self.gas_cost
            .assign(region, offset, value, value_prev, original_value, is_warm)?;
        debug_assert_eq!(
            cal_sstore_gas_cost_for_assignment(value, value_prev, original_value, is_warm),
            step.gas_cost,
            "invalid gas cost in sstore value {:?} value_prev {:?} original_value {:?} is_warm {:?} contract addr {:?} storage key {:?}",
            value, value_prev, original_value, is_warm, call.callee_address, key
        );

        self.tx_refund.assign(
            region,
            offset,
            tx_refund,
            tx_refund_prev,
            value,
            value_prev,
            original_value,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SstoreTxRefundGadget<F> {
    tx_refund_old: Cell<F>,
    tx_refund_new: Expression<F>,
    value: Cell<F>,
    value_prev: Cell<F>,
    original_value: Cell<F>,
    value_prev_is_zero_gadget: IsZeroGadget<F>,
    value_is_zero_gadget: IsZeroGadget<F>,
    original_is_zero_gadget: IsZeroGadget<F>,
    original_eq_value_gadget: IsEqualGadget<F>,
    prev_eq_value_gadget: IsEqualGadget<F>,
    original_eq_prev_gadget: IsEqualGadget<F>,
}

impl<F: Field> SstoreTxRefundGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        tx_refund_old: Cell<F>,
        value: Cell<F>,
        value_prev: Cell<F>,
        original_value: Cell<F>,
    ) -> Self {
        let value_prev_is_zero_gadget = IsZeroGadget::construct(cb, value_prev.expr());
        let value_is_zero_gadget = IsZeroGadget::construct(cb, value.expr());
        let original_is_zero_gadget = IsZeroGadget::construct(cb, original_value.expr());

        let original_eq_value_gadget =
            IsEqualGadget::construct(cb, original_value.expr(), value.expr());
        let prev_eq_value_gadget = IsEqualGadget::construct(cb, value_prev.expr(), value.expr());
        let original_eq_prev_gadget =
            IsEqualGadget::construct(cb, original_value.expr(), value_prev.expr());

        let value_prev_is_zero = value_prev_is_zero_gadget.expr();
        let value_is_zero = value_is_zero_gadget.expr();
        let original_is_zero = original_is_zero_gadget.expr();

        let original_eq_value = original_eq_value_gadget.expr();
        let prev_eq_value = prev_eq_value_gadget.expr();
        let original_eq_prev = original_eq_prev_gadget.expr();

        // (value_prev != value) && (original_value != value) && (value ==
        // Word::from(0))
        let delete_slot =
            not::expr(prev_eq_value.clone()) * not::expr(original_is_zero.clone()) * value_is_zero;
        // (value_prev != value) && (original_value == value) && (original_value !=
        // Word::from(0))
        let reset_existing = not::expr(prev_eq_value.clone())
            * original_eq_value.clone()
            * not::expr(original_is_zero.clone());
        // (value_prev != value) && (original_value == value) && (original_value ==
        // Word::from(0))
        let reset_inexistent =
            not::expr(prev_eq_value.clone()) * original_eq_value * (original_is_zero);
        // (value_prev != value) && (original_value != value_prev) && (value_prev ==
        // Word::from(0))
        let recreate_slot =
            not::expr(prev_eq_value) * not::expr(original_eq_prev) * (value_prev_is_zero);

        let tx_refund_new = tx_refund_old.expr()
            + delete_slot * GasCost::SSTORE_CLEARS_SCHEDULE.expr()
            + reset_existing * (GasCost::SSTORE_RESET.expr() - GasCost::WARM_ACCESS.expr())
            + reset_inexistent * (GasCost::SSTORE_SET.expr() - GasCost::WARM_ACCESS.expr())
            - recreate_slot * (GasCost::SSTORE_CLEARS_SCHEDULE.expr());

        Self {
            value,
            value_prev,
            original_value,
            tx_refund_old,
            tx_refund_new,
            value_prev_is_zero_gadget,
            value_is_zero_gadget,
            original_is_zero_gadget,
            original_eq_value_gadget,
            prev_eq_value_gadget,
            original_eq_prev_gadget,
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        // Return the new tx_refund
        self.tx_refund_new.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        tx_refund: u64,
        tx_refund_old: u64,
        value: eth_types::Word,
        value_prev: eth_types::Word,
        original_value: eth_types::Word,
    ) -> Result<(), Error> {
        self.tx_refund_old
            .assign(region, offset, Value::known(F::from(tx_refund_old)))?;
        self.value.assign(region, offset, region.word_rlc(value))?;
        self.value_prev
            .assign(region, offset, region.word_rlc(value_prev))?;
        self.original_value
            .assign(region, offset, region.word_rlc(original_value))?;
        self.value_prev_is_zero_gadget
            .assign_value(region, offset, region.word_rlc(value_prev))?;
        self.value_is_zero_gadget
            .assign_value(region, offset, region.word_rlc(value))?;
        self.original_is_zero_gadget.assign_value(
            region,
            offset,
            region.word_rlc(original_value),
        )?;
        self.original_eq_value_gadget.assign_value(
            region,
            offset,
            region.word_rlc(original_value),
            region.word_rlc(value),
        )?;
        self.prev_eq_value_gadget.assign_value(
            region,
            offset,
            region.word_rlc(value_prev),
            region.word_rlc(value),
        )?;
        self.original_eq_prev_gadget.assign_value(
            region,
            offset,
            region.word_rlc(original_value),
            region.word_rlc(value_prev),
        )?;
        debug_assert_eq!(
            calc_expected_tx_refund(tx_refund_old, value, value_prev, original_value),
            tx_refund
        );
        Ok(())
    }
}

fn calc_expected_tx_refund(
    tx_refund_old: u64,
    value: eth_types::Word,
    value_prev: eth_types::Word,
    original_value: eth_types::Word,
) -> u64 {
    // Same clause tags(like "delete slot (2.1.2b)") used as [`makeGasSStoreFunc` in go-ethereum](https://github.com/ethereum/go-ethereum/blob/9fd8825d5a196edde6d8ef81382979875145b346/core/vm/operations_acl.go#L27)
    // Control flow of this function try to follow `makeGasSStoreFunc` for better
    // understanding and comparison.

    let mut tx_refund_new = tx_refund_old;

    // The "clearing slot refund" and "resetting value refund" are ADDED together,
    // they are NOT MUTUALLY EXCLUSIVE.
    // Search "Apply both of the following clauses" in EIP-2200 for more details.
    // There can be five total kinds of refund:
    // 1. -SSTORE_CLEARS_SCHEDULE
    // 2. SSTORE_CLEARS_SCHEDULE
    // 3. SSTORE_SET - WARM_ACCESS
    // 4. SSTORE_RESET - WARM_ACCESS
    // 5. -SSTORE_CLEARS_SCHEDULE + SSTORE_RESET - WARM_ACCESS
    // The last case can happen if (original_value, prev_value, value) be (v,0,v)
    // where v != 0,
    // then both "clearing slot refund" and "resetting value refund" are non zero.

    if value_prev != value {
        // refund related to clearing slot
        // "delete slot (2.1.2b)" can be safely merged in "delete slot (2.2.1.2)"
        if !original_value.is_zero() {
            if value_prev.is_zero() {
                // recreate slot (2.2.1.1)
                tx_refund_new -= GasCost::SSTORE_CLEARS_SCHEDULE.as_u64()
            }
            if value.is_zero() {
                // delete slot (2.2.1.2)
                tx_refund_new += GasCost::SSTORE_CLEARS_SCHEDULE.as_u64()
            }
        }

        // refund related to resetting value
        if original_value == value {
            if original_value.is_zero() {
                // reset to original inexistent slot (2.2.2.1)
                tx_refund_new += GasCost::SSTORE_SET.as_u64() - GasCost::WARM_ACCESS.as_u64();
            } else {
                // reset to original existing slot (2.2.2.2)
                tx_refund_new += GasCost::SSTORE_RESET.as_u64() - GasCost::WARM_ACCESS.as_u64();
            }
        }
    }

    tx_refund_new
}

#[cfg(test)]
mod test {

    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, Word};
    use mock::{test_ctx::helpers::tx_from_1_to_0, TestContext, MOCK_ACCOUNTS};

    #[test]
    fn sstore_gadget_no_refund() {
        // value_prev == value
        test_ok(
            0x030201.into(),
            0x060504.into(),
            0x060504.into(),
            0x060504.into(),
        );
    }

    #[test]
    fn sstore_gadget_delete_slot() {
        // value_prev != value, original_value != value, value == 0
        test_ok(
            0x030201.into(),
            0x0.into(),
            0x060505.into(),
            0x060506.into(),
        );
    }

    #[test]
    fn sstore_gadget_reset_existing() {
        // value_prev != value, original_value == value, original_value != 0
        test_ok(
            0x030201.into(),
            0x060504.into(),
            0x060505.into(),
            0x060504.into(),
        );
    }
    #[test]
    fn sstore_gadget_reset_inexistent() {
        // value_prev != value, original_value == value, original_value == 0
        test_ok(0x030201.into(), 0.into(), 0x060505.into(), 0.into());
    }

    #[test]
    fn sstore_gadget_recreate_slot() {
        // value_prev != value, original_value != value_prev, original_value != value,
        // value_prev == 0
        test_ok(
            0x030201.into(),
            0x060504.into(),
            0x0.into(),
            0x060506.into(),
        );
    }
    #[test]
    fn sstore_gadget_recreate_slot_and_reset_inexistent() {
        // value_prev != value, original_value != value_prev, original_value == value,
        // value_prev == 0
        test_ok(
            0x030201.into(),
            0x060504.into(),
            0x0.into(),
            0x060504.into(),
        );
    }

    fn test_ok(key: Word, value: Word, value_prev: Word, original_value: Word) {
        // Here we use two bytecodes to test both is_persistent(STOP) or not(REVERT)
        // Besides, in bytecode we use two SSTOREs,
        // the first SSTORE is used to test cold,  and the second is used to test warm
        let bytecode_success = bytecode! {
            PUSH32(value_prev)
            PUSH32(key)
            SSTORE
            PUSH32(value)
            PUSH32(key)
            SSTORE
            STOP
        };
        let bytecode_failure = bytecode! {
            PUSH32(value_prev)
            PUSH32(key)
            SSTORE
            PUSH32(value)
            PUSH32(key)
            SSTORE
            PUSH32(0)
            PUSH32(0)
            REVERT
        };
        for bytecode in [bytecode_success, bytecode_failure] {
            let ctx = TestContext::<2, 1>::new(
                None,
                |accs| {
                    accs[0]
                        .address(MOCK_ACCOUNTS[0])
                        .balance(Word::from(10u64.pow(19)))
                        .code(bytecode)
                        .storage(vec![(key, original_value)].into_iter());
                    accs[1]
                        .address(MOCK_ACCOUNTS[1])
                        .balance(Word::from(10u64.pow(19)));
                },
                tx_from_1_to_0,
                |block, _txs| block,
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        }
    }
}
