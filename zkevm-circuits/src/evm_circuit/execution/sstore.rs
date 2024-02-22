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
                ConstrainBuilderCommon, EVMConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::Delta,
            },
            math_gadget::{IsEqualWordGadget, IsZeroWordGadget, LtGadget},
            not, CachedRegion, Cell, U64Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{
        word::{Word, Word32Cell, WordCell, WordExpr},
        Expr,
    },
};

use eth_types::{evm_types::GasCost, Field};
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
    callee_address: WordCell<F>,
    //phase2_key
    key: Word32Cell<F>,
    //phase2_value
    value: Word32Cell<F>,
    // phase2_value_prev
    value_prev: Word32Cell<F>,
    // phase2_original_value
    original_value: Word32Cell<F>,
    is_warm: Cell<F>,
    tx_refund_prev: U64Cell<F>,
    // Constrain for SSTORE reentrancy sentry.
    sufficient_gas_sentry: LtGadget<F, N_BYTES_GAS>,
    gas_cost: SstoreGasGadget<F, Word32Cell<F>>,
    tx_refund: SstoreTxRefundGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for SstoreGadget<F> {
    const NAME: &'static str = "SSTORE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SSTORE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);

        // constrain not in static call
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);
        cb.require_zero("is_static is false", is_static.expr());

        let mut reversion_info = cb.reversion_info_read(None);
        let callee_address = cb.call_context_read_as_word(None, CallContextFieldTag::CalleeAddress);

        let key = cb.query_word32();
        // Pop the key from the stack
        cb.stack_pop(key.to_word());

        let value = cb.query_word32();
        // Pop the value from the stack
        cb.stack_pop(value.to_word());

        let value_prev = cb.query_word32();
        let original_value = cb.query_word32();
        cb.account_storage_write(
            callee_address.to_word(),
            key.to_word(),
            value.to_word(),
            value_prev.to_word(),
            tx_id.expr(),
            original_value.to_word(),
            Some(&mut reversion_info),
        );

        let is_warm = cb.query_bool();
        cb.account_storage_access_list_read(
            tx_id.expr(),
            callee_address.to_word(),
            key.to_word(),
            Word::from_lo_unchecked(is_warm.expr()),
        );
        cb.account_storage_access_list_write(
            tx_id.expr(),
            callee_address.to_word(),
            key.to_word(),
            Word::from_lo_unchecked(true.expr()),
            Word::from_lo_unchecked(is_warm.expr()),
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
            is_warm.clone(),
            value.clone(),
            value_prev.clone(),
            original_value.clone(),
        );

        let tx_refund_prev = cb.query_u64();
        let tx_refund = SstoreTxRefundGadget::construct(
            cb,
            tx_refund_prev.clone(),
            value.clone(),
            value_prev.clone(),
            original_value.clone(),
        );
        cb.tx_refund_write(
            tx_id.expr(),
            Word::from_lo_unchecked(tx_refund.expr()),
            tx_refund_prev.to_word(),
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
            key,
            value,
            value_prev,
            original_value,
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
        self.callee_address
            .assign_h160(region, offset, call.callee_address)?;

        let [key, value] =
            [step.rw_indices[5], step.rw_indices[6]].map(|idx| block.rws[idx].stack_value());
        self.key.assign_u256(region, offset, key)?;
        self.value.assign_u256(region, offset, value)?;

        let (_, value_prev, _, original_value) = block.rws[step.rw_indices[7]].storage_value_aux();
        self.value_prev.assign_u256(region, offset, value_prev)?;
        self.original_value
            .assign_u256(region, offset, original_value)?;

        let (_, is_warm) = block.rws[step.rw_indices[8]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        let (tx_refund, tx_refund_prev) = block.rws[step.rw_indices[10]].tx_refund_value_pair();
        self.tx_refund_prev
            .assign(region, offset, Some(tx_refund_prev.to_le_bytes()))?;

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
    tx_refund_old: U64Cell<F>,
    tx_refund_new: Expression<F>,
    value_prev_is_zero_gadget: IsZeroWordGadget<F, Word<Expression<F>>>,
    value_is_zero_gadget: IsZeroWordGadget<F, Word<Expression<F>>>,
    original_is_zero_gadget: IsZeroWordGadget<F, Word<Expression<F>>>,
    original_eq_value_gadget: IsEqualWordGadget<F, Word<Expression<F>>, Word<Expression<F>>>,
    prev_eq_value_gadget: IsEqualWordGadget<F, Word<Expression<F>>, Word<Expression<F>>>,
    original_eq_prev_gadget: IsEqualWordGadget<F, Word<Expression<F>>, Word<Expression<F>>>,
}

impl<F: Field> SstoreTxRefundGadget<F> {
    pub(crate) fn construct<T: WordExpr<F>>(
        cb: &mut EVMConstraintBuilder<F>,
        tx_refund_old: U64Cell<F>,
        value: T,
        value_prev: T,
        original_value: T,
    ) -> Self {
        let value_prev_is_zero_gadget = IsZeroWordGadget::construct(cb, &value_prev.to_word());
        let value_is_zero_gadget = IsZeroWordGadget::construct(cb, &value.to_word());
        let original_is_zero_gadget = IsZeroWordGadget::construct(cb, &original_value.to_word());

        let original_eq_value_gadget =
            IsEqualWordGadget::construct(cb, &original_value.to_word(), &value.to_word());
        let prev_eq_value_gadget =
            IsEqualWordGadget::construct(cb, &value_prev.to_word(), &value.to_word());
        let original_eq_prev_gadget =
            IsEqualWordGadget::construct(cb, &original_value.to_word(), &value_prev.to_word());

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
            .assign(region, offset, Some(tx_refund_old.to_le_bytes()))?;
        self.value_prev_is_zero_gadget
            .assign(region, offset, Word::from(value_prev))?;
        self.value_is_zero_gadget
            .assign(region, offset, Word::from(value))?;
        self.original_is_zero_gadget
            .assign(region, offset, Word::from(original_value))?;
        self.original_eq_value_gadget.assign(
            region,
            offset,
            Word::from(original_value),
            Word::from(value),
        )?;
        self.prev_eq_value_gadget.assign(
            region,
            offset,
            Word::from(value_prev),
            Word::from(value),
        )?;
        self.original_eq_prev_gadget.assign(
            region,
            offset,
            Word::from(original_value),
            Word::from(value_prev),
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
