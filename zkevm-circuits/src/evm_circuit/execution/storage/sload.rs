use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{MAX_GAS_SIZE_IN_BYTES, STACK_CAPACITY},
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::TransferWithGasFeeGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            math_gadget::{MulWordByU64Gadget, RangeCheckGadget},
            select, Cell, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::{
    eth_types::{ToLittleEndian, ToScalar},
    evm::GasCost,
};
use halo2::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct SloadGadget<F> {
    tx_id: Cell<F>,
    storage_slot: Word<F>,
    value: Word<F>,
    committed_value: Word<F>,
    gas: SloadGasGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for SloadGadget<F> {
    const NAME: &'static str = "SLOAD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SLOAD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let call_id = cb.curr.state.rw_counter.clone();

        let [tx_id, rw_counter_end_of_reversion, is_persistent] = [
            CallContextFieldTag::TxId,
            CallContextFieldTag::RwCounterEndOfReversion,
            CallContextFieldTag::IsPersistent,
        ]
        .map(|field_tag| cb.call_context(Some(call_id.expr()), field_tag));

        let tx_callee_address =
            cb.tx_context(tx_id.expr(), TxContextFieldTag::CalleeAddress);

        let storage_slot = RandomLinearCombination::new(
            cb.query_bytes(),
            cb.power_of_randomness(),
        );
        // Pop the storage_slot from the stack
        cb.stack_pop(storage_slot.expr());

        let is_warm = cb.query_bool();
        cb.storage_slot_access_list_read(
            tx_id.expr(),
            tx_callee_address.expr(),
            storage_slot.expr(),
            is_warm.expr(),
        );

        let gas = SloadGasGadget::construct(cb, is_warm.expr());

        let value = RandomLinearCombination::new(
            cb.query_bytes(),
            cb.power_of_randomness(),
        );
        let committed_value = RandomLinearCombination::new(
            cb.query_bytes(),
            cb.power_of_randomness(),
        );
        cb.storage_slot_read(
            tx_callee_address.expr(),
            storage_slot.expr(),
            value.expr(),
            tx_id.expr(),
            committed_value.expr(),
        );

        cb.storage_slot_access_list_write_with_reversion(
            tx_id.expr(),
            tx_callee_address.expr(),
            storage_slot.expr(),
            1.expr(),
            is_warm.expr(),
            is_persistent.expr(),
            rw_counter_end_of_reversion.expr(),
        );

        cb.stack_push(value.expr());

        Self {
            tx_id: tx_id,
            storage_slot: storage_slot,
            value: value,
            committed_value: committed_value,
            gas: gas,
        }
    }

    fn assign_exec_step(
        &self,
        _region: &mut Region<'_, F>,
        _offset: usize,
        _block: &Block<F>,
        _tx: &Transaction<F>,
        _call: &Call<F>,
        _step: &ExecStep,
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SloadGasGadget<F> {
    is_warm: Expression<F>,
    gas_cost: Expression<F>,
}

impl<F: FieldExt> SloadGasGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        is_warm: Expression<F>,
    ) -> Self {
        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_STORAGE_READ_COST.expr(),
            GasCost::COLD_SLOAD_COST.expr(),
        );

        Self {
            is_warm: is_warm,
            gas_cost: gas_cost,
        }
    }

    pub(crate) fn gas_cost(&self) -> Expression<F> {
        // Return the gas cost
        self.gas_cost.clone()
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        witness,
    };
    use bus_mapping::{bytecode, eth_types::Word, evm::OpcodeId};

    fn test_ok(address: Word, _value: Word) {
        let bytecode = bytecode! {
            // TODO: SSTORE first
            PUSH32(address)
            #[start]
            SLOAD
            STOP
        };
        let block = witness::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn sload_gadget_simple() {
        test_ok(0x030201.into(), 0x060504.into());
        test_ok(0x090705.into(), 0x060504.into());
    }

    #[test]
    fn sload_gadget_rand() {
        let a = rand_word();
        let b = rand_word();
        test_ok(a, b);
        test_ok(a, b);
    }
}
