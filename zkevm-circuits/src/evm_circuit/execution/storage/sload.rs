use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::STACK_CAPACITY,
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::{SameContextGadget, TransferWithGasFeeGadget},
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
use eth_types::{evm_types::GasCost, ToLittleEndian, ToScalar};
use halo2::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct SloadGadget<F> {
    same_context: SameContextGadget<F>,
    // tx_id: Cell<F>,
    key: Word<F>,
    value: Word<F>,
    // committed_value: Word<F>,
    gas: SloadGasGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for SloadGadget<F> {
    const NAME: &'static str = "SLOAD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SLOAD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Use rw_counter of the step which triggers next call as its call_id.
        // let call_id = cb.curr.state.rw_counter.clone();
        // let [tx_id, rw_counter_end_of_reversion, is_persistent] = [
        //     CallContextFieldTag::TxId,
        //     CallContextFieldTag::RwCounterEndOfReversion,
        //     CallContextFieldTag::IsPersistent,
        // ]
        // .map(|field_tag| cb.call_context(Some(call_id.expr()), field_tag));
        // let tx_callee_address =
        //     cb.tx_context(tx_id.expr(), TxContextFieldTag::CalleeAddress);

        // TODO:
        let tx_callee_address = cb.query_word();
        let tx_id = 1;

        let key = cb.query_word();
        // Pop the key from the stack
        // TODO: 74
        cb.stack_pop(key.expr());

        let is_warm = cb.query_bool();
        cb.storage_slot_access_list_read(
            tx_id.expr(),
            tx_callee_address.expr(),
            key.expr(),
            is_warm.expr(),
        );

        let gas = SloadGasGadget::construct(cb, is_warm.expr());

        let value = cb.query_word();
        let committed_value = cb.query_word();
        cb.storage_slot_read(
            tx_callee_address.expr(),
            key.expr(),
            value.expr(),
            tx_id.expr(),
            committed_value.expr(),
        );

        // cb.storage_slot_access_list_write_with_reversion(
        //     tx_id.expr(),
        //     tx_callee_address.expr(),
        //     key.expr(),
        //     1.expr(),
        //     is_warm.expr(),
        //     true.expr(), // TODO: is_persistent.expr(),
        //     0.expr(), // TODO: rw_counter_end_of_reversion.expr(),
        // );

        cb.stack_push(value.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(4.expr()),      // TODO:
            program_counter: Delta(1.expr()), // TODO:
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            Some(gas.gas_cost().expr()),
        );

        Self {
            same_context: same_context,
            // tx_id: tx_id,
            key: key,
            value: value,
            // committed_value: committed_value,
            gas: gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction<F>,
        _call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [key, value] =
            [step.rw_indices[0], step.rw_indices[3]].map(|idx| block.rws[idx].stack_value());
        self.key.assign(region, offset, Some(key.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        // TODO:
        // self.gas.assign(region, offset,
        // ???

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SloadGasGadget<F> {
    is_warm: Expression<F>,
    gas_cost: Expression<F>,
}

impl<F: FieldExt> SloadGasGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, is_warm: Expression<F>) -> Self {
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
    use crate::evm_circuit::{test::rand_word, witness};
    use crate::test_util::run_test_circuits;
    use bus_mapping::evm::OpcodeId;
    use eth_types::{bytecode, Word};

    fn test_ok(key: Word, _value: Word) {
        let bytecode = bytecode! {
            // TODO: SSTORE first
            PUSH32(key)
            #[start]
            SLOAD
            STOP
        };
        assert_eq!(run_test_circuits(bytecode), Ok(()));
    }

    #[test]
    fn sload_gadget_simple() {
        test_ok(0x030201.into(), 0x060504.into());
        test_ok(0x090705.into(), 0x060504.into());
    }

    #[test]
    fn sload_gadget_rand() {
        let key = rand_word();
        let value = rand_word();
        test_ok(key, value);
        test_ok(key, value);
    }
}
