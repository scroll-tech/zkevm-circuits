use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::CallContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            select, Cell, Word,
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
pub(crate) struct SstoreGadget<F> {
    same_context: SameContextGadget<F>,
    call_id: Cell<F>,
    tx_id: Cell<F>,
    rw_counter_end_of_reversion: Cell<F>,
    is_persistent: Cell<F>,
    callee_address: Cell<F>,
    key: Word<F>,
    value: Word<F>,
    committed_value: Word<F>,
    is_warm: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for SstoreGadget<F> {
    const NAME: &'static str = "SSTORE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SSTORE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let call_id = cb.query_cell();
        let [tx_id, rw_counter_end_of_reversion, is_persistent, callee_address] = [
            CallContextFieldTag::TxId,
            CallContextFieldTag::RwCounterEndOfReversion,
            CallContextFieldTag::IsPersistent,
            CallContextFieldTag::CalleeAddress,
        ]
        .map(|field_tag| cb.call_context(Some(call_id.expr()), field_tag));
        
        let key = cb.query_word();
        // Pop the key from the stack
        cb.stack_pop(key.expr());
        
        let value = cb.query_word();
        // Pop the value from the stack
        cb.stack_pop(key.expr());

        let value_prev = cb.query_word();
        let committed_value = cb.query_word();
        cb.account_storage_write_with_reversion(
            callee_address.expr(),
            key.expr(),
            value.expr(),
            value_prev.expr(),
            tx_id.expr(),
            committed_value.expr(),
            is_persistent.expr(),
            rw_counter_end_of_reversion.expr(),
        );

        let is_warm = cb.query_bool();
        cb.account_storage_access_list_write_with_reversion(
            tx_id.expr(),
            callee_address.expr(),
            key.expr(),
            true.expr(),
            is_warm.expr(),
            is_persistent.expr(),
            rw_counter_end_of_reversion.expr(),
        );

        // TODO:
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(8.expr()),
            program_counter: Delta(1.expr()),
            state_write_counter: To(1.expr()),
            ..Default::default()
        };
        let gas_cost = SstoreGasGadget::construct(cb, is_warm.expr());
        // TODO: gas_refund
        let same_context =
            SameContextGadget::construct(cb, opcode, step_state_transition, Some(gas_cost.expr()));

        Self {
            same_context,
            call_id,
            tx_id,
            rw_counter_end_of_reversion,
            is_persistent,
            callee_address,
            key,
            value,
            committed_value,
            is_warm,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction<F>,
        call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        // TODO:
        Ok(())
    }
}

// TODO:
#[derive(Clone, Debug)]
pub(crate) struct SstoreGasGadget<F> {
    is_warm: Expression<F>,
    gas_cost: Expression<F>,
}

// TODO:
impl<F: FieldExt> SstoreGasGadget<F> {
    pub(crate) fn construct(_cb: &mut ConstraintBuilder<F>, is_warm: Expression<F>) -> Self {
        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_STORAGE_READ_COST.expr(),
            GasCost::COLD_SLOAD_COST.expr(),
        );

        Self { is_warm, gas_cost }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        // Return the gas cost
        self.gas_cost.clone()
    }
}
