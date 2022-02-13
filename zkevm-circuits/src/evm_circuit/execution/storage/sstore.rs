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
    // same_context: SameContextGadget<F>,
    // call_id: Cell<F>,
    // tx_id: Cell<F>,
    // rw_counter_end_of_reversion: Cell<F>,
    // is_persistent: Cell<F>,
    // callee_address: Cell<F>,
    // key: Word<F>,
    // value: Word<F>,
    // committed_value: Word<F>,
    // is_warm: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for SstoreGadget<F> {
    const NAME: &'static str = "SSTORE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SSTORE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // TODO:
        Self {
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

