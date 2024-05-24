use std::marker::PhantomData;

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            constraint_builder::{EVMConstraintBuilder, StepStateTransition, Transition::Same},
            CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Field,
};
use halo2_proofs::plonk::Error;

#[derive(Debug, Clone)]
pub(crate) struct PaddingGadget<F> {
    /// Marker
    pub _marker: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for PaddingGadget<F> {
    const NAME: &'static str = "Padding";

    const EXECUTION_STATE: ExecutionState = ExecutionState::Padding;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        // Propagate rw_counter and call_id all the way down.
        // TODO: is it better that we constrain all state "Same"?
        cb.require_step_state_transition(StepStateTransition {
            rw_counter: Same,
            call_id: Same,
            ..StepStateTransition::any()
        });
        Self {
            _marker: Default::default(),
        }
    }

    fn assign_exec_step(
        &self,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        _block: &Block,
        _: &Transaction,
        _: &Call,
        _step: &ExecStep,
    ) -> Result<(), Error> {
        Ok(())
    }
}
