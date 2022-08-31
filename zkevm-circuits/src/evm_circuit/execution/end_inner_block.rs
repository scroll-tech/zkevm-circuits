use crate::evm_circuit::{
    execution::ExecutionGadget,
    step::ExecutionState,
    util::{constraint_builder::ConstraintBuilder, CachedRegion},
    witness::{Block, Call, ExecStep, Transaction},
};
use eth_types::Field;
use halo2_proofs::plonk::Error;

use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub(crate) struct EndInnerBlockGadget<F> {
    _marker: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for EndInnerBlockGadget<F> {
    const NAME: &'static str = "EndInnerBlock";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EndInnerBlock;

    fn configure(_: &mut ConstraintBuilder<F>) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn assign_exec_step(
        &self,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        _: &Block<F>,
        _: &Transaction,
        _: &Call,
        _step: &ExecStep,
    ) -> Result<(), Error> {
        Ok(())
    }
}
