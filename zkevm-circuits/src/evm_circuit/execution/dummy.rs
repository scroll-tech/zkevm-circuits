use std::marker::PhantomData;

use crate::evm_circuit::{
    execution::ExecutionGadget,
    step::ExecutionState,
    util::constraint_builder::ConstraintBuilder,
    witness::{Block, Call, ExecStep, Transaction},
};

use eth_types::Field;
use halo2_proofs::{circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct DummpyGadget<F, const S: ExecutionState> {
    _marker: PhantomData<F>,
    //_marker2: PhantomData<S>,
}

impl<F: Field, const S: ExecutionState> ExecutionGadget<F> for DummpyGadget<F, S> {
    const NAME: &'static str = "DUMMPY";

    const EXECUTION_STATE: ExecutionState = S;

    fn configure(_cb: &mut ConstraintBuilder<F>) -> Self {
        Self {
            _marker: PhantomData,
            //_marker2: PhantomData,
        }
    }

    fn assign_exec_step(
        &self,
        _region: &mut Region<'_, F>,
        _offset: usize,
        _block: &Block<F>,
        _: &Transaction,
        _: &Call,
        _step: &ExecStep,
    ) -> Result<(), Error> {
        Ok(())
    }
}
