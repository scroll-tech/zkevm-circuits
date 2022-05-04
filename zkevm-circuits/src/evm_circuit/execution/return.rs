use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{constraint_builder::ConstraintBuilder, Cell},
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::Field;
use halo2_proofs::{circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ReturnGadget<F> {
    opcode: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for ReturnGadget<F> {
    const NAME: &'static str = "RETURN";

    const EXECUTION_STATE: ExecutionState = ExecutionState::RETURN;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        // Other constraints are ignored now for RETURN to serve as a mocking
        // terminator

        Self { opcode }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        _: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Some(F::from(opcode.as_u64())))?;

        Ok(())
    }
}
