use crate::{
    evm_circuit::{
        execution::{
            bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
            ExecutionGadget,
        },
        step::ExecutionResult,
        util::{constraint_builder::ConstraintBuilder, Cell},
    },
    util::Expr,
};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone)]
pub(crate) struct StopGadget<F> {
    opcode: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for StopGadget<F> {
    const NAME: &'static str = "STOP";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::STOP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr());

        // Other constraints are ignored now for STOP to serve as a mocking
        // terminator

        Self { opcode }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        _: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode.assign(
            region,
            offset,
            Some(F::from_u64(opcode.as_u64())),
        )?;

        Ok(())
    }
}
