use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionResult,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
        },
        witness::bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct JumpdestGadget<F> {
    same_context: SameContextGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for JumpdestGadget<F> {
    const NAME: &'static str = "JUMPDEST";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::JUMPDEST;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // State transition
        let state_transition = StateTransition {
            program_counter: Delta(1.expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

        Self { same_context }
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
        self.same_context.assign_exec_step(region, offset, step)
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::run_test_circuit_incomplete_fixed_table,
        witness::bus_mapping_tmp,
    };
    use bus_mapping::bytecode;

    fn test_ok() {
        let bytecode = bytecode! {
            #[start]
            JUMPDEST
            STOP
        };
        let block =
            bus_mapping_tmp::build_block_from_trace_code_at_start(
                &bytecode,
            );
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn jumpdest_gadget_simple() {
        test_ok();
    }
}
