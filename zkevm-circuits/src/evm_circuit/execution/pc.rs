use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_PROGRAM_COUNTER,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes, CachedRegion, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct PcGadget<F> {
    same_context: SameContextGadget<F>,
    value: RandomLinearCombination<F, N_BYTES_PROGRAM_COUNTER>,
}

impl<F: Field> ExecutionGadget<F> for PcGadget<F> {
    const NAME: &'static str = "PC";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PC;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let value = cb.query_word_rlc();

        // program_counter is limited to 64 bits so we only consider 8 bytes
        cb.require_equal(
            "Constrain program_counter equal to stack value",
            from_bytes::expr(&value.cells),
            cb.curr.state.program_counter.expr(),
        );

        // Push the value on the stack
        cb.stack_push(value.expr());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::PC.constant_gas_cost().expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            value,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        _: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        self.value
            .assign(region, offset, Some(step.program_counter.to_le_bytes()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::bytecode;
    use mock::TestContext;

    fn test_ok() {
        let bytecode = bytecode! {
            PUSH32(0)
            PC
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn pc_gadget_simple() {
        test_ok();
    }
}
