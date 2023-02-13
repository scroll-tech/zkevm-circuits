use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct IsZeroGadget<F> {
    same_context: SameContextGadget<F>,
    value: Cell<F>,
    is_zero: math_gadget::IsZeroGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for IsZeroGadget<F> {
    const NAME: &'static str = "ISZERO";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ISZERO;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let value = cb.query_cell_phase2();
        let is_zero = math_gadget::IsZeroGadget::construct(cb, value.expr());

        cb.stack_pop(value.expr());
        cb.stack_push(is_zero.expr());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-OpcodeId::ISZERO.constant_gas_cost().expr()),
            ..StepStateTransition::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            value,
            is_zero,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let value = block.rws[step.rw_indices[0]].stack_value();
        let value = region.word_rlc(value);
        self.value.assign(region, offset, value)?;
        self.is_zero.assign_value(region, offset, value)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(value: Word) {
        let bytecode = bytecode! {
            PUSH32(value)
            ISZERO
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn is_zero_gadget() {
        test_ok(0x060504.into());
        test_ok(0x0.into());
    }
}
