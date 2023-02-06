use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{AddWordsGadget, PairSelectGadget},
            select, CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::plonk::Error;

// AddGadget verifies ADD and SUB at the same time by an extra swap flag,
// when it's ADD, we annotate stack as [a, b, ...] and [c, ...],
// when it's SUB, we annotate stack as [c, b, ...] and [a, ...].
// Then we verify if a + b is equal to c.
#[derive(Clone, Debug)]
pub(crate) struct AddSubGadget<F> {
    same_context: SameContextGadget<F>,
    add_words: AddWordsGadget<F, 2, false>,
    is_sub: PairSelectGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for AddSubGadget<F> {
    const NAME: &'static str = "ADD_SUB";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ADD_SUB;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word_rlc();
        let b = cb.query_word_rlc();
        let c = cb.query_word_rlc();
        let add_words = AddWordsGadget::construct(cb, [a.clone(), b.clone()], c.clone());

        // Swap a and c if opcode is SUB
        let is_sub = PairSelectGadget::construct(
            cb,
            opcode.expr(),
            OpcodeId::SUB.expr(),
            OpcodeId::ADD.expr(),
        );

        // ADD: Pop a and b from the stack, push c on the stack
        // SUB: Pop c and b from the stack, push a on the stack
        cb.stack_pop(select::expr(is_sub.expr().0, c.expr(), a.expr()));
        cb.stack_pop(b.expr());
        cb.stack_push(select::expr(is_sub.expr().0, a.expr(), c.expr()));

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::ADD.constant_gas_cost().expr()),
            ..StepStateTransition::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            add_words,
            is_sub,
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

        let opcode = step.opcode.unwrap();
        let indices = if opcode == OpcodeId::SUB {
            [step.rw_indices[2], step.rw_indices[1], step.rw_indices[0]]
        } else {
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
        };
        let [a, b, c] = indices.map(|idx| block.rws[idx].stack_value());
        self.add_words.assign(region, offset, [a, b], c)?;
        self.is_sub.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::SUB.as_u64()),
            F::from(OpcodeId::ADD.as_u64()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_word;
    use crate::test_util::CircuitTestBuilder;
    use eth_types::evm_types::OpcodeId;
    use eth_types::{bytecode, Word};

    use mock::TestContext;

    fn test_ok(opcode: OpcodeId, a: Word, b: Word) {
        let bytecode = bytecode! {
            PUSH32(a)
            PUSH32(b)
            .write_op(opcode)
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run()
    }

    #[test]
    fn add_gadget_simple() {
        test_ok(OpcodeId::ADD, 0x030201.into(), 0x060504.into());
        test_ok(OpcodeId::SUB, 0x090705.into(), 0x060504.into());
    }

    #[test]
    fn add_gadget_rand() {
        let a = rand_word();
        let b = rand_word();
        test_ok(OpcodeId::ADD, a, b);
        test_ok(OpcodeId::SUB, a, b);
    }
}
