use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::{FixedTableTag, Lookup},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct NotGadget<F> {
    same_context: SameContextGadget<F>,
    input: Word<F>,
    output: Word<F>,
}

impl<F: Field> ExecutionGadget<F> for NotGadget<F> {
    const NAME: &'static str = "NOT";

    const EXECUTION_STATE: ExecutionState = ExecutionState::NOT;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let input = cb.query_word_rlc();
        let output = cb.query_word_rlc();

        cb.stack_pop(input.expr());
        cb.stack_push(output.expr());

        for (i, o) in input.cells.iter().zip(output.cells.iter()) {
            cb.add_lookup(
                "input XOR output is all 1's",
                Lookup::Fixed {
                    tag: FixedTableTag::BitwiseXor.expr(),
                    values: [i.expr(), o.expr(), 255.expr()],
                },
            );
        }

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-OpcodeId::NOT.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            input,
            output,
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

        let [input, output] =
            [step.rw_indices[0], step.rw_indices[1]].map(|idx| block.rws[idx].stack_value());
        self.input
            .assign(region, offset, Some(input.to_le_bytes()))?;
        self.output
            .assign(region, offset, Some(output.to_le_bytes()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(a: Word) {
        let bytecode = bytecode! {
            PUSH32(a)
            NOT
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn not_gadget_simple() {
        test_ok(0.into());
        test_ok(1.into());
        test_ok(255.into());
        test_ok(256.into());
        test_ok(Word::MAX);
    }

    #[test]
    fn not_gadget_rand() {
        let a = rand_word();
        // the debug statement is useful for random tests so in case it fails, the
        // failing example shows up in the logs.
        dbg!(a);
        test_ok(a);
    }
}
