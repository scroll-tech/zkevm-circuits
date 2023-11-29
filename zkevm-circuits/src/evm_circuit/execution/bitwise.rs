use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_WORD,
        step::ExecutionState,
        table::{FixedTableTag, Lookup},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{EVMConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{
        word::{Word32Cell, WordExpr},
        Expr,
    },
};
use eth_types::{evm_types::OpcodeId, Field};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct BitwiseGadget<F> {
    same_context: SameContextGadget<F>,
    a: Word32Cell<F>,
    b: Word32Cell<F>,
    c: Word32Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for BitwiseGadget<F> {
    const NAME: &'static str = "BITWISE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BITWISE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word32();
        let b = cb.query_word32();
        let c = cb.query_word32();

        cb.stack_pop(a.to_word());
        cb.stack_pop(b.to_word());
        cb.stack_push(c.to_word());

        // Because opcode AND, OR, and XOR are continuous, so we can make the
        // FixedTableTag of them also continuous, and use the opcode delta from
        // OpcodeId::AND as the delta to FixedTableTag::BitwiseAnd.
        let tag =
            FixedTableTag::BitwiseAnd.expr() + (opcode.expr() - OpcodeId::AND.as_u64().expr());
        for idx in 0..N_BYTES_WORD {
            cb.add_lookup(
                "Bitwise lookup",
                Lookup::Fixed {
                    tag: tag.clone(),
                    values: [
                        a.limbs[idx].expr(),
                        b.limbs[idx].expr(),
                        c.limbs[idx].expr(),
                    ],
                },
            );
        }

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::AND.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            a,
            b,
            c,
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

        let [a, b, c] = [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
            .map(|idx| block.rws[idx].stack_value());
        self.a.assign_u256(region, offset, a)?;
        self.b.assign_u256(region, offset, b)?;
        self.c.assign_u256(region, offset, c)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(a: Word, b: Word) {
        let bytecode = bytecode! {
            PUSH32(b)
            PUSH32(a)
            PUSH32(b)
            PUSH32(a)
            PUSH32(b)
            PUSH32(a)
            AND
            POP
            OR
            POP
            XOR
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn bitwise_gadget_simple() {
        test_ok(0x12_34_56.into(), 0x78_9A_BC.into());
    }

    #[test]
    fn bitwise_gadget_rand() {
        let a = rand_word();
        let b = rand_word();
        test_ok(a, b);
    }
}
