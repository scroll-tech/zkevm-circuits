use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_PROGRAM_COUNTER,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes, CachedRegion, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct JumpGadget<F> {
    same_context: SameContextGadget<F>,
    destination: RandomLinearCombination<F, N_BYTES_PROGRAM_COUNTER>,
}

impl<F: Field> ExecutionGadget<F> for JumpGadget<F> {
    const NAME: &'static str = "JUMP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::JUMP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let destination = cb.query_word_rlc();

        // Pop the value from the stack
        cb.stack_pop(destination.expr());

        // Lookup opcode at destination
        cb.opcode_lookup_at(
            from_bytes::expr(&destination.cells),
            OpcodeId::JUMPDEST.expr(),
            1.expr(),
        );

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: To(from_bytes::expr(&destination.cells)),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::JUMP.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            destination,
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

        let destination = block.rws[step.rw_indices[0]].stack_value();
        self.destination.assign(
            region,
            offset,
            Some(
                destination.to_le_bytes()[..N_BYTES_PROGRAM_COUNTER]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_range, test_util::CircuitTestBuilder};
    use eth_types::bytecode;
    use mock::TestContext;

    fn test_ok(destination: usize) {
        assert!((34..(1 << 24) - 1).contains(&destination));

        let mut bytecode = bytecode! {
            PUSH32(destination)
            JUMP
        };
        for _ in 0..(destination - 34) {
            bytecode.write(0, false);
        }
        bytecode.append(&bytecode! {
            JUMPDEST
            STOP
        });

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    fn test_invalid_jump(destination: usize) {
        let mut bytecode = bytecode! {
            PUSH32(destination)
            JUMP
        };

        // incorrect assigning for invalid jump
        for _ in 0..(destination - 33) {
            bytecode.write(0, false);
        }
        bytecode.append(&bytecode! {
            JUMPDEST
            STOP
        });

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn jump_gadget_simple() {
        test_ok(34);
        test_ok(100);
    }

    #[test]
    #[ignore]
    fn jump_gadget_huge_bytecode() {
        test_ok(0x5ffe);
    }

    #[test]
    fn jump_gadget_rand() {
        test_ok(rand_range(34..1 << 11));
    }

    #[test]
    #[ignore]
    fn jump_gadget_rand_huge_bytecode() {
        test_ok(rand_range(1 << 11..0x5fff));
    }
}
