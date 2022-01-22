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
            from_bytes,
            math_gadget::IsZeroGadget,
            select, Cell, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::evm_types::OpcodeId;
use eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct JumpiGadget<F> {
    same_context: SameContextGadget<F>,
    destination: RandomLinearCombination<F, N_BYTES_PROGRAM_COUNTER>,
    condition: Cell<F>,
    is_condition_zero: IsZeroGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for JumpiGadget<F> {
    const NAME: &'static str = "JUMPI";

    const EXECUTION_STATE: ExecutionState = ExecutionState::JUMPI;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let destination = cb.query_rlc();
        let condition = cb.query_cell();

        // Pop the value from the stack
        cb.stack_pop(destination.expr());
        cb.stack_pop(condition.expr());

        // Determine if the jump condition is met
        let is_condition_zero = IsZeroGadget::construct(cb, condition.expr());
        let should_jump = 1.expr() - is_condition_zero.expr();

        // Lookup opcode at destination when should_jump
        cb.condition(should_jump.clone(), |cb| {
            cb.opcode_lookup_at(
                from_bytes::expr(&destination.cells),
                OpcodeId::JUMPDEST.expr(),
                1.expr(),
            );
        });

        // Transit program_counter to destination when should_jump, otherwise by
        // delta 1.
        let next_program_counter = select::expr(
            should_jump,
            from_bytes::expr(&destination.cells),
            cb.curr.state.program_counter.expr() + 1.expr(),
        );

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: To(next_program_counter),
            stack_pointer: Delta(2.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            None,
        );

        Self {
            same_context,
            destination,
            condition,
            is_condition_zero,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [destination, condition] = [step.rw_indices[0], step.rw_indices[1]]
            .map(|idx| block.rws[idx].stack_value());
        let condition = Word::random_linear_combine(
            condition.to_le_bytes(),
            block.randomness,
        );

        self.destination.assign(
            region,
            offset,
            Some(
                destination.to_le_bytes()[..N_BYTES_PROGRAM_COUNTER]
                    .try_into()
                    .unwrap(),
            ),
        )?;
        self.condition.assign(region, offset, Some(condition))?;
        self.is_condition_zero.assign(region, offset, condition)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        evm_circuit::test::{rand_range, rand_word},
        test_util::run_test_circuits,
    };
    use bus_mapping::bytecode;
    use eth_types::Word;

    fn test_ok(destination: usize, condition: Word) {
        assert!((68..(1 << 24) - 1).contains(&destination));

        let mut bytecode = bytecode! {
            PUSH32(condition)
            PUSH32(destination)
            #[start]
            JUMPI
            STOP
        };
        for _ in 0..(destination - 68) {
            bytecode.write(0);
        }
        bytecode.append(&bytecode! {
            JUMPDEST
            STOP
        });
        assert_eq!(run_test_circuits(bytecode), Ok(()));
    }

    #[test]
    fn jumpi_gadget_simple() {
        test_ok(68, 1.into());
        test_ok(100, 1.into());
        test_ok(1 << 11, 1.into());
        test_ok(68, 0.into());
        test_ok(100, 0.into());
        test_ok(1 << 11, 0.into());
    }

    #[test]
    #[ignore]
    fn jumpi_gadget_huge_bytecode() {
        test_ok(0x5ffe, 1.into());
        test_ok(0x5ffe, 0.into());
    }

    #[test]
    fn jumpi_gadget_rand() {
        test_ok(rand_range(68..1 << 11), 0.into());
        test_ok(rand_range(68..1 << 11), rand_word());
    }

    #[test]
    #[ignore]
    fn jumpi_gadget_rand_huge_bytecode() {
        test_ok(rand_range(1 << 11..0x5fff), 0.into());
        test_ok(rand_range(1 << 11..0x5fff), rand_word());
    }
}
