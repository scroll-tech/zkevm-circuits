use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::MAX_CODE_SIZE_IN_BYTES,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct JumpGadget<F> {
    same_context: SameContextGadget<F>,
    destination: RandomLinearCombination<F, MAX_CODE_SIZE_IN_BYTES>,
}

impl<F: FieldExt> ExecutionGadget<F> for JumpGadget<F> {
    const NAME: &'static str = "JUMP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::JUMP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let destination =
            RandomLinearCombination::new(cb.query_bytes(), cb.randomness());

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

        let destination = block.rws[step.rw_indices[0]].stack_value();
        self.destination.assign(
            region,
            offset,
            Some(destination.to_le_bytes()[..3].try_into().unwrap()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::{rand_range, run_test_circuit_incomplete_fixed_table},
        witness,
    };
    use bus_mapping::bytecode;

    fn test_ok(destination: usize) {
        assert!((34..(1 << 24) - 1).contains(&destination));

        let mut bytecode = bytecode! {
            PUSH32(destination)
            #[start]
            JUMP
        };
        for _ in 0..(destination - 34) {
            bytecode.write(0);
        }
        bytecode.append(&bytecode! {
            JUMPDEST
            STOP
        });
        let block = witness::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
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
