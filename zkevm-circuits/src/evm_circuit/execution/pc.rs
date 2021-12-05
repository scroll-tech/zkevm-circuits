use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            from_bytes, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use array_init::array_init;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct PcGadget<F> {
    same_context: SameContextGadget<F>,
    value: RandomLinearCombination<F, 8>,
}

impl<F: FieldExt> ExecutionGadget<F> for PcGadget<F> {
    const NAME: &'static str = "PC";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PC;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // program_counter is limited to 64 bits so we only consider 8 bytes
        let bytes = array_init(|_| cb.query_cell());
        cb.require_equal(
            "Constrain program_counter equal to stack value",
            from_bytes::expr(&bytes),
            cb.curr.state.program_counter.expr(),
        );

        // Push the value on the stack
        let value = RandomLinearCombination::new(bytes, cb.randomness());
        cb.stack_push(value.expr());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            None,
        );

        Self {
            same_context,
            value,
        }
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
        self.same_context.assign_exec_step(region, offset, step)?;

        self.value.assign(
            region,
            offset,
            Some(step.program_counter.to_le_bytes()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::run_test_circuit_incomplete_fixed_table, witness,
    };
    use bus_mapping::bytecode;

    fn test_ok() {
        let bytecode = bytecode! {
            PUSH32(0)
            #[start]
            PC
            STOP
        };
        let block = witness::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn pc_gadget_simple() {
        test_ok();
    }
}
