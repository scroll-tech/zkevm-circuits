use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::BlockContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct TimestampGadget<F> {
    same_context: SameContextGadget<F>,
    timestamp: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for TimestampGadget<F> {
    const NAME: &'static str = "TIMESTAMP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::TIMESTAMP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let timestamp = cb.query_cell();

        // Push the value to the stack
        cb.stack_push(timestamp.expr());

        // Lookup block table with timestamp
        cb.block_lookup(
            BlockContextFieldTag::Time.expr(),
            None,
            timestamp.expr(),
        );

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
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
            timestamp,
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

        let timestamp = block.rws[step.rw_indices[0]].stack_value();

        self.timestamp.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                timestamp.to_le_bytes(),
                block.randomness,
            )),
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
            #[start]
            TIMESTAMP
            STOP
        };
        let block = witness::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }
    #[test]
    fn timestamp_gadget_test() {
        test_ok();
    }
}
