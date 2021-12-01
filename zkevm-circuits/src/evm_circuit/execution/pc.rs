use crate::{
    evm_circuit::{
        execution::{
            bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
            ExecutionGadget,
        },
        step::ExecutionResult,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            from_bytes, RandomLinearCombination,
        },
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

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::PC;

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
        let state_transition = StateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

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
        bus_mapping_tmp_convert,
        execution::bus_mapping_tmp::{
            Block, Bytecode, Call, ExecStep, Rw, Transaction,
        },
        step::ExecutionResult,
        test::run_test_circuit_incomplete_fixed_table,
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        bytecode,
        eth_types::{ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok() {
        let bytecode = bytecode! {
            PUSH32(0)
            #[start]
            PC
            STOP
        };
        let block =
            bus_mapping_tmp_convert::build_block_from_trace_code_at_start(
                &bytecode,
            );

        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn pc_gadget_simple() {
        test_ok();
    }
}
