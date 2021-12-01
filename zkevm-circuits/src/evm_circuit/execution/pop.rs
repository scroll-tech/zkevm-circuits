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
            Cell, Word,
        },
    },
    util::Expr,
};
use bus_mapping::eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct PopGadget<F> {
    same_context: SameContextGadget<F>,
    value: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for PopGadget<F> {
    const NAME: &'static str = "POP";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::POP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let value = cb.query_cell();

        // Pop the value from the stack
        cb.stack_pop(value.expr());

        // State transition
        let state_transition = StateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
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
        block: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let value = block.rws[step.rw_indices[0]].stack_value();
        self.value.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                value.to_le_bytes(),
                block.randomness,
            )),
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
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        bytecode,
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok(value: Word) {
        let bytecode = bytecode! {
            PUSH32(value)
            #[start]
            POP
            STOP
        };
        let block =
            bus_mapping_tmp_convert::build_block_from_trace_code_at_start(
                &bytecode,
            );
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn pop_gadget_simple() {
        test_ok(Word::from(0x030201));
    }

    #[test]
    fn pop_gadget_rand() {
        test_ok(rand_word());
    }
}
