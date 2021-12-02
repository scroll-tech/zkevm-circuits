use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionResult,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            math_gadget::{AddWordsGadget, PairSelectGadget},
            select,
        },
        witness::bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

// AddGadget verifies ADD and SUB at the same time by an extra swap flag,
// when it's ADD, we annotate stack as [a, b, ...] and [c, ...],
// when it's SUB, we annotate stack as [c, b, ...] and [a, ...].
// Then we verify if a + b is equal to c.
#[derive(Clone, Debug)]
pub(crate) struct AddGadget<F> {
    same_context: SameContextGadget<F>,
    add_words: AddWordsGadget<F, 2>,
    is_sub: PairSelectGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for AddGadget<F> {
    const NAME: &'static str = "ADD";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::ADD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word();
        let b = cb.query_word();
        let add_words = AddWordsGadget::construct(cb, [a.clone(), b.clone()]);
        let c = add_words.sum();

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
        let state_transition = StateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            ..Default::default()
        };
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

        Self {
            same_context,
            add_words,
            is_sub,
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
            F::from_u64(opcode.as_u64()),
            F::from_u64(OpcodeId::SUB.as_u64()),
            F::from_u64(OpcodeId::ADD.as_u64()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        witness::bus_mapping_tmp,
    };
    use bus_mapping::{bytecode, eth_types::Word, evm::OpcodeId};

    fn test_ok(opcode: OpcodeId, a: Word, b: Word) {
        let bytecode = bytecode! {
            PUSH32(a)
            PUSH32(b)
            #[start]
            .write_op(opcode)
            STOP
        };
        let block =
            bus_mapping_tmp::build_block_from_trace_code_at_start(
                &bytecode,
            );
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
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
