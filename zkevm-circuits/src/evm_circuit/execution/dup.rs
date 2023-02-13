use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct DupGadget<F> {
    same_context: SameContextGadget<F>,
    value: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for DupGadget<F> {
    const NAME: &'static str = "DUP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::DUP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let value = cb.query_cell_phase2();

        // The stack index we have to peek, deduced from the 'x' value of 'dupx'
        // The offset starts at 0 for DUP1
        let dup_offset = opcode.expr() - OpcodeId::DUP1.expr();

        // Peek the value at `dup_offset` and push the value on the stack
        cb.stack_lookup(false.expr(), dup_offset, value.expr());
        cb.stack_push(value.expr());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::DUP1.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            value,
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

        let value = block.rws[step.rw_indices[0]].stack_value();
        self.value.assign(region, offset, region.word_rlc(value))?;

        Ok(())
    }
}

#[cfg(test)]

mod test {
    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::evm_types::OpcodeId;
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(opcode: OpcodeId, value: Word) {
        let n = opcode.postfix().expect("opcode with postfix");
        let mut bytecode = bytecode! {
            PUSH32(value)
        };
        for _ in 0..n - 1 {
            bytecode.write_op(OpcodeId::DUP1);
        }
        bytecode.append(&bytecode! {
            .write_op(opcode)
            STOP
        });

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn dup_gadget_simple() {
        test_ok(OpcodeId::DUP1, Word::max_value());
        test_ok(OpcodeId::DUP2, Word::max_value());
        test_ok(OpcodeId::DUP15, Word::max_value());
        test_ok(OpcodeId::DUP16, Word::max_value());
    }

    #[test]
    #[ignore]
    fn dup_gadget_rand() {
        for opcode in vec![
            OpcodeId::DUP1,
            OpcodeId::DUP2,
            OpcodeId::DUP3,
            OpcodeId::DUP4,
            OpcodeId::DUP5,
            OpcodeId::DUP6,
            OpcodeId::DUP7,
            OpcodeId::DUP8,
            OpcodeId::DUP9,
            OpcodeId::DUP10,
            OpcodeId::DUP11,
            OpcodeId::DUP12,
            OpcodeId::DUP13,
            OpcodeId::DUP14,
            OpcodeId::DUP15,
            OpcodeId::DUP16,
        ]
        .into_iter()
        {
            test_ok(opcode, rand_word());
        }
    }
}
