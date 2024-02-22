use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{EVMConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{
        word::{WordCell, WordExpr},
        Expr,
    },
};
use eth_types::{evm_types::OpcodeId, Field};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct SwapGadget<F> {
    same_context: SameContextGadget<F>,
    // phase2_values
    values: [WordCell<F>; 2],
}

impl<F: Field> ExecutionGadget<F> for SwapGadget<F> {
    const NAME: &'static str = "SWAP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SWAP;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let values = [cb.query_word_unchecked(), cb.query_word_unchecked()];

        // The stack index we have to peek, deduced from the 'x' value of
        // 'swapx' The offset starts at 1 for SWAP1
        let swap_offset = opcode.expr() - (OpcodeId::SWAP1.as_u64() - 1).expr();

        // Peek the value at `swap_offset`
        cb.stack_lookup(false.expr(), swap_offset.clone(), values[0].to_word());
        // Peek the value at the top of the stack
        cb.stack_lookup(false.expr(), 0.expr(), values[1].to_word());
        // Write the value previously at the top of the stack to `swap_offset`
        cb.stack_lookup(true.expr(), swap_offset, values[1].to_word());
        // Write the value previously at `swap_offset` to the top of the stack
        cb.stack_lookup(true.expr(), 0.expr(), values[0].to_word());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(4.expr()),
            program_counter: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::SWAP1.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            values,
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

        for (cell, value) in self.values.iter().zip(
            [step.rw_indices[0], step.rw_indices[1]]
                .map(|idx| block.rws[idx].stack_value())
                .iter(),
        ) {
            cell.assign_u256(region, offset, *value)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, evm_types::OpcodeId, Word};
    use mock::TestContext;

    fn test_ok(opcode: OpcodeId, lhs: Word, rhs: Word) {
        let n = opcode.postfix().expect("opcode with postfix");

        let mut bytecode = bytecode! {
            PUSH32(lhs)
        };
        for _ in 0..n - 1 {
            bytecode.op_dup1();
        }
        bytecode.append(&bytecode! {
            PUSH32(rhs)
            .write_op(opcode)
            STOP
        });

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn swap_gadget_simple() {
        test_ok(OpcodeId::SWAP1, Word::from(0x030201), Word::from(0x040506));
        test_ok(OpcodeId::SWAP2, Word::from(0x030201), Word::from(0x040506));
        test_ok(OpcodeId::SWAP15, Word::from(0x030201), Word::from(0x040506));
        test_ok(OpcodeId::SWAP16, Word::from(0x030201), Word::from(0x040506));
    }

    #[test]
    #[ignore]
    fn swap_gadget_rand() {
        for opcode in vec![
            OpcodeId::SWAP1,
            OpcodeId::SWAP2,
            OpcodeId::SWAP3,
            OpcodeId::SWAP4,
            OpcodeId::SWAP5,
            OpcodeId::SWAP6,
            OpcodeId::SWAP7,
            OpcodeId::SWAP8,
            OpcodeId::SWAP9,
            OpcodeId::SWAP10,
            OpcodeId::SWAP11,
            OpcodeId::SWAP12,
            OpcodeId::SWAP13,
            OpcodeId::SWAP14,
            OpcodeId::SWAP15,
            OpcodeId::SWAP16,
        ]
        .into_iter()
        {
            test_ok(opcode, rand_word(), rand_word());
        }
    }
}
