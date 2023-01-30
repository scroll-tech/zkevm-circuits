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
pub(crate) struct SwapGadget<F> {
    same_context: SameContextGadget<F>,
    phase2_values: [Cell<F>; 2],
}

impl<F: Field> ExecutionGadget<F> for SwapGadget<F> {
    const NAME: &'static str = "SWAP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SWAP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let phase2_values = [cb.query_cell_phase2(), cb.query_cell_phase2()];

        // The stack index we have to peek, deduced from the 'x' value of
        // 'swapx' The offset starts at 1 for SWAP1
        let swap_offset = opcode.expr() - (OpcodeId::SWAP1.as_u64() - 1).expr();

        // Peek the value at `swap_offset`
        cb.stack_lookup(false.expr(), swap_offset.clone(), phase2_values[0].expr());
        // Peek the value at the top of the stack
        cb.stack_lookup(false.expr(), 0.expr(), phase2_values[1].expr());
        // Write the value previously at the top of the stack to `swap_offset`
        cb.stack_lookup(true.expr(), swap_offset, phase2_values[1].expr());
        // Write the value previously at `swap_offset` to the top of the stack
        cb.stack_lookup(true.expr(), 0.expr(), phase2_values[0].expr());

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
            phase2_values,
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

        for (cell, value) in self.phase2_values.iter().zip(
            [step.rw_indices[0], step.rw_indices[1]]
                .map(|idx| block.rws[idx].stack_value())
                .iter(),
        ) {
            cell.assign(region, offset, region.word_rlc(*value))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::run_test_circuits};
    use eth_types::evm_types::OpcodeId;
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(opcode: OpcodeId, lhs: Word, rhs: Word) {
        let n = opcode.postfix().expect("opcode with postfix");

        let mut bytecode = bytecode! {
            PUSH32(lhs)
        };
        for _ in 0..n - 1 {
            bytecode.write_op(OpcodeId::DUP1);
        }
        bytecode.append(&bytecode! {
            PUSH32(rhs)
            .write_op(opcode)
            STOP
        });

        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                None
            ),
            Ok(())
        );
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
