use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::{FixedTableTag, Lookup},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::evm_types::OpcodeId;
use eth_types::Field;
use eth_types::ToLittleEndian;
use halo2_proofs::{circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct BitwiseGadget<F> {
    same_context: SameContextGadget<F>,
    a: Word<F>,
    b: Word<F>,
    c: Word<F>,
}

impl<F: Field> ExecutionGadget<F> for BitwiseGadget<F> {
    const NAME: &'static str = "BITWISE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BITWISE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word();
        let b = cb.query_word();
        let c = cb.query_word();

        cb.stack_pop(a.expr());
        cb.stack_pop(b.expr());
        cb.stack_push(c.expr());

        // Because opcode AND, OR, and XOR are continuous, so we can make the
        // FixedTableTag of them also continuous, and use the opcode delta from
        // OpcodeId::AND as the delta to FixedTableTag::BitwiseAnd.
        let tag =
            FixedTableTag::BitwiseAnd.expr() + (opcode.expr() - OpcodeId::AND.as_u64().expr());
        for idx in 0..32 {
            cb.add_lookup(
                "Bitwise lookup",
                Lookup::Fixed {
                    tag: tag.clone(),
                    values: [
                        a.cells[idx].expr(),
                        b.cells[idx].expr(),
                        c.cells[idx].expr(),
                    ],
                },
            );
        }

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::AND.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            a,
            b,
            c,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [a, b, c] = [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
            .map(|idx| block.rws[idx].stack_value());
        self.a.assign(region, offset, Some(a.to_le_bytes()))?;
        self.b.assign(region, offset, Some(b.to_le_bytes()))?;
        self.c.assign(region, offset, Some(c.to_le_bytes()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        evm_circuit::test::rand_word,
        test_util::{get_fixed_table, run_test_circuits, BytecodeTestConfig, FixedTableConfig},
    };
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(a: Word, b: Word) {
        let bytecode = bytecode! {
            PUSH32(b)
            PUSH32(a)
            PUSH32(b)
            PUSH32(a)
            PUSH32(b)
            PUSH32(a)
            AND
            POP
            OR
            POP
            XOR
            STOP
        };
        let test_config = BytecodeTestConfig {
            evm_circuit_lookup_tags: get_fixed_table(FixedTableConfig::Complete),
            ..Default::default()
        };

        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                Some(test_config)
            ),
            Ok(())
        );
    }

    #[test]
    fn bitwise_gadget_simple() {
        test_ok(0x12_34_56.into(), 0x78_9A_BC.into());
    }

    #[test]
    fn bitwise_gadget_rand() {
        let a = rand_word();
        let b = rand_word();
        test_ok(a, b);
    }
}
