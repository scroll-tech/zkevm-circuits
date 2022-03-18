use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{AddWordsGadget, PairSelectGadget, IsZeroGadget},
            select, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{circuit::Region, plonk::Error};

// AddGadget verifies ADD and SUB at the same time by an extra swap flag,
// when it's ADD, we annotate stack as [a, b, ...] and [c, ...],
// when it's SUB, we annotate stack as [c, b, ...] and [a, ...].
// Then we verify if a + b is equal to c.
#[derive(Clone, Debug)]
pub(crate) struct Is0Gadget<F> {
    same_context: SameContextGadget<F>,
    is_0: IsZeroGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for Is0Gadget<F> {
    const NAME: &'static str = "ISZERO";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ISZERO;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word();
        let is_0 = IsZeroGadget::construct(cb, a.expr());

        cb.stack_pop(a.expr());
        cb.stack_push(is_0.expr());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-OpcodeId::ADD.constant_gas_cost().expr()),
            ..StepStateTransition::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            is_0,
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

        let indices = 
            [step.rw_indices[0], step.rw_indices[1]];
        let [a, is_0] = indices.map(|idx| block.rws[idx].stack_value());
        let a = Word::random_linear_combine(a.to_le_bytes(), block.randomness);
        self.is_0.assign(region, offset, a)?;

        Ok(())
    }
}
/* 
#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_word;
    use crate::test_util::run_test_circuits;
    use eth_types::evm_types::OpcodeId;
    use eth_types::{bytecode, Word};

    fn test_ok(opcode: OpcodeId, a: Word, b: Word) {
        let bytecode = bytecode! {
            PUSH32(a)
            PUSH32(b)
            .write_op(opcode)
            STOP
        };
        assert_eq!(run_test_circuits(bytecode), Ok(()));
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
*/