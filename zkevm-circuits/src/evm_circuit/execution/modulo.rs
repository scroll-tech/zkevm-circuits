use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::ExtendMulWordsGadget,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{Field, Word};
use halo2_proofs::{circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ModGadget<F> {
    same_context: SameContextGadget<F>,
    div_words: ExtendMulWordsGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ModGadget<F> {
    const NAME: &'static str = "MOD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MOD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let div_words = ExtendMulWordsGadget::construct(cb, 1.expr());

        cb.stack_pop(div_words.dividend());
        cb.stack_pop(div_words.divisor());
        cb.stack_push(div_words.remainder());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition, None);

        Self {
            same_context,
            div_words,
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
        let indices = [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]];
        let [dividend, divisor, remainder] = indices.map(|idx| block.rws[idx].stack_value());
        let zero = Word::from_big_endian(&[0u8; 32]);
        let quotient = if divisor == zero {
            zero
        } else {
            (dividend - remainder) / divisor
        };
        self.div_words.assign(
            region,
            offset,
            [dividend, divisor, quotient, remainder],
            true,
        )
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_word;
    use crate::test_util::run_test_circuits;
    use eth_types::evm_types::OpcodeId;
    use eth_types::{bytecode, Word};

    fn test_ok(opcode: OpcodeId, dividend: Word, divisor: Word) {
        let bytecode = bytecode! {
            PUSH32(divisor)
            PUSH32(dividend)
            #[start]
            .write_op(opcode)
            STOP
        };
        assert_eq!(run_test_circuits(bytecode), Ok(()));
    }

    #[test]
    fn mod_gadget_simple() {
        test_ok(OpcodeId::MOD, 0xFFFFFF.into(), 0xABC.into());
        test_ok(OpcodeId::MOD, 0xFFFFFF.into(), 0xFFF.into());
        test_ok(OpcodeId::MOD, 0xFFFFFF.into(), 0xFFFFFFF.into());
        test_ok(
            OpcodeId::MOD,
            Word::from_big_endian(&[255u8; 32]),
            0xABCDEF.into(),
        );
        test_ok(
            OpcodeId::MOD,
            Word::from_big_endian(&[255u8; 32]),
            0x0.into(),
        );
    }

    #[test]
    fn mod_gadget_rand() {
        let dividend = rand_word();
        let divisor = rand_word();
        test_ok(OpcodeId::MOD, dividend, divisor);
    }
}
