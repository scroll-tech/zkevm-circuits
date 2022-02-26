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

// MulGadget verifies MUL: a * b mod 2^256 is equal to c,
#[derive(Clone, Debug)]
pub(crate) struct MulGadget<F> {
    same_context: SameContextGadget<F>,
    mul_words: ExtendMulWordsGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for MulGadget<F> {
    const NAME: &'static str = "MUL";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MUL;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Pop a and b from the stack, push product on the stack
        let mul_words = ExtendMulWordsGadget::construct(cb, 0.expr());
        cb.stack_pop(mul_words.a());
        cb.stack_pop(mul_words.b());
        cb.stack_push(mul_words.product());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            // Setting gas_left as default (SAME), SameContextGadget would
            // deduce the gas cost from OPCODE automatically
            // gas_left: Delta(-GasCost::FAST.as_usize().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition, None);

        Self {
            same_context,
            mul_words,
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
        let [a, b, c] = indices.map(|idx| block.rws[idx].stack_value());
        let zero = Word::from_big_endian(&[0u8; 32]);
        self.mul_words
            .assign(region, offset, [c, a, b, zero], false)
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::run_test_circuits};
    use eth_types::evm_types::OpcodeId;
    use eth_types::{bytecode, Word};

    fn test_ok(opcode: OpcodeId, a: Word, b: Word) {
        let bytecode = bytecode! {
            PUSH32(a)
            PUSH32(b)
            #[start]
            .write_op(opcode)
            STOP
        };
        assert_eq!(run_test_circuits(bytecode), Ok(()));
    }

    #[test]
    fn mul_gadget_simple() {
        test_ok(OpcodeId::MUL, 0x030201.into(), 0x060504.into());
    }

    #[test]
    fn mul_gadget_overflow() {
        let a = Word::from_dec_str("3402823669209384634633746074317682114560").unwrap(); //2**128 * 10
        let b = Word::from_dec_str("34028236692093846346337460743176821145600").unwrap(); //2**128 * 100
        test_ok(OpcodeId::MUL, a, b);

        let a = Word::from_dec_str("3402823669209384634633746074317682114560").unwrap(); //2**128 * 10
        let b = Word::from_dec_str("34028236692093846346337460743176821145500").unwrap(); //(2**128
                                                                                          //(2**128 - 1) * 100
        test_ok(OpcodeId::MUL, a, b);
    }

    #[test]
    fn mul_gadget_rand() {
        let a = rand_word();
        let b = rand_word();
        test_ok(OpcodeId::MUL, a, b);
    }
}
