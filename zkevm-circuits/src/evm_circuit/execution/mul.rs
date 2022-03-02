use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{IsZeroGadget, LtWordGadget, MulAddWordsGadget},
            select, sum,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, U256};
use halo2_proofs::{circuit::Region, plonk::Error};

// MulGadget verifies MUL: a * b mod 2^256 is equal to c,
#[derive(Clone, Debug)]
pub(crate) struct MulGadget<F> {
    same_context: SameContextGadget<F>,
    mul_add_words: MulAddWordsGadget<F>,
    lt_word: LtWordGadget<F>,
    divisor_is_zero: IsZeroGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for MulGadget<F> {
    const NAME: &'static str = "MUL";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MUL;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_mul = (OpcodeId::DIV.expr() - opcode.expr())
            * (OpcodeId::MOD.expr() - opcode.expr())
            * F::from(8).invert().unwrap();
        let is_div = (opcode.expr() - OpcodeId::MUL.expr())
            * (OpcodeId::MOD.expr() - opcode.expr())
            * F::from(4).invert().unwrap();
        let is_mod = (opcode.expr() - OpcodeId::MUL.expr())
            * (opcode.expr() - OpcodeId::DIV.expr())
            * F::from(8).invert().unwrap();
        let mul_add_words = MulAddWordsGadget::construct(cb);

        // Pop a and b from the stack, push result on the stack
        // The first pop is multiplier for MUL and dividend for DIV/MOD
        // The seoncd pop is multiplicand for MUL and divosr for DIV/MOD
        // The push is product for MUL, quotient for DIV, and residue for MOD
        cb.stack_pop(select::expr(
            is_mul.clone(),
            mul_add_words.a.expr(),
            mul_add_words.d.expr(),
        ));
        cb.stack_pop(mul_add_words.b.expr());
        cb.stack_push(
            is_mul.clone() * mul_add_words.d.expr()
                + is_div * mul_add_words.a.expr()
                + is_mod * mul_add_words.c.expr(),
        );

        // Constraint for MUL case
        cb.add_constraint(
            "c == 0 for opcode MUL",
            is_mul.clone() * sum::expr(&mul_add_words.c.cells),
        );

        // Constraints for DIV and MOD cases
        let lt_word = LtWordGadget::construct(cb, &mul_add_words.c, &mul_add_words.b);
        let divisor_is_zero = IsZeroGadget::construct(cb, sum::expr(&mul_add_words.b.cells));
        cb.condition(1.expr() - is_mul, |cb| {
            cb.add_constraint("divisor != 0 for opcode DIV/MOD", divisor_is_zero.expr());
            cb.require_equal(
                "residue < divisor for opcode DIV/MOD",
                lt_word.expr(),
                1.expr(),
            );
            cb.add_constraint("overflow == 0 for opcode DIV/MOD", mul_add_words.overflow());
        });

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition, None);

        Self {
            same_context,
            mul_add_words,
            lt_word,
            divisor_is_zero,
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
        let [pop1, pop2, push] = indices.map(|idx| block.rws[idx].stack_value());
        let (a, b, c, d) = match step.opcode.unwrap() {
            OpcodeId::MUL => (pop1, pop2, U256::from(0), push),
            OpcodeId::DIV => (push, pop2, pop1 - push * pop2, pop1),
            OpcodeId::MOD => (pop1 / pop2, pop2, push, pop1),
            _ => unreachable!(),
        };
        self.mul_add_words.assign(region, offset, [a, b, c, d])?;
        self.lt_word.assign(region, offset, c, b)?;
        let b_sum = (0..32).fold(0, |acc, idx| acc + b.byte(idx) as u64);
        self.divisor_is_zero
            .assign(region, offset, F::from(b_sum))?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::run_test_circuits};
    use eth_types::evm_types::OpcodeId;
    use eth_types::{bytecode, Word};

    fn test_ok(opcode: OpcodeId, a: Word, b: Word) {
        let bytecode = bytecode! {
            PUSH32(b)
            PUSH32(a)
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

    #[test]
    fn div_gadget_simple() {
        test_ok(OpcodeId::DIV, 0xFFFFFF.into(), 0xABC.into());
        test_ok(OpcodeId::DIV, 0xABC.into(), 0xFFFFFF.into());
        test_ok(OpcodeId::DIV, 0xFFFFFF.into(), 0xFFFFFFF.into());
        test_ok(
            OpcodeId::DIV,
            Word::from_big_endian(&[255u8; 32]),
            0xABCDEF.into(),
        );
    }

    #[test]
    fn div_gadget_rand() {
        let dividend = rand_word();
        let divisor = rand_word();
        test_ok(OpcodeId::DIV, dividend, divisor);
    }

    #[test]
    fn mod_gadget_simple() {
        test_ok(OpcodeId::MOD, 0xFFFFFF.into(), 0xABC.into());
        test_ok(OpcodeId::MOD, 0xABC.into(), 0xFFFFFF.into());
        test_ok(OpcodeId::MOD, 0xFFFFFF.into(), 0xFFFFFFF.into());
        test_ok(
            OpcodeId::MOD,
            Word::from_big_endian(&[255u8; 32]),
            0xABCDEF.into(),
        );
    }

    #[test]
    fn mod_gadget_rand() {
        let dividend = rand_word();
        let divisor = rand_word();
        test_ok(OpcodeId::MOD, dividend, divisor);
    }
}
