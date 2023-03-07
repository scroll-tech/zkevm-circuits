use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::{FixedTableTag, Lookup},
        util::{
            self,
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes,
            math_gadget::{IsZeroGadget, LtWordGadget, MulAddWordsGadget},
            sum, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, U256};
use halo2_proofs::{circuit::Value, plonk::Error};

/// ShlShrGadget verifies opcode SHL and SHR.
/// For SHL, verify pop1 * (2^pop2) % 2^256 == push;
/// For SHR, verify pop1 / (2^pop2) % 2^256 == push;
/// when pop1, pop2, push are 256-bit words.
#[derive(Clone, Debug)]
pub(crate) struct ShlShrGadget<F> {
    same_context: SameContextGadget<F>,
    quotient: util::Word<F>,
    divisor: util::Word<F>,
    remainder: util::Word<F>,
    dividend: util::Word<F>,
    /// Shift word
    shift: util::Word<F>,
    /// First byte of shift word
    shf0: Cell<F>,
    /// Gadget that verifies quotient * divisor + remainder = dividend
    mul_add_words: MulAddWordsGadget<F>,
    /// Identify if `shift` is less than 256 or not
    shf_lt256: IsZeroGadget<F>,
    /// Check if divisor is zero
    divisor_is_zero: IsZeroGadget<F>,
    /// Check if remainder is zero
    remainder_is_zero: IsZeroGadget<F>,
    /// Check if remainder < divisor when divisor != 0
    remainder_lt_divisor: LtWordGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ShlShrGadget<F> {
    const NAME: &'static str = "SHL_SHR";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SHL_SHR;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let is_shl = OpcodeId::SHR.expr() - opcode.expr();
        let is_shr = 1.expr() - is_shl.expr();

        let quotient = cb.query_word_rlc();
        let divisor = cb.query_word_rlc();
        let remainder = cb.query_word_rlc();
        let dividend = cb.query_word_rlc();
        let shift = cb.query_word_rlc();
        let shf0 = cb.query_cell();

        let mul_add_words =
            MulAddWordsGadget::construct(cb, [&quotient, &divisor, &remainder, &dividend]);
        let shf_lt256 = IsZeroGadget::construct(cb, sum::expr(&shift.cells[1..32]));
        let divisor_is_zero = IsZeroGadget::construct(cb, sum::expr(&divisor.cells));
        let remainder_is_zero = IsZeroGadget::construct(cb, sum::expr(&remainder.cells));
        let remainder_lt_divisor = LtWordGadget::construct(cb, &remainder, &divisor);

        // Constrain stack pops and pushes as:
        // - for SHL, two pops are shift and quotient, and push is dividend.
        // - for SHR, two pops are shift and dividend, and push is quotient.
        cb.stack_pop(shift.expr());
        cb.stack_pop(is_shl.expr() * quotient.expr() + is_shr.expr() * dividend.expr());
        cb.stack_push(
            (is_shl.expr() * dividend.expr() + is_shr.expr() * quotient.expr())
                * (1.expr() - divisor_is_zero.expr()),
        );

        cb.require_zero(
            "shf0 == shift.cells[0]",
            shf0.expr() - shift.cells[0].expr(),
        );

        cb.require_zero(
            "shift == shift.cells[0] when divisor != 0",
            (1.expr() - divisor_is_zero.expr()) * (shift.expr() - shift.cells[0].expr()),
        );

        cb.require_zero(
            "shift < 256 when divisor != 0 or shift >= 256 when divisor == 0",
            1.expr() - divisor_is_zero.expr() - shf_lt256.expr(),
        );

        cb.require_zero(
            "remainder < divisor when divisor != 0",
            (1.expr() - divisor_is_zero.expr()) * (1.expr() - remainder_lt_divisor.expr()),
        );

        cb.require_zero(
            "remainder == 0 for opcode SHL",
            is_shl * (1.expr() - remainder_is_zero.expr()),
        );

        cb.require_zero(
            "overflow == 0 for opcode SHR",
            is_shr * mul_add_words.overflow(),
        );

        // Constrain divisor_lo == 2^shf0 when shf0 < 128, and
        // divisor_hi == 2^(128 - shf0) otherwise.
        let divisor_lo = from_bytes::expr(&divisor.cells[..16]);
        let divisor_hi = from_bytes::expr(&divisor.cells[16..]);
        cb.condition(1.expr() - divisor_is_zero.expr(), |cb| {
            cb.add_lookup(
                "Pow2 lookup of shf0, divisor_lo and divisor_hi",
                Lookup::Fixed {
                    tag: FixedTableTag::Pow2.expr(),
                    values: [shf0.expr(), divisor_lo.expr(), divisor_hi.expr()],
                },
            );
        });

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::SHL.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            quotient,
            divisor,
            remainder,
            dividend,
            shift,
            shf0,
            mul_add_words,
            shf_lt256,
            divisor_is_zero,
            remainder_is_zero,
            remainder_lt_divisor,
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
        let indices = [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]];
        let [pop1, pop2, push] = indices.map(|idx| block.rws[idx].stack_value());
        let shf0 = u64::from(pop1.to_le_bytes()[0]);
        let shf_lt256 = pop1
            .to_le_bytes()
            .iter()
            .fold(Some(0_u64), |acc, val| {
                acc.and_then(|acc| acc.checked_add(u64::from(*val)))
            })
            .unwrap()
            - shf0;
        let divisor = if shf_lt256 == 0 {
            U256::from(1) << shf0
        } else {
            U256::from(0)
        };

        let (quotient, remainder, dividend) = match step.opcode.unwrap() {
            OpcodeId::SHL => (pop2, U256::from(0), push),
            OpcodeId::SHR => (push, pop2 - push * divisor, pop2),
            _ => unreachable!(),
        };
        self.quotient
            .assign(region, offset, Some(quotient.to_le_bytes()))?;
        self.divisor
            .assign(region, offset, Some(divisor.to_le_bytes()))?;
        self.remainder
            .assign(region, offset, Some(remainder.to_le_bytes()))?;
        self.dividend
            .assign(region, offset, Some(dividend.to_le_bytes()))?;
        self.shift
            .assign(region, offset, Some(pop1.to_le_bytes()))?;
        self.shf0
            .assign(region, offset, Value::known(F::from(shf0)))?;
        self.mul_add_words
            .assign(region, offset, [quotient, divisor, remainder, dividend])?;
        self.shf_lt256.assign(region, offset, F::from(shf_lt256))?;
        let divisor_sum = (0..32).fold(0, |acc, idx| acc + divisor.byte(idx) as u64);
        self.divisor_is_zero
            .assign(region, offset, F::from(divisor_sum))?;
        let remainder_sum = (0..32).fold(0, |acc, idx| acc + remainder.byte(idx) as u64);
        self.remainder_is_zero
            .assign(region, offset, F::from(remainder_sum))?;
        self.remainder_lt_divisor
            .assign(region, offset, remainder, divisor)
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::evm_types::OpcodeId;
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(opcode: OpcodeId, pop1: Word, pop2: Word) {
        let bytecode = bytecode! {
            PUSH32(pop1)
            PUSH32(pop2)
            #[start]
            .write_op(opcode)
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn shl_gadget_tests() {
        test_ok(OpcodeId::SHL, Word::from(0xABCD) << 240, Word::from(8));
        test_ok(OpcodeId::SHL, Word::from(0x1234) << 240, Word::from(7));
        test_ok(OpcodeId::SHL, Word::from(0x8765) << 240, Word::from(17));
        test_ok(OpcodeId::SHL, Word::from(0x4321) << 240, Word::from(0));
        test_ok(OpcodeId::SHL, Word::from(0xFFFF), Word::from(256));
        test_ok(OpcodeId::SHL, Word::from(0x12345), Word::from(256 + 8 + 1));
        let max_word = Word::from_big_endian(&[255_u8; 32]);
        test_ok(OpcodeId::SHL, max_word, Word::from(63));
        test_ok(OpcodeId::SHL, max_word, Word::from(128));
        test_ok(OpcodeId::SHL, max_word, Word::from(129));
        test_ok(OpcodeId::SHL, rand_word(), rand_word());
    }

    #[test]
    fn shr_gadget_tests() {
        test_ok(OpcodeId::SHR, Word::from(0xABCD), Word::from(8));
        test_ok(OpcodeId::SHR, Word::from(0x1234), Word::from(7));
        test_ok(OpcodeId::SHR, Word::from(0x8765), Word::from(17));
        test_ok(OpcodeId::SHR, Word::from(0x4321), Word::from(0));
        test_ok(OpcodeId::SHR, Word::from(0xFFFF), Word::from(256));
        test_ok(OpcodeId::SHR, Word::from(0x12345), Word::from(256 + 8 + 1));
        let max_word = Word::from_big_endian(&[255_u8; 32]);
        test_ok(OpcodeId::SHR, max_word, Word::from(63));
        test_ok(OpcodeId::SHR, max_word, Word::from(128));
        test_ok(OpcodeId::SHR, max_word, Word::from(129));
        test_ok(OpcodeId::SHR, rand_word(), rand_word());
    }
}
