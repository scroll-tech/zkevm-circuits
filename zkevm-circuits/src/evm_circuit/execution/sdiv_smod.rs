use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::Delta,
            },
            math_gadget::{AbsWordGadget, IsZeroGadget, LtGadget, LtWordGadget, MulAddWordsGadget},
            select, sum, CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, U256};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct SignedDivModGadget<F> {
    same_context: SameContextGadget<F>,
    quotient_abs_word: AbsWordGadget<F>,
    divisor_abs_word: AbsWordGadget<F>,
    remainder_abs_word: AbsWordGadget<F>,
    dividend_abs_word: AbsWordGadget<F>,
    mul_add_words: MulAddWordsGadget<F>,
    remainder_abs_lt_divisor_abs: LtWordGadget<F>,
    dividend_is_signed_overflow: LtGadget<F, 1>,
    quotient_is_zero: IsZeroGadget<F>,
    divisor_is_zero: IsZeroGadget<F>,
    remainder_is_zero: IsZeroGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for SignedDivModGadget<F> {
    const NAME: &'static str = "SDIV_SMOD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SDIV_SMOD;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let is_sdiv = (OpcodeId::SMOD.expr() - opcode.expr()) * F::from(2).invert().unwrap();

        let quotient_abs_word = AbsWordGadget::construct(cb);
        let divisor_abs_word = AbsWordGadget::construct(cb);
        let remainder_abs_word = AbsWordGadget::construct(cb);
        let dividend_abs_word = AbsWordGadget::construct(cb);
        let quotient_is_zero =
            IsZeroGadget::construct(cb, "", sum::expr(&quotient_abs_word.x().cells));
        let divisor_is_zero =
            IsZeroGadget::construct(cb, "", sum::expr(&divisor_abs_word.x().cells));
        let remainder_is_zero =
            IsZeroGadget::construct(cb, "", sum::expr(&remainder_abs_word.x().cells));

        cb.stack_pop(dividend_abs_word.x().expr());
        cb.stack_pop(divisor_abs_word.x().expr());
        cb.stack_push(select::expr(
            is_sdiv,
            quotient_abs_word.x().expr() * (1.expr() - divisor_is_zero.expr()),
            remainder_abs_word.x().expr() * (1.expr() - divisor_is_zero.expr()),
        ));

        // Constrain `|quotient| * |divisor| + |remainder| = |dividend|`.
        let mul_add_words = MulAddWordsGadget::construct(
            cb,
            [
                quotient_abs_word.x_abs(),
                divisor_abs_word.x_abs(),
                remainder_abs_word.x_abs(),
                dividend_abs_word.x_abs(),
            ],
        );
        cb.add_constraint("overflow == 0", mul_add_words.overflow());

        let remainder_abs_lt_divisor_abs =
            LtWordGadget::construct(cb, remainder_abs_word.x_abs(), divisor_abs_word.x_abs());
        cb.add_constraint(
            "abs(remainder) < abs(divisor) when divisor != 0",
            (1.expr() - remainder_abs_lt_divisor_abs.expr()) * (1.expr() - divisor_is_zero.expr()),
        );

        cb.condition(
            (1.expr() - quotient_is_zero.expr())
            * (1.expr() - divisor_is_zero.expr())
            * (1.expr() - remainder_is_zero.expr()),
            |cb| cb.add_constraint(
                "sign(dividend) == sign(remainder) when quotient, divisor and remainder are all non-zero",
                dividend_abs_word.is_neg().expr() - remainder_abs_word.is_neg().expr(),
            )
        );

        // For a special `SDIV` case, when input `dividend = -(1 << 255)` and
        // `divisor = -1`, the quotient result should be `1 << 255`. But a
        // `signed` word could only express `signed` value from `-(1 << 255)` to
        // `(1 << 255) - 1`. So constraint
        // `sign(dividend) == sign(divisor) ^ sign(quotient)` cannot be applied
        // for this case.
        let dividend_is_signed_overflow =
            LtGadget::construct(cb, 127.expr(), dividend_abs_word.x_abs().cells[31].expr());

        // Constrain sign(dividend) == sign(divisor) ^ sign(quotient) when both
        // quotient and divisor are non-zero and dividend is not signed overflow.
        cb.condition(
            (1.expr() - quotient_is_zero.expr())
                * (1.expr() - divisor_is_zero.expr())
                * (1.expr() - dividend_is_signed_overflow.expr()),
            |cb| {
                cb.add_constraint(
                    "sign(dividend) == sign(divisor) ^ sign(quotient)",
                    quotient_abs_word.is_neg().expr() + divisor_abs_word.is_neg().expr()
                        - dividend_abs_word.is_neg().expr()
                        - 2.expr()
                            * quotient_abs_word.is_neg().expr()
                            * divisor_abs_word.is_neg().expr(),
                )
            },
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::SDIV.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            quotient_abs_word,
            divisor_abs_word,
            remainder_abs_word,
            dividend_abs_word,
            mul_add_words,
            remainder_abs_lt_divisor_abs,
            dividend_is_signed_overflow,
            quotient_is_zero,
            divisor_is_zero,
            remainder_is_zero,
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
        let pop1_abs = get_abs(pop1);
        let pop2_abs = get_abs(pop2);
        let push_abs = get_abs(push);
        let is_pop1_neg = is_neg(pop1);
        let is_pop2_neg = is_neg(pop2);
        let (quotient, divisor, remainder, dividend) = match step.opcode.unwrap() {
            OpcodeId::SDIV => (
                push,
                pop2,
                if is_pop1_neg {
                    get_neg(pop1_abs - push_abs * pop2_abs)
                } else {
                    pop1_abs - push_abs * pop2_abs
                },
                pop1,
            ),
            OpcodeId::SMOD => (
                if pop2.is_zero() {
                    U256::from(0)
                } else if is_pop1_neg == is_pop2_neg {
                    pop1_abs / pop2_abs
                } else {
                    get_neg(pop1_abs / pop2_abs)
                },
                pop2,
                if pop2.is_zero() { pop1 } else { push },
                pop1,
            ),
            _ => unreachable!(),
        };
        let quotient_abs = get_abs(quotient);
        let divisor_abs = get_abs(divisor);
        let remainder_abs = get_abs(remainder);
        let dividend_abs = get_abs(dividend);
        self.quotient_abs_word
            .assign(region, offset, quotient, quotient_abs)?;
        self.divisor_abs_word
            .assign(region, offset, divisor, divisor_abs)?;
        self.remainder_abs_word
            .assign(region, offset, remainder, remainder_abs)?;
        self.dividend_abs_word
            .assign(region, offset, dividend, dividend_abs)?;
        self.mul_add_words.assign(
            region,
            offset,
            [quotient_abs, divisor_abs, remainder_abs, dividend_abs],
        )?;
        self.remainder_abs_lt_divisor_abs
            .assign(region, offset, remainder_abs, divisor_abs)?;
        self.dividend_is_signed_overflow.assign(
            region,
            offset,
            127.into(),
            u64::from(dividend_abs.to_le_bytes()[31]).into(),
        )?;
        let quotient_sum = (0..32).fold(0, |acc, idx| acc + quotient.byte(idx) as u64);
        let divisor_sum = (0..32).fold(0, |acc, idx| acc + divisor.byte(idx) as u64);
        let remainder_sum = (0..32).fold(0, |acc, idx| acc + remainder.byte(idx) as u64);
        self.quotient_is_zero
            .assign(region, offset, F::from(quotient_sum))?;
        self.divisor_is_zero
            .assign(region, offset, F::from(divisor_sum))?;
        self.remainder_is_zero
            .assign(region, offset, F::from(remainder_sum))?;
        Ok(())
    }
}

#[inline]
fn get_abs(x: U256) -> U256 {
    if is_neg(x) {
        get_neg(x)
    } else {
        x
    }
}

#[inline]
fn get_neg(x: U256) -> U256 {
    if x.is_zero() {
        x
    } else {
        U256::from_big_endian(&[255u8; 32]) - x + U256::from(1)
    }
}

#[inline]
fn is_neg(x: U256) -> bool {
    127 < x.to_le_bytes()[31]
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, evm_types::OpcodeId, Word};
    use mock::TestContext;

    fn test_ok(opcode: OpcodeId, a: Word, b: Word) {
        let bytecode = bytecode! {
            PUSH32(b)
            PUSH32(a)
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
    fn sdiv_gadget_simple() {
        test_ok(OpcodeId::SDIV, 0xFFFFFF.into(), 0xABC.into());
        test_ok(OpcodeId::SDIV, 0xABC.into(), 0xFFFFFF.into());
        test_ok(OpcodeId::SDIV, 0xFFFFFF.into(), 0xFFFFFFF.into());
        test_ok(OpcodeId::SDIV, 0xABC.into(), 0.into());
        // (1 << 255) + (7 << 128)
        let mut x = [0u8; 32];
        x[31] = 128u8;
        x[16] = 7u8;
        test_ok(OpcodeId::SDIV, Word::from_big_endian(&x), 0x1234.into());
        test_ok(
            OpcodeId::SDIV,
            Word::from_big_endian(&[255u8; 32]),
            0xABCDEF.into(),
        );
        test_ok(
            OpcodeId::SDIV,
            0xABCDEF.into(),
            Word::from_big_endian(&[255u8; 32]),
        );
        // 1 << 255
        let mut x = [0u8; 32];
        x[31] = 128u8;
        test_ok(
            OpcodeId::SDIV,
            Word::from_big_endian(&x),
            Word::from_big_endian(&[255u8; 32]),
        );
    }

    #[test]
    fn sdiv_gadget_rand() {
        let dividend = rand_word();
        let divisor = rand_word();
        test_ok(OpcodeId::SDIV, dividend, divisor);
    }

    #[test]
    fn smod_gadget_simple() {
        test_ok(OpcodeId::SMOD, 0xFFFFFF.into(), 0xABC.into());
        test_ok(OpcodeId::SMOD, 0xABC.into(), 0xFFFFFF.into());
        test_ok(OpcodeId::SMOD, 0xFFFFFF.into(), 0xFFFFFFF.into());
        test_ok(OpcodeId::SMOD, 0xABC.into(), 0.into());
        // (1 << 255) + (7 << 128)
        let mut x = [0u8; 32];
        x[31] = 128u8;
        x[16] = 7u8;
        test_ok(OpcodeId::SMOD, Word::from_big_endian(&x), 0x1234.into());
        test_ok(
            OpcodeId::SMOD,
            Word::from_big_endian(&[255u8; 32]),
            0xABCDEF.into(),
        );
        test_ok(
            OpcodeId::SMOD,
            0xABCDEF.into(),
            Word::from_big_endian(&[255u8; 32]),
        );
        let mut x = [0u8; 32];
        x[31] = 128u8;
        test_ok(
            OpcodeId::SMOD,
            Word::from_big_endian(&x),
            Word::from_big_endian(&[255u8; 32]),
        );
    }

    #[test]
    fn smod_gadget_rand() {
        let dividend = rand_word();
        let divisor = rand_word();
        test_ok(OpcodeId::SMOD, dividend, divisor);
    }
}
