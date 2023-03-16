use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::N_BYTES_U64;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::table::{FixedTableTag, Lookup};
use crate::evm_circuit::util::common_gadget::SameContextGadget;
use crate::evm_circuit::util::constraint_builder::Transition::Delta;
use crate::evm_circuit::util::constraint_builder::{ConstraintBuilder, StepStateTransition};
use crate::evm_circuit::util::math_gadget::{IsEqualGadget, IsZeroGadget, LtGadget};
use crate::evm_circuit::util::{from_bytes, select, sum, CachedRegion, Cell, Word};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Transaction};
use crate::util::Expr;
use array_init::array_init;
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

/// SarGadget verifies SAR opcode.
/// Verify signed word shift right as `signed(a) >> shift == signed(b)`;
/// when `shift` is an unsigned word, but both `a` and `b` are signed words.
#[derive(Clone, Debug)]
pub(crate) struct SarGadget<F> {
    same_context: SameContextGadget<F>,
    shift: Word<F>,
    a: Word<F>,
    b: Word<F>,
    // Each of the four `a64s` limbs is split into two parts (`a64s_lo` and `a64s_hi`) at position
    // `shf_mod64`, `a64s_lo` is the lower `shf_mod64` bits.
    a64s_lo: [Cell<F>; 4],
    // `a64s_hi` is the higher `64 - shf_mod64` bits.
    a64s_hi: [Cell<F>; 4],
    // `shift[0] / 64`
    shf_div64: Cell<F>,
    // `shift[0] % 64`
    shf_mod64: Cell<F>,
    // 1 << shf_mod64
    p_lo: Cell<F>,
    // 1 << (64 - shf_mod64)
    p_hi: Cell<F>,
    // is_neg * (u64::MAX + 1 - p_hi)
    p_top: Cell<F>,
    // Identify if `a` is a negative word.
    is_neg: LtGadget<F, 1>,
    // Verify `shf_div64 < 4`.
    shf_div64_lt_4: LtGadget<F, 1>,
    // Verify `shf_mod64 < 64`.
    shf_mod64_lt_64: LtGadget<F, 1>,
    // Identify if `shift` is less than 256 or not.
    shf_lt256: IsZeroGadget<F>,
    // shf_div64 == 0
    shf_lo_div64_eq0: IsZeroGadget<F>,
    // shf_div64 == 1
    shf_lo_div64_eq1: IsEqualGadget<F>,
    // shf_div64 == 2
    shf_lo_div64_eq2: IsEqualGadget<F>,
    // shf_div64 == 3
    shf_lo_div64_eq3: IsEqualGadget<F>,
    // Verify `a64s_lo[idx]` should be less than `p_lo` when idx in `(0, 1, 2, 3)`.
    a64s_lo_lt_p_lo: [LtGadget<F, 16>; 4],
    // Verify `a64s_hi[idx]` should be less than `p_hi` when idx in `(0, 1, 2, 3)`.
    a64s_hi_lt_p_hi: [LtGadget<F, 16>; 4],
}

impl<F: Field> ExecutionGadget<F> for SarGadget<F> {
    const NAME: &'static str = "SAR";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SAR;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let shift = cb.query_word_rlc();
        let a = cb.query_word_rlc();
        let b = cb.query_word_rlc();

        cb.stack_pop(shift.expr());
        cb.stack_pop(a.expr());
        cb.stack_push(b.expr());

        let a64s_lo = array_init(|_| cb.query_cell());
        let a64s_hi = array_init(|_| cb.query_cell());
        let shf_div64 = cb.query_cell();
        let shf_mod64 = cb.query_cell();
        let p_lo = cb.query_cell();
        let p_hi = cb.query_cell();
        let p_top = cb.query_cell();
        let is_neg = LtGadget::construct(cb, 127.expr(), a.cells[31].expr());
        let shf_lt256 = IsZeroGadget::construct(cb, sum::expr(&shift.cells[1..32]));

        for idx in 0..4 {
            cb.require_equal(
                "a64s[idx] == a64s_lo[idx] + a64s_hi[idx] * p_lo",
                from_bytes::expr(&a.cells[N_BYTES_U64 * idx..N_BYTES_U64 * (idx + 1)]),
                a64s_lo[idx].expr() + a64s_hi[idx].expr() * p_lo.expr(),
            );
        }

        // Constrain `a64s_lo[idx] < p_lo`.
        let a64s_lo_lt_p_lo = array_init(|idx| {
            let lt = LtGadget::construct(cb, a64s_lo[idx].expr(), p_lo.expr());
            cb.require_zero("a64s_lo[idx] < p_lo", 1.expr() - lt.expr());
            lt
        });

        // Constrain `a64s_hi[idx] < p_hi`.
        let a64s_hi_lt_p_hi = array_init(|idx| {
            let lt = LtGadget::construct(cb, a64s_hi[idx].expr(), p_hi.expr());
            cb.require_zero("a64s_hi[idx] < p_hi", 1.expr() - lt.expr());
            lt
        });

        // Merge contraints
        let shf_lo_div64_eq0 = IsZeroGadget::construct(cb, shf_div64.expr());
        let shf_lo_div64_eq1 = IsEqualGadget::construct(cb, shf_div64.expr(), 1.expr());
        let shf_lo_div64_eq2 = IsEqualGadget::construct(cb, shf_div64.expr(), 2.expr());
        let shf_lo_div64_eq3 = IsEqualGadget::construct(cb, shf_div64.expr(), 3.expr());
        let shf_div64_eq0 = shf_lt256.expr() * shf_lo_div64_eq0.expr();
        let shf_div64_eq1 = shf_lt256.expr() * shf_lo_div64_eq1.expr();
        let shf_div64_eq2 = shf_lt256.expr() * shf_lo_div64_eq2.expr();
        let shf_div64_eq3 = shf_lt256.expr() * shf_lo_div64_eq3.expr();

        cb.require_equal(
            "Constrain merged b64s[0] value",
            from_bytes::expr(&b.cells[0..N_BYTES_U64]),
            (a64s_hi[0].expr() + a64s_lo[1].expr() * p_hi.expr()) * shf_div64_eq0.expr()
                + (a64s_hi[1].expr() + a64s_lo[2].expr() * p_hi.expr()) * shf_div64_eq1.expr()
                + (a64s_hi[2].expr() + a64s_lo[3].expr() * p_hi.expr()) * shf_div64_eq2.expr()
                + (a64s_hi[3].expr() + p_top.expr()) * shf_div64_eq3.expr()
                + is_neg.expr()
                    * u64::MAX.expr()
                    * (1.expr()
                        - shf_div64_eq0.expr()
                        - shf_div64_eq1.expr()
                        - shf_div64_eq2.expr()
                        - shf_div64_eq3.expr()),
        );
        cb.require_equal(
            "Constrain merged b64s[1] value",
            from_bytes::expr(&b.cells[N_BYTES_U64..N_BYTES_U64 * 2]),
            (a64s_hi[1].expr() + a64s_lo[2].expr() * p_hi.expr()) * shf_div64_eq0.expr()
                + (a64s_hi[2].expr() + a64s_lo[3].expr() * p_hi.expr()) * shf_div64_eq1.expr()
                + (a64s_hi[3].expr() + p_top.expr()) * shf_div64_eq2.expr()
                + is_neg.expr()
                    * u64::MAX.expr()
                    * (1.expr()
                        - shf_div64_eq0.expr()
                        - shf_div64_eq1.expr()
                        - shf_div64_eq2.expr()),
        );
        cb.require_equal(
            "Constrain merged b64s[2] value",
            from_bytes::expr(&b.cells[N_BYTES_U64 * 2..N_BYTES_U64 * 3]),
            (a64s_hi[2].expr() + a64s_lo[3].expr() * p_hi.expr()) * shf_div64_eq0.expr()
                + (a64s_hi[3].expr() + p_top.expr()) * shf_div64_eq1.expr()
                + is_neg.expr()
                    * u64::MAX.expr()
                    * (1.expr() - shf_div64_eq0.expr() - shf_div64_eq1.expr()),
        );
        cb.require_equal(
            "Constrain merged b64s[3] value",
            from_bytes::expr(&b.cells[N_BYTES_U64 * 3..]),
            (a64s_hi[3].expr() + p_top.expr()) * shf_div64_eq0.expr()
                + is_neg.expr() * u64::MAX.expr() * (1.expr() - shf_div64_eq0.expr()),
        );

        // Shift constraint
        let shf_div64_lt_4 = LtGadget::construct(cb, shf_div64.expr(), 4.expr());
        cb.require_equal("shf_div64 < 4", shf_div64_lt_4.expr(), 1.expr());
        let shf_mod64_lt_64 = LtGadget::construct(cb, shf_mod64.expr(), 64.expr());
        cb.require_equal("shf_mod64 < 64", shf_mod64_lt_64.expr(), 1.expr());
        cb.require_equal(
            "shift[0] == shf_mod64 + shf_div64 * 64",
            shift.cells[0].expr(),
            shf_mod64.expr() + shf_div64.expr() * 64.expr(),
        );

        // `is_neg` constraints
        cb.require_boolean("is_neg is boolean", is_neg.expr());
        cb.add_lookup(
            "SignByte lookup for a and is_neg",
            Lookup::Fixed {
                tag: FixedTableTag::SignByte.expr(),
                values: [
                    a.cells[31].expr(),
                    select::expr(is_neg.expr(), 255.expr(), 0.expr()),
                    0.expr(),
                ],
            },
        );

        // `p_top` constraint
        cb.require_equal(
            "p_top == is_neg * (MAX_U64 + 1 - p_hi)",
            p_top.expr(),
            is_neg.expr() * (u64::MAX.expr() + 1.expr() - p_hi.expr()),
        );

        // Constrain `p_lo == pow(2, shf_mod64)`.
        cb.add_lookup(
            "Pow2 lookup for p_lo == pow(2, shf_mod64)",
            Lookup::Fixed {
                tag: FixedTableTag::Pow2.expr(),
                values: [shf_mod64.expr(), p_lo.expr(), 0.expr()],
            },
        );

        // Constrain `p_hi == pow(2, 64 - shf_mod64)`.
        cb.add_lookup(
            "Pow2 lookup for p_hi == pow(2, 64 - shf_mod64)",
            Lookup::Fixed {
                tag: FixedTableTag::Pow2.expr(),
                values: [64.expr() - shf_mod64.expr(), p_hi.expr(), 0.expr()],
            },
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::SAR.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            shift,
            a,
            b,
            a64s_lo,
            a64s_hi,
            shf_div64,
            shf_mod64,
            p_lo,
            p_hi,
            p_top,
            is_neg,
            shf_div64_lt_4,
            shf_mod64_lt_64,
            shf_lt256,
            shf_lo_div64_eq0,
            shf_lo_div64_eq1,
            shf_lo_div64_eq2,
            shf_lo_div64_eq3,
            a64s_lo_lt_p_lo,
            a64s_hi_lt_p_hi,
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
        let [shift, a, b] = indices.map(|idx| block.rws[idx].stack_value());

        self.shift
            .assign(region, offset, Some(shift.to_le_bytes()))?;
        self.a.assign(region, offset, Some(a.to_le_bytes()))?;
        self.b.assign(region, offset, Some(b.to_le_bytes()))?;

        let is_neg = 127 < a.to_le_bytes()[31];
        let shf0 = u128::from(shift.to_le_bytes()[0]);
        let shf_div64 = shf0 / 64;
        let shf_mod64 = shf0 % 64;
        let p_lo = 1 << shf_mod64;
        let p_hi = 1 << (64 - shf_mod64);
        let p_top = if is_neg {
            u128::from(u64::MAX) + 1 - p_hi
        } else {
            0
        };
        let shf_lt256 = shift
            .to_le_bytes()
            .iter()
            .fold(0, |acc, val| acc + u128::from(*val))
            - shf0;
        let a64s = a.0;
        let mut a64s_lo = [0; 4];
        let mut a64s_hi = [0; 4];
        for idx in 0..4 {
            a64s_hi[idx] = u128::from(a64s[idx]) / p_lo;
            a64s_lo[idx] = u128::from(a64s[idx]) % p_lo;
        }
        let mut b64s = if is_neg {
            [u128::from(u64::MAX); 4]
        } else {
            [0; 4]
        };
        if shf_lt256 == 0 && shf_div64 < 4 {
            let idx = shf_div64 as usize;
            b64s[3 - idx] = a64s_hi[3] + p_top;
            for k in 0..3 - idx {
                b64s[k] = a64s_hi[k + idx] + a64s_lo[k + idx + 1] * p_hi;
            }
        }
        self.a64s_lo
            .iter()
            .zip(a64s_lo.into_iter())
            .map(|(c, v)| c.assign(region, offset, Value::known(F::from_u128(v))))
            .collect::<Result<Vec<_>, _>>()?;
        self.a64s_hi
            .iter()
            .zip(a64s_hi.into_iter())
            .map(|(c, v)| c.assign(region, offset, Value::known(F::from_u128(v))))
            .collect::<Result<Vec<_>, _>>()?;
        self.shf_div64
            .assign(region, offset, Value::known(F::from_u128(shf_div64)))?;
        self.shf_mod64
            .assign(region, offset, Value::known(F::from_u128(shf_mod64)))?;
        self.p_lo
            .assign(region, offset, Value::known(F::from_u128(p_lo)))?;
        self.p_hi
            .assign(region, offset, Value::known(F::from_u128(p_hi)))?;
        self.p_top
            .assign(region, offset, Value::known(F::from_u128(p_top)))?;
        self.is_neg.assign(
            region,
            offset,
            127.into(),
            u64::from(a.to_le_bytes()[31]).into(),
        )?;
        self.shf_div64_lt_4
            .assign(region, offset, F::from_u128(shf_div64), 4.into())?;
        self.shf_mod64_lt_64
            .assign(region, offset, F::from_u128(shf_mod64), 64.into())?;
        self.shf_lt256
            .assign(region, offset, F::from_u128(shf_lt256))?;
        self.shf_lo_div64_eq0
            .assign(region, offset, F::from_u128(shf_div64))?;
        self.shf_lo_div64_eq1
            .assign(region, offset, F::from_u128(shf_div64), F::from(1))?;
        self.shf_lo_div64_eq2
            .assign(region, offset, F::from_u128(shf_div64), F::from(2))?;
        self.shf_lo_div64_eq3
            .assign(region, offset, F::from_u128(shf_div64), F::from(3))?;
        self.a64s_lo_lt_p_lo
            .iter()
            .zip(a64s_lo.into_iter())
            .map(|(l, v)| l.assign(region, offset, F::from_u128(v), F::from_u128(p_lo)))
            .collect::<Result<Vec<_>, _>>()?;
        self.a64s_hi_lt_p_hi
            .iter()
            .zip(a64s_hi.into_iter())
            .map(|(l, v)| l.assign(region, offset, F::from_u128(v), F::from_u128(p_hi)))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_word;
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, U256};
    use ethers_core::types::I256;
    use lazy_static::lazy_static;
    use mock::TestContext;
    use rand::Rng;

    lazy_static! {
        // Maximum negative word value of i256 (integer value of -1)
        static ref MAX_NEG: U256 = U256::MAX;

        // Maximum positive word value of i256
        static ref MAX_POS: U256 = U256::try_from(I256::MAX).unwrap();

        // Negative sign (the highest bit is 1)
        static ref NEG_SIGN: U256 = MAX_POS.checked_add(1.into()).unwrap();
    }

    #[test]
    fn test_sar_gadget_with_positive_a() {
        // Test if `a` is positive.
        test_ok(8.into(), 0x1234.into());
        test_ok(17.into(), 0x5678.into());
        test_ok(0.into(), 0xABCD.into());
        test_ok(256.into(), 0xFFFF.into());
        test_ok((256 + 8 + 1).into(), 0x12345.into());
        test_ok(NEG_SIGN.checked_add(8.into()).unwrap(), 0x1234.into());
    }

    #[test]
    fn test_sar_gadget_with_negative_a() {
        // Test if `a` is negative.
        test_ok(8.into(), NEG_SIGN.checked_add(0x1234.into()).unwrap());
        test_ok(17.into(), NEG_SIGN.checked_add(0x5678.into()).unwrap());
        test_ok(0.into(), NEG_SIGN.checked_add(0xABCD.into()).unwrap());
        test_ok(256.into(), NEG_SIGN.checked_add(0xFFFF.into()).unwrap());
        test_ok(
            (256 + 8 + 1).into(),
            NEG_SIGN.checked_add(0x12345.into()).unwrap(),
        );
        test_ok(
            NEG_SIGN.checked_add(8.into()).unwrap(),
            NEG_SIGN.checked_add(0x1234.into()).unwrap(),
        );
    }

    #[test]
    fn test_sar_gadget_with_max_values() {
        // Test either (or both) `a` or `shift` is a maximum word.
        test_ok(8.into(), *MAX_NEG);
        test_ok(129.into(), *MAX_NEG);
        test_ok(300.into(), *MAX_NEG);
        test_ok(8.into(), *MAX_POS);
        test_ok(129.into(), *MAX_POS);
        test_ok(300.into(), *MAX_POS);
        test_ok(*MAX_NEG, *MAX_NEG);
        test_ok(*MAX_NEG, *MAX_POS);
        test_ok(*MAX_POS, *MAX_NEG);
        test_ok(*MAX_POS, *MAX_POS);
    }

    #[test]
    fn test_sar_gadget_with_random_values() {
        // Test for random `a` and `shift`.
        let rand_shift = rand::thread_rng().gen_range(0..=255);
        test_ok(rand_shift.into(), rand_word());
        test_ok(rand_word(), rand_word());
    }

    #[test]
    fn test_sar_gadget_with_eip_145_cases() {
        // Test cases from eip-145.
        // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-145.md#sar-arithmetic-shift-right
        test_ok(0.into(), 1.into());
        test_ok(1.into(), 1.into());
        test_ok(1.into(), 0.into());
        test_ok(1.into(), *NEG_SIGN);
        test_ok(0xFF.into(), *NEG_SIGN);
        test_ok(0x100.into(), *NEG_SIGN);
        test_ok(0x101.into(), *NEG_SIGN);
        test_ok(0.into(), *MAX_NEG);
        test_ok(1.into(), *MAX_NEG);
        test_ok(0xFF.into(), *MAX_NEG);
        test_ok(0x100.into(), *MAX_NEG);
        test_ok(0xFE.into(), U256::from(2).checked_pow(254.into()).unwrap());
        test_ok(0xF8.into(), *MAX_POS);
        test_ok(0xFE.into(), *MAX_POS);
        test_ok(0xFF.into(), *MAX_POS);
        test_ok(0x100.into(), *MAX_POS);
    }

    fn test_ok(shift: U256, a: U256) {
        let bytecode = bytecode! {
            PUSH32(a)
            PUSH32(shift)
            SAR
            STOP
        };
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }
}
