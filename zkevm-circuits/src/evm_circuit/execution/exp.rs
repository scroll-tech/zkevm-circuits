use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar, U256};
use gadgets::util::{and, not, or, split_u256, Expr};
use halo2_proofs::plonk::Error;

use crate::evm_circuit::{
    step::ExecutionState,
    util::{
        common_gadget::SameContextGadget,
        constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
        from_bytes,
        math_gadget::{ComparisonGadget, IsEqualGadget, IsZeroGadget},
        CachedRegion, Cell, Word,
    },
    witness::{Block, Call, ExecStep, Transaction},
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct ExponentiationGadget<F> {
    same_context: SameContextGadget<F>,
    base: Word<F>,
    exponent: Word<F>,
    exponentiation: Word<F>,
    exponent_is_zero: IsZeroGadget<F>,
    exponent_is_one: IsEqualGadget<F>,
    exponent_byte_size: Cell<F>,
    pow2_upper: Cell<F>,
    pow2_lower: Cell<F>,
    exponent_lo_cmp_pow2: ComparisonGadget<F, 16>,
    exponent_hi_cmp_pow2: ComparisonGadget<F, 16>,
    pow2_cmp_exponent_lo: ComparisonGadget<F, 16>,
    pow2_cmp_exponent_hi: ComparisonGadget<F, 16>,
}

impl<F: Field> ExecutionGadget<F> for ExponentiationGadget<F> {
    const NAME: &'static str = "EXP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let base_rlc = cb.query_rlc();
        let exponent_rlc = cb.query_rlc();
        let exponentiation_rlc = cb.query_rlc();

        cb.stack_pop(base_rlc.expr());
        cb.stack_pop(exponent_rlc.expr());
        cb.stack_push(exponentiation_rlc.expr());

        let (base_lo, base_hi) = (
            from_bytes::expr(&base_rlc.cells[0x00..0x10]),
            from_bytes::expr(&base_rlc.cells[0x10..0x20]),
        );
        let (exponent_lo, exponent_hi) = (
            from_bytes::expr(&exponent_rlc.cells[0x00..0x10]),
            from_bytes::expr(&exponent_rlc.cells[0x10..0x20]),
        );
        let (exponentiation_lo, exponentiation_hi) = (
            from_bytes::expr(&exponentiation_rlc.cells[0x00..0x10]),
            from_bytes::expr(&exponentiation_rlc.cells[0x10..0x20]),
        );

        let exponent_is_zero = IsZeroGadget::construct(cb, exponent_lo.clone());
        let exponent_is_one = IsEqualGadget::construct(cb, exponent_lo.clone(), 1.expr());
        cb.condition(
            and::expr([exponent_is_zero.expr(), not::expr(exponent_hi.clone())]),
            |cb| {
                cb.require_equal(
                    "exponentiation == 1 if exponent == 0 (lo == 1)",
                    exponentiation_lo.clone(),
                    1.expr(),
                );
                cb.require_equal(
                    "exponentiation == 1 if exponent == 0 (hi == 0)",
                    exponentiation_hi.clone(),
                    0.expr(),
                );
            },
        );
        cb.condition(
            and::expr([exponent_is_one.expr(), not::expr(exponent_hi.clone())]),
            |cb| {
                cb.require_equal(
                    "exponentiation == base if exponent == 1 (lo)",
                    exponentiation_lo.clone(),
                    base_lo.clone(),
                );
                cb.require_equal(
                    "exponentiation == base if exponent == 1 (hi)",
                    exponentiation_hi.clone(),
                    base_hi.clone(),
                );
            },
        );
        cb.condition(
            not::expr(or::expr([exponent_is_zero.expr(), exponent_is_one.expr()])),
            |cb| {
                let base_limbs = [
                    from_bytes::expr(&base_rlc.cells[0x00..0x08]),
                    from_bytes::expr(&base_rlc.cells[0x08..0x10]),
                    from_bytes::expr(&base_rlc.cells[0x10..0x18]),
                    from_bytes::expr(&base_rlc.cells[0x18..0x20]),
                ];
                let exponentiation_lo_hi = [
                    from_bytes::expr(&exponentiation_rlc.cells[0x00..0x10]),
                    from_bytes::expr(&exponentiation_rlc.cells[0x10..0x20]),
                ];
                cb.exp_table_lookup(
                    base_limbs,
                    [exponent_lo.clone(), exponent_hi.clone()],
                    exponentiation_lo_hi,
                );
            },
        );

        let exponent_byte_size = cb.query_cell();
        let pow2_upper = cb.query_cell();
        let pow2_lower = cb.query_cell();
        cb.condition(
            and::expr([exponent_is_zero.expr(), not::expr(exponent_hi.clone())]),
            |cb| {
                cb.require_zero(
                    "exponent byte size == 0 if exponent == 0",
                    exponent_byte_size.expr(),
                );
                cb.require_equal(
                    "pow2_upper == 1 if exponent == 0",
                    pow2_upper.expr(),
                    1.expr(),
                );
                cb.require_zero("pow2_lower == 0 if exponent == 0", pow2_lower.expr());
            },
        );
        let (
            exponent_lo_cmp_pow2,
            exponent_hi_cmp_pow2,
            pow2_cmp_exponent_lo,
            pow2_cmp_exponent_hi,
        ) = cb.condition(
            or::expr([not::expr(exponent_is_zero.expr()), exponent_hi.clone()]),
            |cb| {
                cb.pow2_lookup(8.expr() * exponent_byte_size.expr(), pow2_upper.clone());
                cb.pow2_lookup(
                    8.expr() * (exponent_byte_size.expr() - 1.expr()),
                    pow2_lower.clone(),
                );
                let exponent_lo_cmp_pow2 =
                    ComparisonGadget::construct(cb, exponent_lo.clone(), pow2_upper.expr());
                let exponent_hi_cmp_pow2 =
                    ComparisonGadget::construct(cb, exponent_hi.clone(), 0.expr());
                let pow2_cmp_exponent_lo =
                    ComparisonGadget::construct(cb, pow2_lower.expr(), exponent_lo);
                let pow2_cmp_exponent_hi = ComparisonGadget::construct(cb, 0.expr(), exponent_hi);

                let (exponent_lo_lt_pow2, _exponent_lo_eq_pow2) = exponent_lo_cmp_pow2.expr();
                let (exponent_hi_lt_pow2, exponent_hi_eq_pow2) = exponent_hi_cmp_pow2.expr();
                let (pow2_lt_exponent_lo, pow2_eq_exponent_lo) = pow2_cmp_exponent_lo.expr();
                let (pow2_lt_exponent_hi, pow2_eq_exponent_hi) = pow2_cmp_exponent_hi.expr();
                cb.require_equal(
                    "exponent < pow2(8 * byte_size(exponent))",
                    or::expr([
                        exponent_hi_lt_pow2,
                        and::expr([exponent_hi_eq_pow2, exponent_lo_lt_pow2]),
                    ]),
                    1.expr(),
                );
                cb.require_equal(
                    "pow2(8 * (byte_size(exponent) - 1)) <= exponent",
                    or::expr([
                        or::expr([
                            pow2_lt_exponent_hi,
                            and::expr([pow2_eq_exponent_hi.clone(), pow2_lt_exponent_lo]),
                        ]),
                        and::expr([pow2_eq_exponent_hi, pow2_eq_exponent_lo]),
                    ]),
                    1.expr(),
                );
                (
                    exponent_lo_cmp_pow2,
                    exponent_hi_cmp_pow2,
                    pow2_cmp_exponent_lo,
                    pow2_cmp_exponent_hi,
                )
            },
        );

        let dynamic_gas_cost = 50.expr() * exponent_byte_size.expr();
        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(3.expr()),
            program_counter: Transition::Delta(1.expr()), // 2 stack pops, 1 stack push
            stack_pointer: Transition::Delta(1.expr()),
            gas_left: Transition::Delta(
                -OpcodeId::EXP.constant_gas_cost().expr() - dynamic_gas_cost,
            ),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            base: base_rlc,
            exponent: exponent_rlc,
            exponentiation: exponentiation_rlc,
            exponent_is_zero,
            exponent_is_one,
            exponent_byte_size,
            pow2_upper,
            pow2_lower,
            exponent_lo_cmp_pow2,
            exponent_hi_cmp_pow2,
            pow2_cmp_exponent_lo,
            pow2_cmp_exponent_hi,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [base, exponent, exponentiation] =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
                .map(|idx| block.rws[idx].stack_value());

        self.base.assign(region, offset, Some(base.to_le_bytes()))?;
        self.exponent
            .assign(region, offset, Some(exponent.to_le_bytes()))?;
        self.exponentiation
            .assign(region, offset, Some(exponentiation.to_le_bytes()))?;

        let exponent_scalar = exponent
            .to_scalar()
            .expect("exponent should fit into scalar");
        self.exponent_is_zero
            .assign(region, offset, exponent_scalar)?;
        self.exponent_is_one
            .assign(region, offset, exponent_scalar, F::one())?;

        let exponent_byte_size = ((exponent.bits() as u32) + 7) / 8;
        self.exponent_byte_size
            .assign(region, offset, Some(F::from(exponent_byte_size as u64)))?;
        let pow2_upper: U256 = 2u64.pow(8 * exponent_byte_size).into();
        let pow2_lower: U256 = if exponent_byte_size > 0 {
            2u64.pow(8 * (exponent_byte_size - 1)).into()
        } else {
            U256::zero()
        };
        let (pow2_upper_lo, pow2_upper_hi) = split_u256(&pow2_upper);
        let (pow2_lower_lo, pow2_lower_hi) = split_u256(&pow2_lower);
        let (exponent_lo, exponent_hi) = split_u256(&exponent);

        self.pow2_upper
            .assign(region, offset, Some(pow2_upper.to_scalar().unwrap()))?;
        self.pow2_lower
            .assign(region, offset, Some(pow2_lower.to_scalar().unwrap()))?;

        self.exponent_lo_cmp_pow2.assign(
            region,
            offset,
            exponent_lo.to_scalar().unwrap(),
            pow2_upper_lo.to_scalar().unwrap(),
        )?;
        self.exponent_hi_cmp_pow2.assign(
            region,
            offset,
            exponent_hi.to_scalar().unwrap(),
            pow2_upper_hi.to_scalar().unwrap(),
        )?;
        self.pow2_cmp_exponent_lo.assign(
            region,
            offset,
            pow2_lower_lo.to_scalar().unwrap(),
            exponent_lo.to_scalar().unwrap(),
        )?;
        self.pow2_cmp_exponent_hi.assign(
            region,
            offset,
            pow2_lower_hi.to_scalar().unwrap(),
            exponent_hi.to_scalar().unwrap(),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    use crate::test_util::run_test_circuits;

    fn test_ok(base: Word, exponent: Word) {
        let code = bytecode! {
            PUSH32(exponent)
            PUSH32(base)
            EXP
            STOP
        };
        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
                None
            ),
            Ok(())
        );
    }

    #[test]
    fn exp_gadget_zero() {
        test_ok(Word::zero(), Word::zero());
        test_ok(Word::one(), Word::zero());
        test_ok(0xcafeu64.into(), Word::zero());
        test_ok(Word::MAX, Word::zero());
    }

    #[test]
    fn exp_gadget_one() {
        test_ok(Word::zero(), Word::one());
        test_ok(Word::one(), Word::one());
        test_ok(0xcafeu64.into(), Word::one());
        test_ok(Word::MAX, Word::one());
    }

    #[test]
    fn exp_gadget_simple() {
        test_ok(2.into(), 5.into());
        test_ok(3.into(), 101.into());
        test_ok(5.into(), 259.into());
        test_ok(7.into(), 1023.into());
        test_ok(Word::MAX, 2.into());
        test_ok(Word::MAX, 3.into());
    }
}
