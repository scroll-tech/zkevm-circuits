use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar};
use gadgets::util::{and, not, or, Expr};
use halo2_proofs::plonk::Error;

use crate::evm_circuit::{
    step::ExecutionState,
    util::{
        common_gadget::SameContextGadget,
        constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
        from_bytes,
        math_gadget::{IsEqualGadget, IsZeroGadget},
        sum, CachedRegion, Cell, Word,
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
    most_significant_nonzero_byte_index: [Cell<F>; 33],
    byte_inverse: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for ExponentiationGadget<F> {
    const NAME: &'static str = "EXP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Query RLC-encoded values for base, exponent and exponentiation, where:
        // base^exponent == exponentiation (mod 2^256).
        let base_rlc = cb.query_rlc();
        let exponent_rlc = cb.query_rlc();
        let exponentiation_rlc = cb.query_rlc();

        // Pop RLC-encoded base and exponent from the stack.
        cb.stack_pop(base_rlc.expr());
        cb.stack_pop(exponent_rlc.expr());

        // Push RLC-encoded exponentiation to the stack.
        cb.stack_push(exponentiation_rlc.expr());

        // Extract low and high bytes of the base.
        let (base_lo, base_hi) = (
            from_bytes::expr(&base_rlc.cells[0x00..0x10]),
            from_bytes::expr(&base_rlc.cells[0x10..0x20]),
        );
        // Extract low and high bytes of the exponent.
        let (exponent_lo, exponent_hi) = (
            from_bytes::expr(&exponent_rlc.cells[0x00..0x10]),
            from_bytes::expr(&exponent_rlc.cells[0x10..0x20]),
        );
        // Extract low and high bytes of the exponentiation result.
        let (exponentiation_lo, exponentiation_hi) = (
            from_bytes::expr(&exponentiation_rlc.cells[0x00..0x10]),
            from_bytes::expr(&exponentiation_rlc.cells[0x10..0x20]),
        );

        // We simplify constraints depending on whether or not the exponent is 0 or 1.
        // In order to do this, we build some utility expressions.
        let exponent_is_zero = IsZeroGadget::construct(cb, exponent_lo.clone());
        let exponent_is_zero_expr =
            and::expr([exponent_is_zero.expr(), not::expr(exponent_hi.clone())]);
        let exponent_is_one = IsEqualGadget::construct(cb, exponent_lo.clone(), 1.expr());
        let exponent_is_one_expr =
            and::expr([exponent_is_one.expr(), not::expr(exponent_hi.clone())]);

        // If exponent == 0, base^exponent == 1, which implies:
        // 1. Low bytes of exponentiation == 1
        // 2. High bytes of exponentiation == 0
        cb.condition(exponent_is_zero_expr.clone(), |cb| {
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
        });
        // If exponent == 1, base^exponent == base, which implies:
        // 1. Low bytes of exponentiation == low bytes of base.
        // 2. High bytes of exponentiation == high bytes of base.
        cb.condition(exponent_is_one_expr.clone(), |cb| {
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
        });
        // If exponent > 1, i.e. exponent != 0 && exponent != 1:
        // We do a lookup to the exponentiation table.
        cb.condition(
            not::expr(or::expr([
                exponent_is_zero_expr.clone(),
                exponent_is_one_expr,
            ])),
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

        // In order to calculate the dynamic gas cost of the exponentiation operation,
        // we need the byte-size of the exponent, i.e. the minimum number of
        // bytes that can represent the exponent value.
        let most_significant_nonzero_byte_index = [(); 33].map(|()| cb.query_bool());
        cb.require_equal(
            "exactly one cell in most_significant_nonzero_byte_index is 1",
            sum::expr(&most_significant_nonzero_byte_index),
            1.expr(),
        );

        let byte_inverse = cb.query_cell();
        for i in 0..32 {
            cb.condition(most_significant_nonzero_byte_index[i].expr(), |cb| {
                cb.require_zero(
                    "more significant bytes are 0",
                    sum::expr(&exponent_rlc.cells[i..32]),
                );
                if i > 0 {
                    cb.require_equal(
                        "most significant nonzero byte inverse exists",
                        exponent_rlc.cells[i - 1].expr() * byte_inverse.expr(),
                        1.expr(),
                    )
                }
            });
        }

        let exponent_byte_size = sum::expr(
            most_significant_nonzero_byte_index
                .iter()
                .enumerate()
                .map(|(i, cell)| i.expr() * cell.expr()),
        );

        // Finally we build an expression for the dynamic gas cost.
        let dynamic_gas_cost = 50.expr() * exponent_byte_size;
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
            most_significant_nonzero_byte_index,
            byte_inverse,
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

        let most_significant_nonzero_byte_index = (exponent.bits() + 7) / 8;
        for i in 0..33 {
            self.most_significant_nonzero_byte_index[i].assign(
                region,
                offset,
                Some(if i == most_significant_nonzero_byte_index {
                    F::one()
                } else {
                    F::zero()
                }),
            )?;
        }
        if most_significant_nonzero_byte_index > 0 {
            let most_significant_nonzero_byte =
                exponent.to_le_bytes()[most_significant_nonzero_byte_index];
            self.byte_inverse.assign(
                region,
                offset,
                Some(
                    F::from(u64::try_from(most_significant_nonzero_byte).unwrap())
                        .invert()
                        .unwrap(),
                ),
            )?;
        }

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
