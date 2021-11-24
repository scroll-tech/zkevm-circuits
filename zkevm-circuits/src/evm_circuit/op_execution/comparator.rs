use super::super::{
    Case, Cell, Constraint, CoreStateInstance, ExecutionStep, Word,
};
use super::utils::common_cases::{OutOfGasCase, StackUnderflowCase};
use super::utils::constraint_builder::ConstraintBuilder;
use super::utils::math_gadgets::{ComparisonGadget, IsEqualGadget};
use super::utils::{from_bytes, select, StateTransition};
use super::{CaseAllocation, CaseConfig, OpExecutionState, OpGadget};
use crate::impl_op_gadget;
use crate::util::{Expr, ToWord};
use bus_mapping::evm::{GasCost, OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::convert::TryInto;

static STATE_TRANSITION: StateTransition = StateTransition {
    gc_delta: Some(3), // 2 stack pops + 1 stack push
    pc_delta: Some(1),
    sp_delta: Some(1),
    gas_delta: Some(GasCost::FASTEST.as_usize()),
};
const NUM_POPPED: usize = 2;

impl_op_gadget!(
    #set[LT, GT, EQ]
    ComparatorGadget {
        ComparatorSuccessCase(),
        StackUnderflowCase(NUM_POPPED),
        OutOfGasCase(STATE_TRANSITION.gas_delta.unwrap()),
    }
);

#[derive(Clone, Debug)]
struct ComparatorSuccessCase<F> {
    case_selector: Cell<F>,
    a: Word<F>,
    b: Word<F>,
    comparison_lo: ComparisonGadget<F, 16>,
    comparison_hi: ComparisonGadget<F, 16>,
    is_eq_op: IsEqualGadget<F>,
    swap: IsEqualGadget<F>,
}

impl<F: FieldExt> ComparatorSuccessCase<F> {
    pub(crate) const CASE_CONFIG: &'static CaseConfig = &CaseConfig {
        case: Case::Success,
        num_word: 2, // a + b
        num_cell: ComparisonGadget::<F, 16>::NUM_CELLS * 2
            + IsEqualGadget::<F>::NUM_CELLS * 2,
        will_halt: false,
    };

    pub(crate) fn construct(alloc: &mut CaseAllocation<F>) -> Self {
        Self {
            case_selector: alloc.selector.clone(),
            a: alloc.words.pop().unwrap(),
            b: alloc.words.pop().unwrap(),
            comparison_lo: ComparisonGadget::<F, 16>::construct(alloc),
            comparison_hi: ComparisonGadget::<F, 16>::construct(alloc),
            is_eq_op: IsEqualGadget::<F>::construct(alloc),
            swap: IsEqualGadget::<F>::construct(alloc),
        }
    }

    fn constraint(
        &self,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
        name: &'static str,
    ) -> Vec<Constraint<F>> {
        let mut cb = ConstraintBuilder::default();

        // Check if this is EQ
        let is_eq_op = self.is_eq_op.constraints(
            &mut cb,
            state_curr.opcode.expr(),
            OpcodeId::EQ.expr(),
        );

        // For GT we swap the stack inputs so that we actually do
        // greater than instead of smaller than.
        let swap = self.swap.constraints(
            &mut cb,
            state_curr.opcode.expr(),
            OpcodeId::GT.expr(),
        );

        // `a[0..16] <= b[0..16]`
        let (lt_lo, eq_lo) = self.comparison_lo.constraints(
            &mut cb,
            from_bytes::expr(self.a.cells[0..16].to_vec()),
            from_bytes::expr(self.b.cells[0..16].to_vec()),
        );

        // `a[16..32] <= b[16..32]`
        let (lt_hi, eq_hi) = self.comparison_hi.constraints(
            &mut cb,
            from_bytes::expr(self.a.cells[16..32].to_vec()),
            from_bytes::expr(self.b.cells[16..32].to_vec()),
        );

        // `a < b` when:
        // - `a[16..32] < b[16..32]` OR
        // - `a[16..32] == b[16..32]` AND `a[0..16] < b[0..16]`
        let lt = select::expr(lt_hi, 1.expr(), eq_hi.clone() * lt_lo);
        // `a == b` when both parts are equal
        let eq = eq_hi * eq_lo;

        // The result is:
        // - `lt` when LT or GT
        // - `eq` when EQ
        let result = select::expr(is_eq_op, eq, lt);

        // Pop a and b from the stack, push the result on the stack.
        // When swap is enabled we swap stack places between a and b.
        // We can push result here directly because
        // it only uses the LSB of a word.
        cb.stack_pop(select::expr(swap.clone(), self.b.expr(), self.a.expr()));
        cb.stack_pop(select::expr(swap, self.a.expr(), self.b.expr()));
        cb.stack_push(result);

        // State transitions
        STATE_TRANSITION.constraints(&mut cb, state_curr, state_next);

        // Generate the constraint
        //cb.constraint(self.case_selector.expr(), name)
        let mut constrains = Vec::<Constraint<F>>::new();
        constrains.push(cb.constraint(self.case_selector.expr(), name));
        constrains
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        state: &mut CoreStateInstance,
        step: &ExecutionStep,
    ) -> Result<(), Error> {
        // EQ op check
        self.is_eq_op.assign(
            region,
            offset,
            F::from_u64(step.opcode.as_u8() as u64),
            F::from_u64(OpcodeId::EQ.as_u8() as u64),
        )?;

        // swap when doing GT
        let swap = self.swap.assign(
            region,
            offset,
            F::from_u64(step.opcode.as_u8() as u64),
            F::from_u64(OpcodeId::GT.as_u8() as u64),
        )?;

        // Inputs and output
        let a = select::value_word::<F>(
            swap,
            step.values[1].to_word(),
            step.values[0].to_word(),
        );
        let b = select::value_word::<F>(
            swap,
            step.values[0].to_word(),
            step.values[1].to_word(),
        );
        self.a.assign(region, offset, Some(a))?;
        self.b.assign(region, offset, Some(b))?;

        // `a[0..16] <= b[0..16]`
        self.comparison_lo.assign(
            region,
            offset,
            from_bytes::value::<F>(a[0..16].to_vec()),
            from_bytes::value::<F>(b[0..16].to_vec()),
        )?;

        // `a[16..32] <= b[16..32]`
        self.comparison_hi.assign(
            region,
            offset,
            from_bytes::value(a[16..32].to_vec()),
            from_bytes::value(b[16..32].to_vec()),
        )?;

        // State transitions
        STATE_TRANSITION.assign(state);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::super::{
        test::TestCircuit, Case, ExecutionStep, Operation,
    };
    use crate::{gadget::evm_word::encode, util::ToWord};
    use bus_mapping::{evm::OpcodeId, operation::Target};
    use halo2::{arithmetic::FieldExt, dev::MockProver};
    use num::BigUint;
    use pasta_curves::pallas::Base;

    macro_rules! try_test_circuit {
        ($execution_step:expr, $operations:expr, $result:expr) => {{
            let circuit =
                TestCircuit::<Base>::new($execution_step, $operations);
            let prover = MockProver::<Base>::run(10, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), $result);
        }};
    }

    fn compress(value: BigUint) -> Base {
        let r = Base::from_u64(1);
        encode(value.to_word().to_vec().into_iter().rev(), r)
    }

    fn check(opcode: OpcodeId, a: BigUint, b: BigUint, result: BigUint) {
        let all_ones = BigUint::from_bytes_le(&[1u8; 32]);
        try_test_circuit!(
            vec![
                ExecutionStep {
                    opcode: OpcodeId::PUSH32,
                    case: Case::Success,
                    values: vec![b.clone(), all_ones.clone()],
                },
                ExecutionStep {
                    opcode: OpcodeId::PUSH32,
                    case: Case::Success,
                    values: vec![a.clone(), all_ones],
                },
                ExecutionStep {
                    opcode,
                    case: Case::Success,
                    values: vec![a.clone(), b.clone()],
                }
            ],
            vec![
                Operation {
                    gc: 1,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        compress(b.clone()),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 2,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1022),
                        compress(a.clone()),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 3,
                    target: Target::Stack,
                    is_write: false,
                    values: [
                        Base::zero(),
                        Base::from_u64(1022),
                        compress(a),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 4,
                    target: Target::Stack,
                    is_write: false,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        compress(b),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 5,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        compress(result),
                        Base::zero(),
                    ]
                },
            ],
            Ok(())
        );
    }

    #[test]
    fn comparator_gadget() {
        let hi_lo = BigUint::from_bytes_be(&[[255u8; 16], [0u8; 16]].concat());
        let lo_hi = BigUint::from_bytes_be(&[[0u8; 16], [255u8; 16]].concat());

        // LT
        // hi_lo < lo_hi == 0
        check(OpcodeId::LT, hi_lo.clone(), lo_hi.clone(), 0x00u64.into());
        // lo_hi < hi_lo == 1
        check(OpcodeId::LT, lo_hi.clone(), hi_lo.clone(), 0x01u64.into());
        // hi_lo < hi_lo == 0
        check(OpcodeId::LT, hi_lo.clone(), hi_lo.clone(), 0x00u64.into());
        // lo_hi < lo_hi == 0
        check(OpcodeId::LT, lo_hi.clone(), lo_hi.clone(), 0x00u64.into());

        // GT
        // hi_lo > lo_hi == 1
        check(OpcodeId::GT, hi_lo.clone(), lo_hi.clone(), 0x01u64.into());
        // lo_hi > hi_lo == 0
        check(OpcodeId::GT, lo_hi.clone(), hi_lo.clone(), 0x00u64.into());
        // hi_lo > hi_lo == 0
        check(OpcodeId::GT, hi_lo.clone(), hi_lo.clone(), 0x00u64.into());
        // lo_hi > lo_hi == 0
        check(OpcodeId::GT, lo_hi.clone(), lo_hi.clone(), 0x00u64.into());

        // EQ
        // (hi_lo == lo_hi) == 0
        check(OpcodeId::EQ, hi_lo.clone(), lo_hi.clone(), 0x00u64.into());
        // (lo_hi == hi_lo) == 0
        check(OpcodeId::EQ, lo_hi.clone(), hi_lo.clone(), 0x00u64.into());
        // (hi_lo == hi_lo) == 1
        check(OpcodeId::EQ, hi_lo.clone(), hi_lo, 0x01u64.into());
        // (lo_hi == lo_hi) == 1
        check(OpcodeId::EQ, lo_hi.clone(), lo_hi, 0x01u64.into());
    }

    #[test]
    #[ignore]
    fn comparator_gadget_exhaustive() {
        let zero = BigUint::default();
        let max = BigUint::from_bytes_be(&[255u8; 32]);

        // LT
        // max < max == 0
        check(OpcodeId::LT, max.clone(), max.clone(), 0x00u64.into());
        // zero < zero == 0
        check(OpcodeId::LT, zero.clone(), zero.clone(), 0x00u64.into());
        // max < zero == 0
        check(OpcodeId::LT, max.clone(), zero.clone(), 0x00u64.into());
        // zero < max == 1
        check(OpcodeId::LT, zero.clone(), max.clone(), 0x01u64.into());

        // GT
        // max > max == 0
        check(OpcodeId::GT, max.clone(), max.clone(), 0x00u64.into());
        // zero > zero == 0
        check(OpcodeId::GT, zero.clone(), zero.clone(), 0x00u64.into());
        // max > zero == 1
        check(OpcodeId::GT, max.clone(), zero.clone(), 0x01u64.into());
        // zero > max == 0
        check(OpcodeId::GT, zero.clone(), max.clone(), 0x00u64.into());

        // EQ
        // (max == max) == 1
        check(OpcodeId::EQ, max.clone(), max.clone(), 0x01u64.into());
        // (zero == zero) == 1
        check(OpcodeId::EQ, zero.clone(), zero.clone(), 0x01u64.into());
        // (max == zero) == 0
        check(OpcodeId::EQ, max.clone(), zero.clone(), 0x00u64.into());
        // (zero == max) == 0
        check(OpcodeId::EQ, zero, max, 0x00u64.into());
    }
}
