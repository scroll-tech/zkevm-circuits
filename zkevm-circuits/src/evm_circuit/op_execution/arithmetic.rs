use super::super::{Case, Cell, Constraint, ExecutionStep, Word};
use super::utils::common_cases::{OutOfGasCase, StackUnderflowCase};
use super::utils::constraint_builder::ConstraintBuilder;
use super::utils::math_gadgets::PairSelectGadget;
use super::utils::{select, StateTransition};
use super::{
    CaseAllocation, CaseConfig, CoreStateInstance, OpExecutionState, OpGadget,
};
use crate::impl_op_gadget;
use crate::util::{Expr, ToWord};
use array_init::array_init;
use bus_mapping::evm::{GasCost, OpcodeId};
use halo2::plonk::Error;
use halo2::{arithmetic::FieldExt, circuit::Region};
use std::convert::TryInto;

static STATE_TRANSITION: StateTransition = StateTransition {
    gc_delta: Some(3), // 2 stack pops + 1 stack push
    pc_delta: Some(1),
    sp_delta: Some(1),
    gas_delta: Some(GasCost::FASTEST.as_usize()),
};
const NUM_POPPED: usize = 2;

impl_op_gadget!(
    #set[ADD, SUB]
    AddGadget {
        AddSuccessCase(),
        StackUnderflowCase(NUM_POPPED),
        OutOfGasCase(STATE_TRANSITION.gas_delta.unwrap()),
    }
);

#[derive(Clone, Debug)]
struct AddSuccessCase<F> {
    case_selector: Cell<F>,
    a: Word<F>,
    b: Word<F>,
    c: Word<F>,
    carry: [Cell<F>; 32],
    swap: PairSelectGadget<F>,
}

// AddGadget verifies ADD and SUB at the same time by an extra swap flag,
// when it's ADD, we annotate stack as [a, b, ...] and [c, ...],
// when it's SUB, we annotate stack as [a, c, ...] and [b, ...].
// Then we verify if a + b is equal to c.
impl<F: FieldExt> AddSuccessCase<F> {
    pub(crate) const CASE_CONFIG: &'static CaseConfig = &CaseConfig {
        case: Case::Success,
        num_word: 3,                                     // a + b + c
        num_cell: 32 + PairSelectGadget::<F>::NUM_CELLS, // 32 carry + swap
        will_halt: false,
    };

    pub(crate) fn construct(alloc: &mut CaseAllocation<F>) -> Self {
        Self {
            case_selector: alloc.selector.clone(),
            a: alloc.words.pop().unwrap(),
            b: alloc.words.pop().unwrap(),
            c: alloc.words.pop().unwrap(),
            carry: array_init(|_| alloc.cells.pop().unwrap()),
            swap: PairSelectGadget::construct(alloc),
        }
    }

    pub(crate) fn constraint(
        &self,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
        name: &'static str,
    ) -> Vec<Constraint<F>> {
        let mut cb = ConstraintBuilder::default();

        // Swap b and c if it's SUB
        let (swap, _) = self.swap.constraints(
            &mut cb,
            state_curr.opcode.expr(),
            OpcodeId::SUB.expr(),
            OpcodeId::ADD.expr(),
        );

        // Do the addition per byte with carry
        for idx in 0..32 {
            // carry needs to be boolean
            cb.require_boolean(self.carry[idx].expr());

            // carry_out * 256 + c == a + b + carry_in
            cb.require_equal(
                self.carry[idx].expr() * 256.expr() + self.c.cells[idx].expr(),
                self.a.cells[idx].expr()
                    + self.b.cells[idx].expr()
                    + if idx == 0 {
                        // first carry_in is always 0
                        0.expr()
                    } else {
                        self.carry[idx - 1].expr()
                    },
            );
        }

        // ADD: Pop a and b from the stack, push c on the stack
        // SUB: Pop a and c from the stack, push b on the stack
        cb.stack_pop(self.a.expr());
        cb.stack_pop(select::expr(swap.clone(), self.c.expr(), self.b.expr()));
        cb.stack_push(select::expr(swap, self.b.expr(), self.c.expr()));

        // State transitions
        STATE_TRANSITION.constraints(&mut cb, state_curr, state_next);

        // Generate the constraint
        vec![cb.constraint(self.case_selector.expr(), name)]
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        state: &mut CoreStateInstance,
        step: &ExecutionStep,
    ) -> Result<(), Error> {
        // Inputs and output
        self.a
            .assign(region, offset, Some(step.values[0].to_word()))?;
        self.b
            .assign(region, offset, Some(step.values[1].to_word()))?;
        self.c
            .assign(region, offset, Some(step.values[2].to_word()))?;

        // Swap
        self.swap.assign(
            region,
            offset,
            F::from_u64(step.opcode as u64),
            F::from_u64(OpcodeId::SUB.as_u64()),
            F::from_u64(OpcodeId::ADD.as_u64()),
        )?;

        // Generate carry values
        self.carry
            .iter()
            .zip(step.values[3].to_word().iter())
            .map(|(alloc, carry)| {
                alloc.assign(region, offset, Some(F::from_u64(*carry as u64)))
            })
            .collect::<Result<Vec<_>, _>>()?;

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
    use bus_mapping::{evm::OpcodeId, operation::Target};
    use halo2::{arithmetic::FieldExt, dev::MockProver};
    use num::BigUint;
    use pasta_curves::pallas::Base;

    macro_rules! try_test_circuit {
        ($execution_steps:expr, $operations:expr, $result:expr) => {{
            let circuit =
                TestCircuit::<Base>::new($execution_steps, $operations);
            let prover = MockProver::<Base>::run(10, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), $result);
        }};
    }

    // TODO: use evm word
    // TODO: add failure cases

    #[test]
    fn add_gadget() {
        // ADD
        try_test_circuit!(
            vec![
                ExecutionStep {
                    opcode: OpcodeId::PUSH3,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x03_02_01u64),
                        BigUint::from(0x01_01_01u64)
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::PUSH3,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x06_05_04u64),
                        BigUint::from(0x01_01_01u64)
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::ADD,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x06_05_04u64),
                        BigUint::from(0x03_02_01u64),
                        BigUint::from(0x09_07_05u64),
                        BigUint::from(0u64) // carry
                    ],
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
                        Base::from_u64(1 + 2 + 3),
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
                        Base::from_u64(4 + 5 + 6),
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
                        Base::from_u64(4 + 5 + 6),
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
                        Base::from_u64(1 + 2 + 3),
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
                        Base::from_u64(5 + 7 + 9),
                        Base::zero(),
                    ]
                }
            ],
            Ok(())
        );
        // SUB
        try_test_circuit!(
            vec![
                ExecutionStep {
                    opcode: OpcodeId::PUSH3,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x09_07_05u64),
                        BigUint::from(0x01_01_01u64)
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::PUSH3,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x06_05_04u64),
                        BigUint::from(0x01_01_01u64)
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::SUB,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x06_05_04u64),
                        BigUint::from(0x03_02_01u64),
                        BigUint::from(0x09_07_05u64),
                        BigUint::from(0u64) // carry
                    ],
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
                        Base::from_u64(5 + 7 + 9),
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
                        Base::from_u64(4 + 5 + 6),
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
                        Base::from_u64(4 + 5 + 6),
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
                        Base::from_u64(5 + 7 + 9),
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
                        Base::from_u64(1 + 2 + 3),
                        Base::zero(),
                    ]
                }
            ],
            Ok(())
        );
    }
}
