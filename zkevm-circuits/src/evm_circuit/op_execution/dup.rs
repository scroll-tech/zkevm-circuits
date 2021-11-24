use super::super::{Case, Cell, Constraint, ExecutionStep, Word};
use super::utils::common_cases::{
    OutOfGasCase, RangeStackUnderflowCase, StackOverflowCase,
};
use super::utils::constraint_builder::ConstraintBuilder;
use super::utils::StateTransition;
use super::{
    CaseAllocation, CaseConfig, CoreStateInstance, OpExecutionState, OpGadget,
};
use crate::impl_op_gadget;
use crate::util::{Expr, ToWord};
use bus_mapping::evm::{GasCost, OpcodeId};
use halo2::plonk::Error;
use halo2::{arithmetic::FieldExt, circuit::Region};
use std::convert::TryInto;

static STATE_TRANSITION: StateTransition = StateTransition {
    gc_delta: Some(2), // 1 stack read + 1 stack push
    pc_delta: Some(1),
    sp_delta: Some(-1),
    gas_delta: Some(GasCost::FASTEST.as_usize()),
};
const NUM_PUSHED: usize = 1;

impl_op_gadget!(
    #range
    [
        DUP1,  DUP2,  DUP3,  DUP4,  DUP5,  DUP6,  DUP7,  DUP8,
        DUP9, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16,
    ]
    DupGadget {
        DupSuccessCase(),
        RangeStackUnderflowCase(OpcodeId::DUP1, 16, 0),
        StackOverflowCase(NUM_PUSHED),
        OutOfGasCase(STATE_TRANSITION.gas_delta.unwrap()),
    }
);

#[derive(Clone, Debug)]
struct DupSuccessCase<F> {
    case_selector: Cell<F>,
    value: Word<F>,
}

impl<F: FieldExt> DupSuccessCase<F> {
    pub(crate) const CASE_CONFIG: &'static CaseConfig = &CaseConfig {
        case: Case::Success,
        num_word: 1, // value
        num_cell: 0,
        will_halt: false,
    };

    pub(crate) fn construct(alloc: &mut CaseAllocation<F>) -> Self {
        Self {
            case_selector: alloc.selector.clone(),
            value: alloc.words.pop().unwrap(),
        }
    }

    pub(crate) fn constraint(
        &self,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
        name: &'static str,
    ) -> Vec<Constraint<F>> {
        let mut cb = ConstraintBuilder::default();

        // The stack index we have to peek, deduced from the 'x' value of 'dupx'
        // The offset starts at 0 for DUP1
        let dup_offset = state_curr.opcode.expr() - OpcodeId::DUP1.expr();

        // Peek the value at `dup_offset` and push the value on the stack
        cb.stack_lookup(dup_offset, self.value.expr(), false);
        cb.stack_push(self.value.expr());

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
        // Input
        self.value
            .assign(region, offset, Some(step.values[0].to_word()))?;

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

    #[test]
    fn dup2_gadget() {
        try_test_circuit!(
            vec![
                ExecutionStep {
                    opcode: OpcodeId::PUSH3,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x04_05_06u64),
                        BigUint::from(0x01_01_01u64),
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::PUSH1,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x03u64),
                        BigUint::from(0x01u64),
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::DUP2, // dup2 for testing
                    case: Case::Success,
                    values: vec![BigUint::from(0x04_05_06u64)],
                },
            ],
            vec![
                Operation {
                    gc: 1,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        Base::from_u64(4 + 5 + 6),
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
                        Base::from_u64(3),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 3,
                    target: Target::Stack,
                    is_write: false,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        Base::from_u64(4 + 5 + 6),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 4,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1021),
                        Base::from_u64(4 + 5 + 6),
                        Base::zero(),
                    ]
                }
            ],
            Ok(())
        );
    }

    #[test]
    fn dup1_gadget() {
        try_test_circuit!(
            vec![
                ExecutionStep {
                    opcode: OpcodeId::PUSH3,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x04_05_06u64),
                        BigUint::from(0x01_01_01u64),
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::PUSH1,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x03u64),
                        BigUint::from(0x01u64),
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::DUP1, // dup1 for testing
                    case: Case::Success,
                    values: vec![BigUint::from(0x03u64)],
                },
            ],
            vec![
                Operation {
                    gc: 1,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        Base::from_u64(4 + 5 + 6),
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
                        Base::from_u64(3),
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
                        Base::from_u64(3),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 4,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1021),
                        Base::from_u64(3),
                        Base::zero(),
                    ]
                }
            ],
            Ok(())
        );
    }
}
