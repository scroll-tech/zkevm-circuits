use super::super::{Case, Cell, Constraint, ExecutionStep, Word};
use super::utils::common_cases::{OutOfGasCase, RangeStackUnderflowCase};
use super::utils::constraint_builder::ConstraintBuilder;
use super::utils::StateTransition;
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
    gc_delta: Some(4), // 2 stack reads + 2 stack writes
    pc_delta: Some(1),
    sp_delta: Some(0),
    gas_delta: Some(GasCost::FASTEST.as_usize()),
};

impl_op_gadget!(
    #range
    [
        SWAP1,  SWAP2,  SWAP3,  SWAP4,  SWAP5,  SWAP6,  SWAP7,  SWAP8,
        SWAP9, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16,
    ]
    SwapGadget {
        SwapSuccessCase(),
        RangeStackUnderflowCase(OpcodeId::SWAP1, 16, 1),
        OutOfGasCase(STATE_TRANSITION.gas_delta.unwrap()),
    }
);

#[derive(Clone, Debug)]
struct SwapSuccessCase<F> {
    case_selector: Cell<F>,
    values: [Word<F>; 2],
}

impl<F: FieldExt> SwapSuccessCase<F> {
    pub(crate) const CASE_CONFIG: &'static CaseConfig = &CaseConfig {
        case: Case::Success,
        num_word: 2, // values
        num_cell: 0,
        will_halt: false,
    };

    pub(crate) fn construct(alloc: &mut CaseAllocation<F>) -> Self {
        Self {
            case_selector: alloc.selector.clone(),
            values: array_init(|_| alloc.words.pop().unwrap()),
        }
    }

    pub(crate) fn constraint(
        &self,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
        name: &'static str,
    ) -> Vec<Constraint<F>> {
        let mut cb = ConstraintBuilder::default();

        // The stack index we have to peek, deduced from the 'x' value of 'swapx'
        // The offset starts at 1 for SWAP1
        let swap_offset =
            state_curr.opcode.expr() - (OpcodeId::SWAP1.as_u64() - 1).expr();

        // Peek the value at `swap_offset`
        cb.stack_lookup(swap_offset.clone(), self.values[0].expr(), false);
        // Peek the value at the top of the stack
        cb.stack_lookup(0.expr(), self.values[1].expr(), false);
        // Write the value previously at the top of the stack to `swap_offset`
        cb.stack_lookup(swap_offset, self.values[1].expr(), true);
        // Write the value previously at `swap_offset` to the top of the stack
        cb.stack_lookup(0.expr(), self.values[0].expr(), true);

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
        // Inputs
        for idx in 0..2 {
            self.values[idx].assign(
                region,
                offset,
                Some(step.values[idx].to_word()),
            )?;
        }

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

    // TODO: add failure cases
    #[test]
    fn swap2_gadget() {
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
                    opcode: OpcodeId::PUSH2,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x05_04u64),
                        BigUint::from(0x01_01u64)
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::PUSH1,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x06u64),
                        BigUint::from(0x01u64)
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::SWAP2,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x03_02_01u64),
                        BigUint::from(0x06u64),
                    ],
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
                        Base::from_u64(1 + 2 + 3),
                        Base::zero(),
                    ],
                },
                Operation {
                    gc: 2,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1022),
                        Base::from_u64(4 + 5),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 3,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1021),
                        Base::from_u64(6),
                        Base::zero(),
                    ]
                },
                // swap1 1021 <=> 1023
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
                    is_write: false,
                    values: [
                        Base::zero(),
                        Base::from_u64(1021),
                        Base::from_u64(6),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 6,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        Base::from_u64(6),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 7,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1021),
                        Base::from_u64(1 + 2 + 3),
                        Base::zero(),
                    ]
                }
            ],
            Ok(())
        );
    }

    #[test]
    fn swap1_gadget() {
        // SWAP1
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
                    opcode: OpcodeId::PUSH2,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x05_04u64),
                        BigUint::from(0x01_01u64)
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::SWAP1,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x03_02_01u64),
                        BigUint::from(0x05_04u64),
                    ],
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
                        Base::from_u64(1 + 2 + 3),
                        Base::zero(),
                    ],
                },
                Operation {
                    gc: 2,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1022),
                        Base::from_u64(4 + 5),
                        Base::zero(),
                    ]
                },
                // swap1 1023 <=> 1022
                Operation {
                    gc: 3,
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
                    gc: 4,
                    target: Target::Stack,
                    is_write: false,
                    values: [
                        Base::zero(),
                        Base::from_u64(1022),
                        Base::from_u64(4 + 5),
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
                        Base::from_u64(4 + 5),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 6,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1022),
                        Base::from_u64(1 + 2 + 3),
                        Base::zero(),
                    ]
                }
            ],
            Ok(())
        );
    }
}
