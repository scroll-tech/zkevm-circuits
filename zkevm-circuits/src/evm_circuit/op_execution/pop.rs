use super::super::{
    BusMappingLookup, Case, Cell, Constraint, CoreStateInstance, ExecutionStep,
    Lookup, Word,
};
use super::{CaseAllocation, CaseConfig, OpExecutionState, OpGadget};
use crate::util::{Expr, ToWord};
use bus_mapping::evm::{GasCost, OpcodeId};
use halo2::plonk::Error;
use halo2::{arithmetic::FieldExt, circuit::Region};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub struct PopGadget<F> {
    success: PopSuccessAllocation<F>,
    stack_underflow: Cell<F>, // case selector
    out_of_gas: (
        Cell<F>, // case selector
        Cell<F>, // gas available
    ),
}

#[derive(Clone, Debug)]
struct PopSuccessAllocation<F> {
    case_selector: Cell<F>,
    value: Word<F>,
}
impl<F: FieldExt> OpGadget<F> for PopGadget<F> {
    const RESPONSIBLE_OPCODES: &'static [OpcodeId] = &[
        OpcodeId::POP, // 0x50 of op id
    ];

    const CASE_CONFIGS: &'static [CaseConfig] = &[
        CaseConfig {
            case: Case::Success,
            num_word: 1, // poped value
            num_cell: 0,
            will_halt: false,
        },
        CaseConfig {
            case: Case::StackUnderflow,
            num_word: 0,
            num_cell: 0,
            will_halt: true,
        },
        CaseConfig {
            case: Case::OutOfGas,
            num_word: 0,
            num_cell: 0,
            will_halt: true,
        },
    ];

    fn construct(case_allocations: Vec<CaseAllocation<F>>) -> Self {
        let [success, stack_underflow, out_of_gas]: [CaseAllocation<F>; 3] =
            case_allocations.try_into().unwrap();
        Self {
            success: PopSuccessAllocation {
                case_selector: success.selector.clone(),
                value: success.words[0].clone(),
            },

            stack_underflow: stack_underflow.selector,
            out_of_gas: (
                out_of_gas.selector.clone(),
                out_of_gas.resumption.unwrap().gas_available,
            ),
        }
    }

    fn constraints(
        &self,
        op_execution_state_curr: &OpExecutionState<F>,
        op_execution_state_next: &OpExecutionState<F>,
    ) -> Vec<Constraint<F>> {
        let OpExecutionState { opcode, .. } = &op_execution_state_curr;
        let common_polys = vec![opcode.expr() - OpcodeId::POP.expr()];

        let success = {
            // interpreter state transition constraints
            let op_execution_state_transition_constraints = vec![
                op_execution_state_next.global_counter.expr()
                    - (op_execution_state_curr.global_counter.expr()
                        + 1.expr()),
                op_execution_state_next.stack_pointer.expr()
                    - (op_execution_state_curr.stack_pointer.expr() + 1.expr()),
                op_execution_state_next.program_counter.expr()
                    - (op_execution_state_curr.program_counter.expr()
                        + 1.expr()),
                op_execution_state_next.gas_counter.expr()
                    - (op_execution_state_curr.gas_counter.expr()
                        + GasCost::QUICK.expr()),
            ];

            let PopSuccessAllocation {
                case_selector,
                value,
            } = &self.success;

            let bus_mapping_lookups = vec![
                // constrain value come from top of stack
                Lookup::BusMappingLookup(BusMappingLookup::Stack {
                    index_offset: 0.expr(),
                    value: value.expr(),
                    is_write: false,
                }),
            ];

            Constraint {
                name: "PopGadget success",
                selector: case_selector.expr(),
                polys: [
                    common_polys.clone(),
                    op_execution_state_transition_constraints,
                ]
                .concat(),
                lookups: bus_mapping_lookups,
            }
        };

        let stack_underflow = {
            let stack_pointer = op_execution_state_curr.stack_pointer.expr();
            Constraint {
                name: "PopGadget stack underflow",
                selector: self.stack_underflow.expr(),
                polys: vec![
                    common_polys.clone(),
                    vec![(stack_pointer - 1024.expr())],
                ]
                .concat(),
                lookups: vec![],
            }
        };

        let out_of_gas = {
            let (case_selector, gas_available) = &self.out_of_gas;
            let gas_overdemand = op_execution_state_curr.gas_counter.expr()
                + GasCost::QUICK.expr()
                - gas_available.expr();
            Constraint {
                name: "PopGadget out of gas",
                selector: case_selector.expr(),
                polys: [
                    common_polys,
                    vec![
                        (gas_overdemand.clone() - 1.expr())
                            * (gas_overdemand - 2.expr()),
                    ],
                ]
                .concat(),
                lookups: vec![],
            }
        };

        vec![success, stack_underflow, out_of_gas]
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        op_execution_state: &mut CoreStateInstance,
        execution_step: &ExecutionStep,
    ) -> Result<(), Error> {
        match execution_step.case {
            Case::Success => self.assign_success(
                region,
                offset,
                op_execution_state,
                execution_step,
            ),
            Case::StackUnderflow => {
                unimplemented!()
            }
            Case::OutOfGas => {
                unimplemented!()
            }
            _ => unreachable!(),
        }
    }
}

impl<F: FieldExt> PopGadget<F> {
    fn assign_success(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        op_execution_state: &mut CoreStateInstance,
        execution_step: &ExecutionStep,
    ) -> Result<(), Error> {
        op_execution_state.global_counter += 1;
        op_execution_state.program_counter += 1;
        op_execution_state.stack_pointer += 1;
        op_execution_state.gas_counter += 2; // pop consume 2 gas point
                                             // no word assignments

        self.success
            .case_selector
            .assign(region, offset, Some(F::from_u64(1)))
            .unwrap();
        self.success
            .value
            .assign(region, offset, Some(execution_step.values[0].to_word()))
            .unwrap();
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
    fn pop_gadget() {
        try_test_circuit!(
            vec![
                ExecutionStep {
                    opcode: OpcodeId::PUSH2,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x02_03u64),
                        BigUint::from(0x01_01u64),
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::POP,
                    case: Case::Success,
                    values: vec![BigUint::from(0x02_03u64)],
                },
                ExecutionStep {
                    opcode: OpcodeId::PUSH3,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x06_05_04u64),
                        BigUint::from(0x01_01_01u64)
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
                        Base::from_u64(2 + 3),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 2,
                    target: Target::Stack,
                    is_write: false,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        Base::from_u64(2 + 3),
                        Base::zero(),
                    ]
                },
                Operation {
                    gc: 3,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1023),
                        Base::from_u64(4 + 5 + 6),
                        Base::zero(),
                    ]
                }
            ],
            Ok(())
        );
    }
}
