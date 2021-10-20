use super::super::{Case, Cell, Constraint, CoreStateInstance, ExecutionStep};
use super::{CaseAllocation, CaseConfig, OpExecutionState, OpGadget};
use crate::util::Expr;
use bus_mapping::evm::OpcodeId;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::{array, convert::TryInto};

#[derive(Clone, Debug)]
struct JumpdestSuccessAllocation<F> {
    selector: Cell<F>,
}

#[derive(Clone, Debug)]
pub struct JumpdestGadget<F> {
    success: JumpdestSuccessAllocation<F>,
    // case selector
    out_of_gas: (
        Cell<F>, // case selector
        Cell<F>, // gas available
    ),
}

impl<F: FieldExt> OpGadget<F> for JumpdestGadget<F> {
    const RESPONSIBLE_OPCODES: &'static [OpcodeId] = &[OpcodeId::JUMPDEST];

    const CASE_CONFIGS: &'static [CaseConfig] = &[
        CaseConfig {
            case: Case::Success,
            num_word: 0,
            num_cell: 0,
            will_halt: false,
        },
        CaseConfig {
            case: Case::OutOfGas,
            num_word: 0,
            num_cell: 0,
            will_halt: true,
        },
    ];

    fn construct(case_allocations: Vec<CaseAllocation<F>>) -> Self {
        let [success, out_of_gas]: [CaseAllocation<F>; 2] =
            case_allocations.try_into().unwrap();
        Self {
            success: JumpdestSuccessAllocation {
                selector: success.selector,
            },
            out_of_gas: (
                out_of_gas.selector,
                out_of_gas.resumption.unwrap().gas_available,
            ),
        }
    }

    fn constraints(
        &self,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
    ) -> Vec<Constraint<F>> {
        let OpExecutionState { opcode, .. } = &state_curr;

        let common_polys = vec![opcode.expr() - OpcodeId::JUMPDEST.expr()];

        let success = {
            // gc & stack pointer remain unchanged
            let state_transaction_constraints = vec![
                state_next.gas_counter.expr()
                    - (state_curr.gas_counter.expr() + 1.expr()),
                state_next.gas_counter.expr()
                    - (state_curr.gas_counter.expr() + 1.expr()),
            ];

            let JumpdestSuccessAllocation { selector } = &self.success;

            Constraint {
                name: "Jumpdest success",
                selector: selector.expr(),
                polys: state_transaction_constraints,
                lookups: vec![],
            }
        };

        let out_of_gas = {
            let (case_selector, gas_available) = &self.out_of_gas;
            let gas_overdemand =
                state_curr.gas_counter.expr() + 1.expr() - gas_available.expr();
            Constraint {
                name: "Jumpdest out of gas",
                selector: case_selector.expr(),
                polys: vec![gas_overdemand - 1.expr()],
                lookups: vec![],
            }
        };

        array::IntoIter::new([success, out_of_gas])
            .map(move |mut constraint| {
                constraint.polys =
                    [common_polys.clone(), constraint.polys].concat();
                constraint
            })
            .collect()
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        core_state: &mut CoreStateInstance,
        execution_step: &ExecutionStep,
    ) -> Result<(), Error> {
        match execution_step.case {
            Case::Success => {
                self.assign_success(region, offset, core_state, execution_step)
            }
            Case::OutOfGas => {
                // TODO
                unimplemented!()
            }
            _ => unreachable!(),
        }
    }
}

impl<F: FieldExt> JumpdestGadget<F> {
    fn assign_success(
        &self,
        _: &mut Region<'_, F>,
        _: usize,
        core_state: &mut CoreStateInstance,
        _: &ExecutionStep,
    ) -> Result<(), Error> {
        core_state.program_counter += 1;
        core_state.gas_counter += 1;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::vec;

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
    fn jumpdest_gadget() {
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
                    // jumpdest
                    opcode: OpcodeId::JUMPDEST,
                    case: Case::Success,
                    values: vec![],
                }
            ],
            vec![Operation {
                gc: 1,
                target: Target::Stack,
                is_write: true,
                values: [
                    Base::zero(),
                    Base::from_u64(1023),
                    Base::from_u64(2 + 3),
                    Base::zero(),
                ]
            }],
            Ok(())
        );
    }
}
