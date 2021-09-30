use super::super::{
    BusMappingLookup, Case, Cell, Constraint, CoreStateInstance, ExecutionStep,
    FixedLookup, Lookup, Word,
};
use super::{CaseAllocation, CaseConfig, OpExecutionState, OpGadget};
use crate::util::{Expr, ToWord};
use bus_mapping::evm::{GasCost, OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::{array, convert::TryInto};

#[derive(Clone, Debug)]
struct DupSuccessAllocation<F> {
    case_selector: Cell<F>,
    word: Word<F>, // target word to dup （witness）
}

#[derive(Clone, Debug)]
pub struct DupGadget<F, const POSITION: usize> {
    success: DupSuccessAllocation<F>,
    stack_overflow: Cell<F>, // case selector
    out_of_gas: (
        Cell<F>, // case selector
        Cell<F>, // gas available
    ),
}

impl<F: FieldExt, const POSITION: usize> OpGadget<F>
    for DupGadget<F, POSITION>
{
    const RESPONSIBLE_OPCODES: &'static [OpcodeId] = &[
        //OpcodeId::from(POSITION as u8),
        from_u8(POSITION as u8),
    ];

    const CASE_CONFIGS: &'static [CaseConfig] = &[
        CaseConfig {
            case: Case::Success,
            num_word: 1,
            num_cell: 0,
            will_halt: false,
        },
        CaseConfig {
            case: Case::StackOverflow,
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
        let [mut success, stack_overflow, out_of_gas]: [CaseAllocation<F>; 3] =
            case_allocations.try_into().unwrap();
        Self {
            success: DupSuccessAllocation {
                case_selector: success.selector.clone(),
                word: success.words.pop().unwrap(),
            },
            stack_overflow: stack_overflow.selector,
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

        // lookup in range 16 for dup
        let common_lookups = vec![
            Lookup::FixedLookup(
                FixedLookup::Range16,
                [opcode.expr() - OpcodeId::DUP1.expr(), 0.expr(), 0.expr()],
            ),
            Lookup::FixedLookup(
                FixedLookup::Range16,
                [POSITION.expr() - OpcodeId::DUP1.expr(), 0.expr(), 0.expr()],
            ),
        ];

        let success = {
            // interpreter state transition constraints
            let state_transition_constraints = vec![
                state_next.global_counter.expr()
                    - (state_curr.global_counter.expr() + 2.expr()),
                state_next.program_counter.expr()
                    - (state_curr.program_counter.expr() + 1.expr()),
                // dupx contains one time push operation
                state_next.stack_pointer.expr()
                    - (state_curr.stack_pointer.expr() - 1.expr()),
                state_next.gas_counter.expr()
                    - (state_curr.gas_counter.expr() + GasCost::FASTEST.expr()),
            ];

            let DupSuccessAllocation {
                case_selector,
                word,
            } = &self.success;

            let bus_mapping_lookups = [
                // TODO: add 32 Bytecode lookups when supported
                vec![Lookup::BusMappingLookup(BusMappingLookup::Stack {
                    index_offset: (POSITION
                        - usize::from(OpcodeId::DUP1.as_u8()))
                        as i32,
                    value: word.expr(),
                    is_write: false,
                })],
                vec![Lookup::BusMappingLookup(BusMappingLookup::Stack {
                    index_offset: -1, // fixed as push decreases the stack pointer
                    value: word.expr(),
                    is_write: true,
                })],
            ]
            .concat();

            Constraint {
                name: "DupGadget success",
                selector: case_selector.expr(),
                polys: [state_transition_constraints].concat(),
                lookups: bus_mapping_lookups, //vec![]
            }
        };

        let stack_overflow = {
            let stack_pointer = state_curr.stack_pointer.expr();
            Constraint {
                name: "DupGadget stack overflow",
                selector: self.stack_overflow.expr(),
                polys: vec![stack_pointer],
                lookups: vec![],
            }
        };

        let out_of_gas = {
            let (one, two, three) = (1.expr(), 2.expr(), 3.expr());
            let (case_selector, gas_available) = &self.out_of_gas;
            let gas_overdemand = state_curr.gas_counter.expr()
                + GasCost::FASTEST.expr()
                - gas_available.expr();
            Constraint {
                name: "DupGadget out of gas",
                selector: case_selector.expr(),
                polys: vec![
                    (gas_overdemand.clone() - one)
                        * (gas_overdemand.clone() - two)
                        * (gas_overdemand - three),
                ],
                lookups: vec![],
            }
        };

        array::IntoIter::new([success, stack_overflow, out_of_gas])
            .map(move |mut constraint| {
                constraint.lookups =
                    [common_lookups.clone(), constraint.lookups].concat();
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
            Case::StackOverflow => {
                unimplemented!()
            }
            Case::OutOfGas => {
                unimplemented!()
            }
            _ => unreachable!(),
        }
    }
}

impl<F: FieldExt, const POSITION: usize> DupGadget<F, POSITION> {
    fn assign_success(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        core_state: &mut CoreStateInstance,
        execution_step: &ExecutionStep,
    ) -> Result<(), Error> {
        core_state.global_counter += 2; // read + push operation
        core_state.program_counter += 1;
        core_state.stack_pointer -= 1;
        core_state.gas_counter += 3;

        self.success.word.assign(
            region,
            offset,
            Some(execution_step.values[0].to_word()),
        )?;
        Ok(())
    }
}

// if imp From<u8> for OpcodeId, it not const function and can not be called within
// const RESPONSIBLE_OPCODES statement
const fn from_u8(opcode: u8) -> OpcodeId {
    match opcode {
        0x80u8 => OpcodeId::DUP1,
        0x81u8 => OpcodeId::DUP2,
        0x82u8 => OpcodeId::DUP3,
        0x83u8 => OpcodeId::DUP4,
        0x84u8 => OpcodeId::DUP5,
        0x85u8 => OpcodeId::DUP6,
        0x86u8 => OpcodeId::DUP7,
        0x87u8 => OpcodeId::DUP8,
        0x88u8 => OpcodeId::DUP9,
        0x89u8 => OpcodeId::DUP10,
        0x8au8 => OpcodeId::DUP11,
        0x8bu8 => OpcodeId::DUP12,
        0x8cu8 => OpcodeId::DUP13,
        0x8du8 => OpcodeId::DUP14,
        0x8eu8 => OpcodeId::DUP15,
        0x8fu8 => OpcodeId::DUP16,
        _ => OpcodeId::STOP,
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
                    values: vec![BigUint::from(0x04_05_06u64),],
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
                    opcode: OpcodeId::DUP1, // dup2 for testing
                    case: Case::Success,
                    values: vec![BigUint::from(0x03u64),],
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
