use super::super::{
    BusMappingLookup, Case, Cell, Constraint, CoreStateInstance, ExecutionStep,
    FixedLookup, Lookup, Word,
};
use super::{CaseAllocation, CaseConfig, OpExecutionState, OpGadget};
use crate::util::{Expr, ToWord};
use bus_mapping::evm::{GasCost, OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error, plonk::Expression};
use std::{array, convert::TryInto};

#[derive(Clone, Debug)]
struct MulSuccessAllocation<F> {
    selector: Cell<F>,
    a: Word<F>,
    b: Word<F>,
    c: Word<F>,
    t0: Cell<F>,
    t1: Cell<F>,
    t2: Cell<F>,
    t3: Cell<F>,
    v0: [Cell<F>; 9],
    v1: [Cell<F>; 9],
}

#[derive(Clone, Debug)]
pub struct MulGadget<F> {
    success: MulSuccessAllocation<F>,
    stack_underflow: Cell<F>,
    out_of_gas: (Cell<F>, Cell<F>),
}
impl<F: FieldExt> OpGadget<F> for MulGadget<F> {
    const RESPONSIBLE_OPCODES: &'static [OpcodeId] =
        &[OpcodeId::MUL];

    const CASE_CONFIGS: &'static [CaseConfig] = &[
        CaseConfig {
            case: Case::Success,
            num_word: 3,
            num_cell: 22,
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
        let [mut success, stack_underflow, out_of_gas]: [CaseAllocation<F>; 3] =
            case_allocations.try_into().unwrap();
        Self {
            success: MulSuccessAllocation {
                selector: success.selector,
                a: success.words.pop().unwrap(),
                b: success.words.pop().unwrap(),
                c: success.words.pop().unwrap(),
                t0: success.cells.pop().unwrap(),
                t1: success.cells.pop().unwrap(),
                t2: success.cells.pop().unwrap(),
                t3: success.cells.pop().unwrap(),
                v0: success
                    .cells
                    .drain(0..9)
                    .collect::<Vec<Cell<F>>>()
                    .try_into()
                    .unwrap(),
                v1: success
                    .cells
                    .drain(0..9)
                    .collect::<Vec<Cell<F>>>()
                    .try_into()
                    .unwrap(),
            },
            stack_underflow: stack_underflow.selector,
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

        let common_polys = vec![
            (opcode.expr() - OpcodeId::MUL.expr()),
        ];

        let success = {
            // interpreter state transition constraints
            let state_transition_constraints = vec![
                state_next.global_counter.expr()
                    - (state_curr.global_counter.expr() + 3.expr()),
                state_next.stack_pointer.expr()
                    - (state_curr.stack_pointer.expr() + 1.expr()),
                state_next.program_counter.expr()
                    - (state_curr.program_counter.expr() + 1.expr()),
                state_next.gas_counter.expr()
                    - (state_curr.gas_counter.expr() + GasCost::FAST.expr()),
            ];

            let MulSuccessAllocation {
                selector,
                a,
                b,
                c,
                t0,
                t1,
                t2,
                t3,
                v0,
                v1,
            } = &self.success;

            //merge 8 8-bit cell for a 64-bit expression for a, b, c
            let mut a_digits = vec![];
            let mut b_digits = vec![];
            let mut c_digits = vec![];
            let mut cur_v0 = 0.expr();
            let mut cur_v1 = 0.expr();
            for virtual_idx in 0..4 {
                let mut tmp_a = 0.expr();
                let mut tmp_b = 0.expr();
                let mut tmp_c = 0.expr();
                let mut radix = Expression::Constant(F::from_u64(1u64));
                for idx in 0..8 {
                    let now_idx = (virtual_idx * 8 + idx) as usize;
                    tmp_a = tmp_a + radix.clone() * a.cells[now_idx].expr();
                    tmp_b = tmp_b + radix.clone() * b.cells[now_idx].expr();
                    tmp_c = tmp_c + radix.clone() * c.cells[now_idx].expr();
                    radix = radix * (1 << 8).expr();
                }
                a_digits.push(tmp_a);
                b_digits.push(tmp_b);
                c_digits.push(tmp_c);
            }
            let mut tmp_radix = Expression::Constant(F::from_u64(1u64));
            let radix_constant_8 = Expression::Constant(F::from_u64(1u64 << 8));
            for idx in 0..9 {
                cur_v0 = cur_v0 + tmp_radix.clone() * v0[idx].expr();
                cur_v1 = cur_v1 + tmp_radix.clone() * v1[idx].expr();
                tmp_radix = tmp_radix * radix_constant_8.clone();
            }

            let mut shr_constraints = vec![];
            for total_idx in 0..4 {
                let mut rhs_sum = 0.expr(); 
                for a_id in 0..=total_idx {
                    let (a_idx, b_idx) = (a_id as usize, (total_idx - a_id) as usize); 
                    rhs_sum = rhs_sum + a_digits[a_idx].clone() * b_digits[b_idx].clone();
                }
                shr_constraints.push(
                    match total_idx {
                        0 => t0.expr() - rhs_sum,
                        1 => t1.expr() - rhs_sum,
                        2 => t2.expr() - rhs_sum,
                        3 => t3.expr() - rhs_sum,
                        _ => unimplemented!(),
                    }
                );
            }
            let radix_constant = Expression::Constant(F::from_u64(1u64 << 32));
            let radix_constant_64 = radix_constant.clone() * radix_constant;
            let radix_constant_128 = radix_constant_64.clone() * radix_constant_64.clone();
            shr_constraints.push(
                cur_v0.clone() * radix_constant_128.clone()
                    - (
                        t0.expr() + t1.expr() * radix_constant_64.clone()
                        - (c_digits[0].clone() + c_digits[1].clone() * radix_constant_64.clone())
                    )
            );
            shr_constraints.push(
                cur_v1 * radix_constant_128.clone()
                    - (
                        cur_v0 + t2.expr() + t3.expr() * radix_constant_64.clone()
                        - (c_digits[2].clone() + c_digits[3].clone() * radix_constant_64.clone())
                    )
            );

            #[allow(clippy::suspicious_operation_groupings)]
            let bus_mapping_lookups = vec![//busmapping check
                Lookup::BusMappingLookup(BusMappingLookup::Stack {
                    index_offset: 0,
                    value: a.expr(),
                    is_write: false,
                }),
                Lookup::BusMappingLookup(BusMappingLookup::Stack {
                    index_offset: 1,
                    value: b.expr(),
                    is_write: false,
                }),
                Lookup::BusMappingLookup(BusMappingLookup::Stack {
                    index_offset: 1,
                    value: c.expr(),
                    is_write: true,
                }),
            ];
            
            let mut v_lookups = vec![];
            for idx in 0..9 {
                v_lookups.push(
                    Lookup::FixedLookup(
                        FixedLookup::Range256,
                        [v0[idx].expr(), 0.expr(), 0.expr()],
                    )
                );
                v_lookups.push(
                    Lookup::FixedLookup(
                        FixedLookup::Range256,
                        [v1[idx].expr(), 0.expr(), 0.expr()],
                    )
                );
            }
            Constraint {
                name: "MulGadget success",
                selector: selector.expr(),
                polys: [
                    state_transition_constraints,
                    shr_constraints,
                ]
                .concat(),
                lookups: [
                    bus_mapping_lookups,
                    v_lookups,
                ].concat(),
            }
        };

        let stack_underflow = {
            let stack_pointer = state_curr.stack_pointer.expr();
            Constraint {
                name: "MulGadget stack underflow",
                selector: self.stack_underflow.expr(),
                polys: vec![
                    (stack_pointer.clone() - 1024.expr())
                        * (stack_pointer - 1023.expr()),
                ],
                lookups: vec![],
            }
        };

        let out_of_gas = {
            let (selector, gas_available) = &self.out_of_gas;
            let gas_overdemand = state_curr.gas_counter.expr()
                + GasCost::FAST.expr()
                - gas_available.expr();
            Constraint {
                name: "MulGadget out of gas",
                selector: selector.expr(),
                polys: vec![
                    (gas_overdemand.clone() - 1.expr())
                        * (gas_overdemand.clone() - 2.expr())
                        * (gas_overdemand.clone() - 3.expr())
                        * (gas_overdemand.clone() - 4.expr())
                        * (gas_overdemand.clone() - 5.expr()),
                ],
                lookups: vec![],
            }
        };

        array::IntoIter::new([success, stack_underflow, out_of_gas])
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

impl<F: FieldExt> MulGadget<F> {
    fn assign_success(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        core_state: &mut CoreStateInstance,
        execution_step: &ExecutionStep,
    ) -> Result<(), Error> {
        core_state.global_counter += 3;
        core_state.program_counter += 1;
        core_state.stack_pointer += 1;
        core_state.gas_counter += 5;
        self.success.a.assign(
            region,
            offset,
            Some(execution_step.values[0].to_word()),
        )?;
        self.success.b.assign(
            region,
            offset,
            Some(execution_step.values[1].to_word()),
        )?;
        self.success.c.assign(
            region,
            offset,
            Some(execution_step.values[2].to_word()),
        )?;
        let radix = F::from_u64(1u64 << 63) * F::from_u64(2u64);
        let t0_digits = execution_step.values[3].to_u64_digits();
        let t0 = if t0_digits.is_empty() {
            F::zero()
        } else {
            let mut tmp = F::zero();
            let mut tmp_radix = F::one();
            for idx in 0.. t0_digits.len(){
                tmp = tmp + tmp_radix * F::from_u64(t0_digits[idx as usize]);
                tmp_radix = tmp_radix * radix.clone()
            }
            tmp
        };
        let t1_digits = execution_step.values[4].to_u64_digits();
        let t1 = if t1_digits.is_empty() {
            F::zero()
        } else {
            let mut tmp = F::zero();
            let mut tmp_radix = F::one();
            for idx in 0.. t1_digits.len(){
                tmp = tmp + tmp_radix * F::from_u64(t1_digits[idx as usize]);
                tmp_radix = tmp_radix * radix.clone()
            }
            tmp
        };
        let t2_digits = execution_step.values[5].to_u64_digits();
        let t2 = if t2_digits.is_empty() {
            F::zero()
        } else {
            let mut tmp = F::zero();
            let mut tmp_radix = F::one();
            for idx in 0.. t2_digits.len(){
                tmp = tmp + tmp_radix * F::from_u64(t2_digits[idx as usize]);
                tmp_radix = tmp_radix * radix.clone()
            }
            tmp
        };
        let t3_digits = execution_step.values[6].to_u64_digits();
        let t3 = if t3_digits.is_empty() {
            F::zero()
        } else {
            let mut tmp = F::zero();
            let mut tmp_radix = F::one();
            for idx in 0.. t3_digits.len(){
                tmp = tmp + tmp_radix * F::from_u64(t3_digits[idx as usize]);
                tmp_radix = tmp_radix * radix.clone()
            }
            tmp
        };
        self.success.t0.assign(region, offset, Some(t0))?;
        self.success.t1.assign(region, offset, Some(t1))?;
        self.success.t2.assign(region, offset, Some(t2))?;
        self.success.t3.assign(region, offset, Some(t3))?;
        self.success
            .v0
            .iter()
            .zip(execution_step.values[7].to_word().iter())
            .map(|(alloc, value)|{
                alloc.assign(region, offset, Some(F::from_u64(*value as u64)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.success
            .v1
            .iter()
            .zip(execution_step.values[8].to_word().iter())
            .map(|(alloc, value)|{
                alloc.assign(region, offset, Some(F::from_u64(*value as u64)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }
}
#[cfg(test)]
mod test {
    use super::super::super::{
        test::TestCircuit, Case, ExecutionStep, Operation,
    };
    use crate::util::ToWord;
    use bus_mapping::{evm::OpcodeId, operation::Target};
    use halo2::{arithmetic::FieldExt, dev::MockProver};
    use num::BigUint;
    use rand::Rng;
    use pasta_curves::pallas::Base;

    macro_rules! try_test_circuit {
        ($execution_step:expr, $operations:expr, $result:expr) => {{
            let circuit =
                TestCircuit::<Base>::new($execution_step, $operations);
            let prover = MockProver::<Base>::run(10, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), $result);
        }};
    }

    fn result_generate(a: &BigUint, b: &BigUint) -> (
            BigUint, BigUint, BigUint, BigUint, BigUint, BigUint, BigUint, u64, u64, u64
        ) {
        let constant_64 = BigUint::from(1u128 << 64);
        let constant_128 = constant_64.clone() * constant_64.clone();
        let constant_256 = constant_128.clone() * constant_128.clone();
        let c = a * b % constant_256;
        let a8s = a.to_word();
        let b8s = b.to_word();
        let c8s = c.to_word();
        let mut suma :u64 = 0;
        let mut sumb :u64 = 0;
        let mut sumc :u64 = 0;
        for idx in 0..32 {
            let tmp_a = if a8s.len() >= idx + 1 { a8s[idx] as u64} else { 0u64 };
            let tmp_b = if b8s.len() >= idx + 1 { b8s[idx] as u64} else { 0u64 };
            let tmp_c = if c8s.len() >= idx + 1 { c8s[idx] as u64} else { 0u64 };
            suma = suma + tmp_a;
            sumb = sumb + tmp_b;
            sumc = sumc + tmp_c;
            print!("{} ",tmp_c);
        }println!("");
        let a_digits = a.to_u64_digits();
        let b_digits = b.to_u64_digits();
        let c_digits = c.to_u64_digits();
        let total_idx :usize = 0;
        let mut t_digits = vec![];
        for total_idx in 0..4 {
            let mut rhs_sum = BigUint::from(0u128); 
            for a_id in 0..=total_idx {
                let (a_idx, b_idx) = (a_id as usize, (total_idx - a_id) as usize); 
                let tmp_a = if a_digits.len() >= a_idx + 1 { BigUint::from(a_digits[a_idx]) } else { BigUint::from(0u128) };
                let tmp_b = if b_digits.len() >= b_idx + 1 { BigUint::from(b_digits[b_idx]) } else { BigUint::from(0u128) };
                rhs_sum = rhs_sum.clone() + tmp_a * tmp_b;
            }
            t_digits.push(rhs_sum);
        }
        let (t0, t1, t2, t3) = (t_digits[0].clone(), t_digits[1].clone(), t_digits[2].clone(), t_digits[3].clone());
        let mut c_now = vec![];
        for idx in 0..4 {
            c_now.push(
                if c_digits.len() >= idx + 1 { BigUint::from(c_digits[idx]) } else { BigUint::from(0u128) }
            )
        }
        let v0 = (
            t0.clone() + t1.clone() * constant_64.clone() 
            - c_now[0].clone() - c_now[1].clone() * constant_64.clone()
        ) / constant_128.clone();
        let v1 = (
            v0.clone() + t2.clone() + t3.clone() * constant_64.clone() 
            - c_now[2].clone() - c_now[3].clone() * constant_64.clone()
        ) / constant_128.clone();

        println!("{} {} {} {} {} {}",t0,t1,t2,t3,v0,v1);
        (
            c,
            t0,
            t1,
            t2,
            t3,
            v0,
            v1,
            suma,
            sumb,
            sumc,
        )
    }

    #[test]
    fn mul_gadget() {
        let rng = rand::thread_rng();
        let mut vec_a = vec![];
        let mut vec_b = vec![];
        for idx in 0..32 {
            vec_a.push(
                if true {rng.clone().gen_range(0, 255)}
                else {0}
            );
        }

        for idx in 0..32 {
            vec_b.push(
                if true {rng.clone().gen_range(0, 255)}
                else {0}
            );
        }

        for idx in 0..32 {
            print!("{} ",vec_a[idx]);
        }
        println!("");
        for idx in 0..32 {
            print!("{} ",vec_b[idx]);
        }
        println!("");

        let a = BigUint::from_bytes_le(&vec_a);
        let b = BigUint::from_bytes_le(&vec_b);
        let a_bits = a.bits();
        let bits_num = if a_bits % 8 == 0 {
            a_bits / 8
        } else {
            a_bits / 8 + 1
        };
        let mut push_bigint = [0u8; 32];
        for idx in 0..bits_num {
            push_bigint[idx as usize] = 1u8;
        }
        let push_bigint = BigUint::from_bytes_le(&push_bigint);
        let (
            c,
            t0,
            t1,
            t2,
            t3,
            v0,
            v1,
            suma,
            sumb,
            sumc,
        ) = result_generate(&a, &b);
        try_test_circuit!(
            vec![
                ExecutionStep {
                    opcode: OpcodeId::PUSH32,
                    case: Case::Success,
                    values: vec![a.clone(),push_bigint.clone()/*BigUint::from(0x01u64)*/],
                },
                ExecutionStep {
                    opcode: OpcodeId::PUSH32,
                    case: Case::Success,
                    values: vec![b.clone(),push_bigint/*BigUint::from(0x01u64)*/],
                },
                ExecutionStep {
                    opcode: OpcodeId::MUL,
                    case: Case::Success,
                    values: vec![
                        a.clone(),
                        b.clone(),
                        c.clone(),
                        t0.clone(),
                        t1.clone(),
                        t2.clone(),
                        t3.clone(),
                        v0.clone(),
                        v1.clone(),
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
                        Base::from_u64(suma),
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
                        Base::from_u64(sumb),
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
                        Base::from_u64(suma),
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
                        Base::from_u64(sumb),
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
                        Base::from_u64(sumc),
                        Base::zero(),
                    ]
                }
            ],
            Ok(())
        );
    }
}