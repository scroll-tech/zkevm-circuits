use super::super::{
	BusMappingLookup, Case, Cell, Constraint, CoreStateInstance, ExecutionStep,
	Lookup, Word,
};
use super::{CaseAllocation, CaseConfig, OpExecutionState, OpGadget};
use crate::util::{Expr, ToWord};
use bus_mapping::evm::{GasCost, OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::{array, convert::TryInto};

#[derive(Clone, Debug)]
struct PcSuccessAllocation<F> {
	selector: Cell<F>,
	pc: Word<F>,
}

#[derive(Clone, Debug)]
pub struct PcGadget<F> {
	success: PcSuccessAllocation<F>,
	stack_overflow: Cell<F>,
	// case selector
	out_of_gas: (
		Cell<F>, // case selector
		Cell<F>, // gas available
	),
}

impl<F: FieldExt> OpGadget<F> for PcGadget<F> {
	const RESPONSIBLE_OPCODES: &'static [OpcodeId] =
		&[OpcodeId::PC];
	
	const CASE_CONFIGS: &'static [CaseConfig] = &[
		CaseConfig {
			case: Case::Success,
			num_word: 1, // pc
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
		let [mut success, stack_overflow, out_of_gas]: [CaseAllocation<F>; 3] =
			case_allocations.try_into().unwrap();
		Self {
			success: PcSuccessAllocation {
				selector: success.selector,
				pc: success.words.pop().unwrap(),
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
		
		let common_polys = vec![
			opcode.expr() - OpcodeId::PC.expr()
		];
		
		let success = {
			let PcSuccessAllocation {
				selector,
				pc,
			} = &self.success;
			
			// interpreter state transition constraints
			let state_transition_constraint = vec![
				state_next.global_counter.expr()
					- (state_curr.global_counter.expr() + 1.expr()),
				state_next.program_counter.expr()
					- (state_curr.program_counter.expr() + 1.expr()),
				state_next.stack_pointer.expr()
					- (state_curr.stack_pointer.expr() + 1.expr()),
				state_next.gas_counter.expr()
					- (state_curr.gas_counter.expr() + GasCost::QUICK.expr()),
			];
			
			let bus_mapping_lookups = [
				vec![Lookup::BusMappingLookup(BusMappingLookup::Stack {
					index_offset: 0,
					value: pc.expr(),
					is_write: true,
				})]]
				.concat();
			
			Constraint {
				name: "PcGadget success",
				selector: selector.expr(),
				polys: state_transition_constraint,
				lookups: bus_mapping_lookups,
			}
		};
		
		let stack_overflow = {
			let stack_pointer = state_curr.stack_pointer.expr();
			Constraint {
				name: "PcGadget stack overflow",
				selector: self.stack_overflow.expr(),
				polys: vec![stack_pointer],
				lookups: vec![],
			}
		};
		
		let out_of_gas = {
			let (case_selector, gas_available) = &self.out_of_gas;
			let gas_overdemand = state_curr.gas_counter.expr()
				+ GasCost::QUICK.expr()
				- gas_available.expr();
			Constraint {
				name: "PcGadget out of gas",
				selector: case_selector.expr(),
				polys: vec![
					(gas_overdemand.clone() - 1.expr())
						* (gas_overdemand - 2.expr())
				],
				lookups: vec![],
			}
		};
		
		array::IntoIter::new([success, stack_overflow, out_of_gas])
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
			Case::StackOverflow => {
				unimplemented!()
			}
			Case::OutOfGas => {
				unimplemented!()
			}
			_ => unreachable!()
		}
	}
}

impl<F: FieldExt> PcGadget<F> {
	fn assign_success(
		&self,
		region: &mut Region<'_, F>,
		offset: usize,
		core_state: &mut CoreStateInstance,
		execution_step: &ExecutionStep,
	) -> Result<(), Error> {
		core_state.global_counter += 1;
		core_state.program_counter += 1;
		core_state.stack_pointer += 1;
		core_state.gas_counter += GasCost::QUICK.as_usize();
		
		self.success.pc.assign(
			region,
			offset,
			Some(execution_step.values[0].to_word()),
		)?;
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
	use std::ops::Add;
	
	macro_rules! try_test_circuit {
        ($execution_steps:expr, $operations:expr, $result:expr) => {{
            let circuit =
                TestCircuit::<Base>::new($execution_steps, $operations);
            let prover = MockProver::<Base>::run(10, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), $result);
        }};
    }
	
	#[test]
	fn pc_gadget() {
		let pc = 0x00u64;
		let data = BigUint::from(0x03_02_01u64);
		let selector = BigUint::from(0x01_01_01u64);
		println!("--------- bits: {}", data.to_bytes_be().len());
		// PC
		try_test_circuit!(
			vec![
				ExecutionStep {
                    opcode: OpcodeId::PC,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(pc.clone()),
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
                        Base::from_u64(pc),
                        Base::zero(),
                    ]
                },
			],
			Ok(())
		);
	}
}
