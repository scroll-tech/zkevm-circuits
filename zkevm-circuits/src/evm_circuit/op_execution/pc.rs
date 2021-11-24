use super::super::{
    Case, Cell, Constraint, CoreStateInstance, ExecutionStep, Word,
};
use super::utils::common_cases::{OutOfGasCase, StackOverflowCase};
use super::utils::constraint_builder::ConstraintBuilder;
use super::utils::{from_bytes, sum, StateTransition};
use super::{CaseAllocation, CaseConfig, OpExecutionState, OpGadget};
use crate::impl_op_gadget;
use crate::util::{Expr, ToWord};
use bus_mapping::evm::{GasCost, OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::convert::TryInto;

static STATE_TRANSITION: StateTransition = StateTransition {
    gc_delta: Some(1), // 1 stack push
    pc_delta: Some(1),
    sp_delta: Some(-1),
    gas_delta: Some(GasCost::QUICK.as_usize()),
};
const NUM_PUSHED: usize = 1;

impl_op_gadget!(
    #set[PC]
    PcGadget {
        PcSuccessCase(),
        StackOverflowCase(NUM_PUSHED),
        OutOfGasCase(STATE_TRANSITION.gas_delta.unwrap()),
    }
);

#[derive(Clone, Debug)]
struct PcSuccessCase<F> {
    case_selector: Cell<F>,
    pc: Word<F>,
}

impl<F: FieldExt> PcSuccessCase<F> {
    const RESPONSIBLE_OPCODES: &'static [OpcodeId] = &[OpcodeId::PC];

    pub const CASE_CONFIG: &'static CaseConfig = &CaseConfig {
        case: Case::Success,
        num_word: 1, // pc
        num_cell: 0,
        will_halt: false,
    };

    pub fn construct(alloc: &mut CaseAllocation<F>) -> Self {
        Self {
            case_selector: alloc.selector.clone(),
            pc: alloc.words.pop().unwrap(),
        }
    }

    pub fn constraint(
        &self,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
        name: &'static str,
    ) -> Vec<Constraint<F>> {
        let mut cb = ConstraintBuilder::default();

        // We limit `pc` to 64 bits so we only consider the lower 8 bytes:
        // - pc[7..0] = state.program_counter
        // - pc[32] + .. + pc[8] = 0
        cb.require_equal(
            from_bytes::expr(self.pc.cells[0..8].to_vec()),
            state_curr.program_counter.expr(),
        );
        cb.require_zero(sum::expr(&self.pc.cells[8..32]));

        // Push the result on the stack
        cb.stack_push(self.pc.expr());

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
        self.pc
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
    fn pc_gadget() {
        // PC
        try_test_circuit!(
            vec![
                ExecutionStep {
                    opcode: OpcodeId::PUSH3,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x03_02_01u64),
                        BigUint::from(0x01_01_01u64),
                    ],
                },
                ExecutionStep {
                    opcode: OpcodeId::PC,
                    case: Case::Success,
                    values: vec![BigUint::from(4u64)],
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
                    ]
                },
                Operation {
                    gc: 2,
                    target: Target::Stack,
                    is_write: true,
                    values: [
                        Base::zero(),
                        Base::from_u64(1022),
                        Base::from_u64(4),
                        Base::zero(),
                    ]
                },
            ],
            Ok(())
        );
    }
}
