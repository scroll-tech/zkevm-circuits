use super::super::{
    Case, Cell, Constraint, CoreStateInstance, ExecutionStep, Word,
};
use super::utils::common_cases::{OutOfGasCase, StackUnderflowCase};
use super::utils::constraint_builder::ConstraintBuilder;
use super::utils::{StateTransition, StateTransitionExpressions};
use super::{CaseAllocation, CaseConfig, OpExecutionState, OpGadget};
use crate::impl_op_gadget;
use crate::util::{Expr, ToWord};
use bus_mapping::evm::{GasCost, OpcodeId};
use halo2::plonk::Error;
use halo2::{arithmetic::FieldExt, circuit::Region};
use num::ToPrimitive;
use std::convert::TryInto;

static STATE_TRANSITION: StateTransition = StateTransition {
    gc_delta: Some(1),
    pc_delta: Some(0), // TODO: pc is dynamic for jump
    sp_delta: Some(1),
    gas_delta: Some(GasCost::MID.as_usize()),
};

const NUM_POPPED: usize = 1;
impl_op_gadget!(
    #set[JUMP]
    JumpGadget {
        JumpSuccessCase(),
        OutOfGasCase(STATE_TRANSITION.gas_delta.unwrap()),
        StackUnderflowCase(NUM_POPPED),
        //TODO: ErrJumpcase
    }
);

#[derive(Clone, Debug)]
struct JumpSuccessCase<F> {
    case_selector: Cell<F>,
    code_hash: Word<F>,
    dest: Word<F>,
}

impl<F: FieldExt> JumpSuccessCase<F> {
    pub(crate) const CASE_CONFIG: &'static CaseConfig = &CaseConfig {
        case: Case::Success,
        num_word: 2, // top stack value as pc, hash of contract
        num_cell: 0,
        will_halt: false,
    };

    pub(crate) fn construct(alloc: &mut CaseAllocation<F>) -> Self {
        Self {
            case_selector: alloc.selector.clone(),
            code_hash: alloc.words.pop().unwrap(),
            dest: alloc.words.pop().unwrap(),
        }
    }

    pub(crate) fn constraint(
        &self,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
        name: &'static str,
    ) -> Constraint<F> {
        let mut cb = ConstraintBuilder::default();

        // State transitions
        // `pc` needs to be `dest` value
        let mut st = StateTransitionExpressions::new(STATE_TRANSITION.clone());
        st.pc_delta =
            Some(self.dest.expr() - state_curr.program_counter.expr());
        st.constraints(&mut cb, state_curr, state_next);

        // Pop the value from the stack
        cb.stack_pop(self.dest.expr());
        // lookup byte code table to ensure 'dest' is valid( jumpdest & is_code)
        cb.add_bytecode_lookup(
            1.expr(),
            [
                self.code_hash.expr(),
                self.dest.expr(),
                1.expr(),
                OpcodeId::JUMPDEST.as_u8().expr(),
            ],
        );

        // Generate the constraint
        cb.constraint(self.case_selector.expr(), name)
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        state: &mut CoreStateInstance,
        step: &ExecutionStep,
    ) -> Result<(), Error> {
        // Inputs

        self.code_hash.assign(
            region,
            offset,
            Some(step.values[0].to_word()),
        )?;

        self.dest
            .assign(region, offset, Some(step.values[1].to_word()))?;

        // State transitions
        let st = STATE_TRANSITION.clone();
        st.assign(state);
        // other than normal op code, jump change pc specially, adjust here
        state.program_counter = step.values[1].to_usize().unwrap();
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
    fn jump_gadget() {
        try_test_circuit!(
            vec![
                ExecutionStep {
                    opcode: OpcodeId::PUSH1,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x03u64),
                        BigUint::from(0x01u64),
                    ],
                },
                ExecutionStep {
                    // Jump
                    opcode: OpcodeId::JUMP,
                    case: Case::Success,
                    values: vec![
                        BigUint::from(0x00u64), // code hash
                        BigUint::from(0x03u64), // dest value
                    ],
                },
                ExecutionStep {
                    // JUMPDEST
                    opcode: OpcodeId::JUMPDEST,
                    case: Case::Success,
                    values: vec![],
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
                        Base::from_u64(03),
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
                        Base::from_u64(03),
                        Base::zero(),
                    ]
                }
            ],
            Ok(())
        );
    }
}
