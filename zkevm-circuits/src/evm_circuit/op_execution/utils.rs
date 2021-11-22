//! Reusable utilities for the op code implementations.

use super::super::Constraint;
use super::utils::constraint_builder::ConstraintBuilder;
use super::OpExecutionState;
use crate::{
    evm_circuit::{CoreStateInstance, Lookup},
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use halo2::{arithmetic::FieldExt, plonk::Expression};

pub(crate) mod common_cases;
pub(crate) mod constraint_builder;
pub(crate) mod math_gadgets;

// Makes sure all state transition variables are always constrained.
// This makes it impossible for opcodes to forget to constrain
// any state variables. If no update is specified it is assumed
// that the state variable needs to remain the same (which may not
// be correct, but this will easily be detected while testing).
#[derive(Clone, Debug, Default)]
pub(crate) struct StateTransitionExpressions<F> {
    pub gc_delta: Option<Expression<F>>,
    pub sp_delta: Option<Expression<F>>,
    pub pc_delta: Option<Expression<F>>,
    pub gas_delta: Option<Expression<F>>,
}

impl<F: FieldExt> StateTransitionExpressions<F> {
    pub(crate) fn new(state_transition: StateTransition) -> Self {
        Self {
            gc_delta: Some(state_transition.gc_delta.unwrap_or(0).expr()),
            pc_delta: Some(state_transition.pc_delta.unwrap_or(0).expr()),
            sp_delta: Some(state_transition.sp_delta.unwrap_or(0).expr()),
            gas_delta: Some(state_transition.gas_delta.unwrap_or(0).expr()),
        }
    }

    pub(crate) fn constraints(
        &self,
        cb: &mut ConstraintBuilder<F>,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
    ) {
        // Global Counter
        cb.add_expression(
            state_next.global_counter.expr()
                - (state_curr.global_counter.expr()
                    + self.gc_delta.clone().unwrap_or_else(|| 0.expr())),
        );
        // Program Counter
        cb.add_expression(
            state_next.program_counter.expr()
                - (state_curr.program_counter.expr()
                    + self.pc_delta.clone().unwrap_or_else(|| 0.expr())),
        );
        // Stack Pointer
        cb.add_expression(
            state_next.stack_pointer.expr()
                - (state_curr.stack_pointer.expr()
                    + self.sp_delta.clone().unwrap_or_else(|| 0.expr())),
        );
        // Gas Counter
        cb.add_expression(
            state_next.gas_counter.expr()
                - (state_curr.gas_counter.expr()
                    + self.gas_delta.clone().unwrap_or_else(|| 0.expr())),
        );
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct StateTransition {
    pub gc_delta: Option<usize>,
    pub sp_delta: Option<i32>,
    pub pc_delta: Option<usize>,
    pub gas_delta: Option<usize>,
}

impl StateTransition {
    pub(crate) fn assign(&self, state: &mut CoreStateInstance) {
        // Global Counter
        state.global_counter += self.gc_delta.unwrap_or(0);
        // Program Counter
        state.program_counter += self.pc_delta.unwrap_or(0);
        // Stack Pointer
        let sp_delta = self.sp_delta.unwrap_or(0);
        if sp_delta < 0 {
            state.stack_pointer -= -sp_delta as usize;
        } else {
            state.stack_pointer += sp_delta as usize;
        }
        // Gas Counter
        state.gas_counter += self.gas_delta.unwrap_or(0);
    }

    pub(crate) fn constraints<F: FieldExt>(
        &self,
        cb: &mut ConstraintBuilder<F>,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
    ) {
        StateTransitionExpressions::new(self.clone())
            .constraints(cb, state_curr, state_next);
    }
}

pub(crate) fn batch_add_expressions<F: FieldExt>(
    constraints: Vec<Constraint<F>>,
    expressions: Vec<Expression<F>>,
    lookups: Vec<(Expression<F>, Lookup<F>)>,
) -> Vec<Constraint<F>> {
    constraints
        .into_iter()
        .map(|mut constraint| {
            constraint.polys =
                [constraint.polys.clone(), expressions.clone().to_vec()]
                    .concat();
            constraint.lookups =
                [constraint.lookups.clone(), lookups.clone().to_vec()].concat();
            constraint
        })
        .collect()
}

/// Returns the sum of the passed in cells
pub(crate) mod sum {
    use super::super::Cell;
    use crate::util::Expr;
    use halo2::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(cells: &[Cell<F>]) -> Expression<F> {
        cells.iter().fold(0.expr(), |acc, cell| acc + cell.expr())
    }

    pub(crate) fn value<F: FieldExt>(values: &[u8]) -> F {
        values
            .iter()
            .fold(F::zero(), |acc, value| acc + F::from_u64(*value as u64))
    }
}

/// Returns `1` when `expr[0] && expr[1] && ... == 1`, and returns `0` otherwise.
/// Inputs need to be boolean
pub(crate) mod and {
    use crate::util::Expr;
    use halo2::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(
        inputs: Vec<Expression<F>>,
    ) -> Expression<F> {
        inputs
            .iter()
            .fold(1.expr(), |acc, input| acc * input.clone())
    }

    pub(crate) fn value<F: FieldExt>(inputs: Vec<F>) -> F {
        inputs.iter().fold(F::one(), |acc, input| acc * input)
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when `selector == 0`.
/// `selector` needs to be boolean.
pub(crate) mod select {
    use crate::util::Expr;
    use halo2::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1.expr() - selector) * when_false
    }

    pub(crate) fn value<F: FieldExt>(
        selector: F,
        when_true: F,
        when_false: F,
    ) -> F {
        selector * when_true + (F::one() - selector) * when_false
    }

    pub(crate) fn value_word<F: FieldExt>(
        selector: F,
        when_true: [u8; 32],
        when_false: [u8; 32],
    ) -> [u8; 32] {
        if selector == F::one() {
            when_true
        } else {
            when_false
        }
    }
}

/// Decodes a field element from its byte representation
pub(crate) mod from_bytes {
    use crate::{
        evm_circuit::{param::MAX_BYTES_FIELD, Cell},
        util::Expr,
    };
    use halo2::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(bytes: Vec<Cell<F>>) -> Expression<F> {
        assert!(bytes.len() <= MAX_BYTES_FIELD, "number of bytes too large");
        let mut value = 0.expr();
        let mut multiplier = F::one();
        for byte in bytes.iter() {
            value = value + byte.expr() * multiplier;
            multiplier *= F::from_u64(256);
        }
        value
    }

    pub(crate) fn value<F: FieldExt>(bytes: Vec<u8>) -> F {
        assert!(bytes.len() <= MAX_BYTES_FIELD, "number of bytes too large");
        let mut value = F::zero();
        let mut multiplier = F::one();
        for byte in bytes.iter() {
            value += F::from_u64(*byte as u64) * multiplier;
            multiplier *= F::from_u64(256);
        }
        value
    }
}

/// Returns 2**num_bits
pub(crate) fn get_range<F: FieldExt>(num_bits: usize) -> F {
    F::from_u64(2).pow(&[num_bits as u64, 0, 0, 0])
}

pub(crate) fn require_opcode_in_set<F: FieldExt>(
    opcode: Expression<F>,
    opcodes: Vec<OpcodeId>,
) -> ConstraintBuilder<F> {
    let mut cb = ConstraintBuilder::default();
    cb.require_in_set(opcode, opcodes.iter().map(|op| op.expr()).collect());
    cb
}

pub(crate) fn require_opcode_in_range<F: FieldExt>(
    opcode: Expression<F>,
    opcodes: Vec<OpcodeId>,
) -> ConstraintBuilder<F> {
    assert!(!opcodes.is_empty());
    // Verify the opcodes are in a continuous range
    for idx in 1..opcodes.len() {
        assert!(
            opcodes[idx].as_u8() - opcodes[idx - 1].as_u8() == 1,
            "opcodes not in continuous range"
        );
    }

    let mut cb = ConstraintBuilder::default();
    cb.require_in_range(opcode - opcodes[0].expr(), opcodes.len() as u64);
    cb
}

/// Counts the number of repetitions
#[macro_export]
macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + crate::count!($($xs)*));
}

/// Common OpGadget implementer
#[macro_export]
macro_rules! impl_op_gadget {
    (# $shared:ident [$($op:ident),* $(,)?] $name:ident { $($case:ident ($($args:expr),*) ),* $(,)? }) => {

        paste::paste! {
            #[derive(Clone, Debug)]
            pub struct $name<F> {
                $(
                    [<$case:snake>]: $case<F>,
                )*
            }
        }

        impl<F: FieldExt> OpGadget<F> for $name<F> {
            const RESPONSIBLE_OPCODES: &'static [OpcodeId] = &[$(OpcodeId::$op),*];

            const CASE_CONFIGS: &'static [CaseConfig] = &[
                $(
                    *$case::<F>::CASE_CONFIG,
                )*
            ];

            fn construct(case_allocations: Vec<CaseAllocation<F>>) -> Self {
                paste::paste! {
                    let [
                        $(
                            mut [<$case:snake>],
                        )*
                    ]: [CaseAllocation<F>; crate::count!($($case)*)] =
                        case_allocations.try_into().unwrap();
                    Self {
                        $(
                            [<$case:snake>]: $case::construct(
                                &mut [<$case:snake>],
                                $(
                                    $args,
                                )*
                            ),
                        )*
                    }
                }
            }

            fn constraints(
                &self,
                state_curr: &OpExecutionState<F>,
                state_next: &OpExecutionState<F>,
            ) -> Vec<Constraint<F>> {
                paste::paste! {
                    $(
                        let [<$case:snake>] = self.[<$case:snake>].constraint(
                            state_curr,
                            state_next,
                            concat!(stringify!($name), " ", stringify!([<$case:snake>])),
                        );
                    )*
                    let cases = vec![
                        $(
                            [<$case:snake>],
                        )*
                    ];
                    // Add common expressions to all cases
                    let cb = super::utils::[<require_opcode_in_ $shared>](
                        state_curr.opcode.expr(),
                        vec![$(OpcodeId::$op),*],
                    );
                    super::utils::batch_add_expressions(
                        cases,
                        cb.expressions,
                        cb.lookups,
                    )
                }
            }

            paste::paste! {
                fn assign(
                    &self,
                    region: &mut Region<'_, F>,
                    offset: usize,
                    op_execution_state: &mut CoreStateInstance,
                    execution_step: &ExecutionStep,
                ) -> Result<(), Error> {
                    $(
                        if execution_step.case == $case::<F>::CASE_CONFIG.case {
                            return self.[<$case:snake>].assign(
                                region,
                                offset,
                                op_execution_state,
                                execution_step,
                            );
                        }
                    )*
                    else {
                        unreachable!();
                    }
                }
            }
        }
    };
}
