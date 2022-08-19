use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use gadgets::util::{not, or, Expr};
use halo2_proofs::plonk::Error;

use crate::evm_circuit::{
    step::ExecutionState,
    util::{
        common_gadget::SameContextGadget,
        constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
        from_bytes,
        math_gadget::{ComparisonGadget, IsZeroGadget},
        CachedRegion, Cell, Word,
    },
    witness::{Block, Call, ExecStep, Transaction},
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct ExponentiationGadget<F> {
    same_context: SameContextGadget<F>,
    base: Word<F>,
    exponent: Word<F>,
    exponentiation: Word<F>,
    exponent_byte_size: Cell<F>,
    exponent_is_zero: IsZeroGadget<F>,
    exponent_is_one: IsZeroGadget<F>,
    cmp1: ComparisonGadget<F, 8>,
    cmp2: ComparisonGadget<F, 8>,
}

impl<F: Field> ExecutionGadget<F> for ExponentiationGadget<F> {
    const NAME: &'static str = "EXP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let base_rlc = cb.query_rlc();
        let exponent_rlc = cb.query_rlc();
        let exponentiation_rlc = cb.query_rlc();

        cb.stack_pop(base_rlc.expr());
        cb.stack_pop(exponent_rlc.expr());
        cb.stack_push(exponentiation_rlc.expr());

        let base = from_bytes::expr(&base_rlc.cells);
        let exponent = from_bytes::expr(&exponent_rlc.cells);
        let exponentiation = from_bytes::expr(&exponentiation_rlc.cells);

        let exponent_is_zero = IsZeroGadget::construct(cb, exponent.clone());
        let exponent_is_one = IsZeroGadget::construct(cb, exponent.clone() - 1.expr());

        cb.condition(exponent_is_zero.expr(), |cb| {
            cb.require_equal(
                "exponentiation == 1 if exponent == 0",
                exponentiation.clone(),
                1.expr(),
            );
        });
        cb.condition(exponent_is_one.expr(), |cb| {
            cb.require_equal(
                "exponentiation == base if exponent == 1",
                exponentiation.clone(),
                base.clone(),
            );
        });
        cb.condition(
            not::expr(or::expr([exponent_is_zero.expr(), exponent_is_one.expr()])),
            |cb| {
                cb.exp_table_lookup(base, exponent.clone(), exponentiation);
            },
        );

        let exponent_byte_size = cb.query_cell();
        let pow2_upper = cb.pow2_lookup(8.expr() * exponent_byte_size.expr());
        let pow2_lower = cb.pow2_lookup(8.expr() * (exponent_byte_size.expr() - 1.expr()));
        let cmp1 = ComparisonGadget::construct(cb, exponent.clone(), pow2_upper.expr());
        let cmp2 = ComparisonGadget::construct(cb, pow2_lower.expr(), exponent);

        let (cmp1_lt, _) = cmp1.expr();
        let (cmp2_lt, cmp2_eq) = cmp2.expr();
        cb.require_equal(
            "exponent < pow2(8 * byte_size(exponent))",
            cmp1_lt,
            1.expr(),
        );
        cb.require_equal(
            "pow2(8 * (byte_size(exponent) - 1)) <= exponent",
            or::expr([cmp2_lt, cmp2_eq]),
            1.expr(),
        );

        let dynamic_gas_cost = 50.expr() * exponent_byte_size.expr();
        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(3.expr()),
            program_counter: Transition::Delta(1.expr()), // 2 stack pops, 1 stack push
            stack_pointer: Transition::Delta(1.expr()),
            gas_left: Transition::Delta(
                -OpcodeId::EXP.constant_gas_cost().expr() - dynamic_gas_cost,
            ),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            base: base_rlc,
            exponent: exponent_rlc,
            exponentiation: exponentiation_rlc,
            exponent_byte_size,
            exponent_is_zero,
            exponent_is_one,
            cmp1,
            cmp2,
        }
    }

    fn assign_exec_step(
        &self,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        _block: &Block<F>,
        _transaction: &Transaction,
        _call: &Call,
        _step: &ExecStep,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}
