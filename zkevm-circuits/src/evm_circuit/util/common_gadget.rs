use crate::{
    evm_circuit::{
        param::MAX_GAS_SIZE_IN_BYTES,
        table::{FixedTableTag, Lookup},
        util::{
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition,
            },
            math_gadget::RangeCheckGadget,
            Cell,
        },
        witness::ExecStep,
    },
    util::Expr,
};
use halo2::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Error, Expression},
};

/// Construction of execution result that stays in the same call context, which
/// lookups the opcode and verifies the execution result is responsible for it,
/// then calculates the gas_cost and constrain the state transition.
#[derive(Clone, Debug)]
pub(crate) struct SameContextGadget<F> {
    opcode: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, MAX_GAS_SIZE_IN_BYTES>,
}

impl<F: FieldExt> SameContextGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        opcode: Cell<F>,
        mut step_state_transition: StepStateTransition<F>,
        dynamic_gas_cost: Option<Expression<F>>,
    ) -> Self {
        cb.opcode_lookup(opcode.expr(), 1.expr());
        cb.add_lookup(Lookup::Fixed {
            tag: FixedTableTag::ResponsibleOpcode.expr(),
            values: [
                cb.execution_state().as_u64().expr(),
                opcode.expr(),
                0.expr(),
            ],
        });

        let mut gas_cost = cb
            .execution_state()
            .responsible_opcodes()
            .first()
            .expect("Execution result in SameContextGadget should be responsible to some opcodes")
            .constant_gas_cost()
            .as_u64()
            .expr();

        if let Some(dynamic_gas_cost) = dynamic_gas_cost {
            gas_cost = gas_cost + dynamic_gas_cost;
        }

        // Check gas_left is sufficient
        let sufficient_gas_left = RangeCheckGadget::construct(
            cb,
            cb.curr.state.gas_left.expr() - gas_cost.clone(),
        );

        // Set state transition of gas_left if it's default value
        if matches!(step_state_transition.gas_left, Transition::Same)
            && !matches!(gas_cost, Expression::Constant(constant) if constant.is_zero_vartime())
        {
            step_state_transition.gas_left = Transition::Delta(-gas_cost);
        }

        // State transition
        cb.require_step_state_transition(step_state_transition);

        Self {
            opcode,
            sufficient_gas_left,
        }
    }

    pub(crate) fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Some(F::from(opcode.as_u64())))?;

        self.sufficient_gas_left.assign(
            region,
            offset,
            F::from((step.gas_left - step.gas_cost) as u64),
        )?;

        Ok(())
    }
}
