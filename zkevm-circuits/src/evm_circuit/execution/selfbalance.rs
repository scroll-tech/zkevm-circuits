use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct SelfbalanceGadget<F> {
    same_context: SameContextGadget<F>,
    callee_address: Cell<F>,
    phase2_self_balance: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for SelfbalanceGadget<F> {
    const NAME: &'static str = "SELFBALANCE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SELFBALANCE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let callee_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);

        let phase2_self_balance = cb.query_cell_phase2();
        cb.account_read(
            callee_address.expr(),
            AccountFieldTag::Balance,
            phase2_self_balance.expr(),
        );

        cb.stack_push(phase2_self_balance.expr());

        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::SELFBALANCE.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            phase2_self_balance,
            callee_address,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        self.callee_address.assign(
            region,
            offset,
            Value::known(
                call.callee_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;

        let self_balance = block.rws[step.rw_indices[2]].stack_value();
        self.phase2_self_balance
            .assign(region, offset, region.word_rlc(self_balance))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::bytecode;
    use mock::TestContext;

    #[test]
    fn selfbalance_gadget_test() {
        let bytecode = bytecode! {
            SELFBALANCE
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }
}
