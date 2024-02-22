use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{EVMConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::{
        word::{WordCell, WordExpr},
        Expr,
    },
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct SelfbalanceGadget<F> {
    same_context: SameContextGadget<F>,
    callee_address: WordCell<F>,
    self_balance: WordCell<F>,
}

impl<F: Field> ExecutionGadget<F> for SelfbalanceGadget<F> {
    const NAME: &'static str = "SELFBALANCE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SELFBALANCE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let callee_address = cb.call_context_read_as_word(None, CallContextFieldTag::CalleeAddress);

        let self_balance = cb.query_word_unchecked();
        cb.account_read(
            callee_address.to_word(),
            AccountFieldTag::Balance,
            self_balance.to_word(),
        );

        cb.stack_push(self_balance.to_word());

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
            callee_address,
            self_balance,
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

        self.callee_address
            .assign_h160(region, offset, call.callee_address)?;

        let self_balance = block.rws[step.rw_indices[2]].stack_value();
        self.self_balance
            .assign_u256(region, offset, self_balance)?;

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
