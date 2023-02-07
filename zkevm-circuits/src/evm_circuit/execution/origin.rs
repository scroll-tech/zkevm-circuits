use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes, CachedRegion, Cell, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, TxContextFieldTag},
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct OriginGadget<F> {
    tx_id: Cell<F>,
    origin: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    same_context: SameContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for OriginGadget<F> {
    const NAME: &'static str = "ORIGIN";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ORIGIN;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let origin = cb.query_word_rlc::<N_BYTES_ACCOUNT_ADDRESS>();

        // Lookup in call_ctx the TxId
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        // Lookup rw_table -> call_context with tx origin address
        cb.tx_context_lookup(
            tx_id.expr(),
            TxContextFieldTag::CallerAddress,
            None, // None because unrelated to calldata
            from_bytes::expr(&origin.cells),
        );

        // Push the value to the stack
        cb.stack_push(origin.expr());

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2u64.expr()),
            program_counter: Delta(1u64.expr()),
            stack_pointer: Delta((-1i32).expr()),
            gas_left: Delta(-OpcodeId::ORIGIN.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            tx_id,
            origin,
            same_context,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let origin = block.rws[step.rw_indices[1]].stack_value();

        // Assing TxId.
        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;

        // Assign Origin addr RLC.
        self.origin.assign(
            region,
            offset,
            Some(
                origin.to_le_bytes()[..N_BYTES_ACCOUNT_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        // Assign SameContextGadget witnesses.
        self.same_context.assign_exec_step(region, offset, step)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::bytecode;
    use mock::TestContext;

    #[test]
    fn origin_gadget_test() {
        let bytecode = bytecode! {
            ORIGIN
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }
}
