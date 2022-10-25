use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::BlockContextFieldTag,
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ChainIdGadget<F> {
    same_context: SameContextGadget<F>,
    chain_id: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for ChainIdGadget<F> {
    const NAME: &'static str = "CHAINID";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CHAINID;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let chain_id = cb.query_cell();

        // Push the value to the stack
        cb.stack_push(chain_id.expr());

        // Lookup block table with chain_id
        cb.block_lookup(
            BlockContextFieldTag::ChainId.expr(),
            cb.curr.state.block_number.expr(),
            chain_id.expr(),
        );

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::CHAINID.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            chain_id,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;
        let chain_id = block.rws[step.rw_indices[0]].stack_value();

        self.chain_id.assign(
            region,
            offset,
            Value::known(Word::random_linear_combine(
                chain_id.to_le_bytes(),
                block.randomness,
            )),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::run_test_circuits;
    use eth_types::bytecode;
    use mock::test_ctx::TestContext;

    #[test]
    fn chainid_gadget_test() {
        let bytecode = bytecode! {
            #[start]
            CHAINID
            STOP
        };
        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                None
            ),
            Ok(())
        );
    }
}
