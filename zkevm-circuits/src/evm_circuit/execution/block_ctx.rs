use crate::{
    evm_circuit::{
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{EVMConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::BlockContextFieldTag,
    util::{
        word::{WordCell, WordExpr},
        Expr,
    },
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::plonk::Error;

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct BlockCtxGadget<F> {
    same_context: SameContextGadget<F>,
    value: WordCell<F>,
}

impl<F: Field> ExecutionGadget<F> for BlockCtxGadget<F> {
    const NAME: &'static str = "BlockCTX";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BLOCKCTX;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let value = cb.query_word_unchecked(); // block table lookup below

        cb.stack_push(value.to_word());

        // Get op's FieldTag
        let opcode = cb.query_cell();
        let blockctx_tag = BlockContextFieldTag::Coinbase.expr()
            + (opcode.expr() - OpcodeId::COINBASE.as_u64().expr());

        // Lookup block table with block context ops
        // TIMESTAMP/NUMBER/GASLIMIT, COINBASE and DIFFICULTY/BASEFEE
        cb.block_lookup(blockctx_tag, None, value.to_word());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::TIMESTAMP.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            value,
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

        let value = block.get_rws(step, 0).stack_value();

        self.value.assign_u256(region, offset, value)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::bytecode;
    use mock::TestContext;

    fn test_ok(bytecode: bytecode::Bytecode) {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run()
    }

    #[test]
    fn blockcxt_u64_gadget_test() {
        let bytecode = bytecode! {
            TIMESTAMP
            POP
            NUMBER
            POP
            GASLIMIT
            STOP
        };
        test_ok(bytecode);
    }
    #[test]
    fn blockcxt_u160_gadget_test() {
        let bytecode = bytecode! {
            COINBASE
            STOP
        };
        test_ok(bytecode);
    }

    #[test]
    fn blockcxt_u256_gadget_test() {
        let bytecode = bytecode! {
            DIFFICULTY
            POP
            BASEFEE
            STOP
        };
        test_ok(bytecode);
    }
}
