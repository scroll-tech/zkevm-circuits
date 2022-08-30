use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes, CachedRegion, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::BlockContextFieldTag,
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use eth_types::ToLittleEndian;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct BlockCtxGadget<F, const N_BYTES: usize> {
    same_context: SameContextGadget<F>,
    value: RandomLinearCombination<F, N_BYTES>,
}

impl<F: Field, const N_BYTES: usize> BlockCtxGadget<F, N_BYTES> {
    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let value = cb.query_rlc();

        // Push the const generic parameter N_BYTES value to the stack
        cb.stack_push(value.expr());

        // Get op's FieldTag
        let opcode = cb.query_cell();
        let blockctx_tag = BlockContextFieldTag::Coinbase.expr()
            + (opcode.expr() - OpcodeId::COINBASE.as_u64().expr());

        // Lookup block table with block context ops
        // TIMESTAMP/NUMBER/GASLIMIT, COINBASE and DIFFICULTY/BASEFEE
        let value_expr = if N_BYTES == N_BYTES_WORD {
            value.expr()
        } else {
            from_bytes::expr(&value.cells)
        };
        cb.block_lookup(blockctx_tag, cb.curr.state.block_number.expr(), value_expr);

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
}

#[derive(Clone, Debug)]
pub(crate) struct BlockCtxU64Gadget<F> {
    value_u64: BlockCtxGadget<F, N_BYTES_U64>,
}

impl<F: Field> ExecutionGadget<F> for BlockCtxU64Gadget<F> {
    const NAME: &'static str = "BlockCTXU64";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BLOCKCTXU64;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let value_u64 = BlockCtxGadget::construct(cb);

        Self { value_u64 }
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
        self.value_u64
            .same_context
            .assign_exec_step(region, offset, step)?;

        let value = block.rws[step.rw_indices[0]].stack_value();

        self.value_u64.value.assign(
            region,
            offset,
            Some(u64::try_from(value).unwrap().to_le_bytes()),
        )?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BlockCtxU160Gadget<F> {
    value_u160: BlockCtxGadget<F, N_BYTES_ACCOUNT_ADDRESS>,
}

impl<F: Field> ExecutionGadget<F> for BlockCtxU160Gadget<F> {
    const NAME: &'static str = "BlockCTXU160";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BLOCKCTXU160;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let value_u160 = BlockCtxGadget::construct(cb);

        Self { value_u160 }
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
        self.value_u160
            .same_context
            .assign_exec_step(region, offset, step)?;

        let value = block.rws[step.rw_indices[0]].stack_value();

        self.value_u160.value.assign(
            region,
            offset,
            Some(
                value.to_le_bytes()[..N_BYTES_ACCOUNT_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BlockCtxU256Gadget<F> {
    value_u256: BlockCtxGadget<F, N_BYTES_WORD>,
}

impl<F: Field> ExecutionGadget<F> for BlockCtxU256Gadget<F> {
    const NAME: &'static str = "BLOCKCTXU256";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BLOCKCTXU256;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let value_u256 = BlockCtxGadget::construct(cb);

        Self { value_u256 }
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
        self.value_u256
            .same_context
            .assign_exec_step(region, offset, step)?;

        let value = block.rws[step.rw_indices[0]].stack_value();

        self.value_u256
            .value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::run_test_circuits;
    use eth_types::bytecode;
    use mock::TestContext;

    fn test_ok(bytecode: bytecode::Bytecode) {
        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                None
            ),
            Ok(())
        );
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
