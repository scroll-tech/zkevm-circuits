use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_U64,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes,
            math_gadget::LtGadget,
            CachedRegion, Cell, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::BlockContextFieldTag,
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar};
use gadgets::util::not;
use halo2_proofs::{circuit::Value, plonk::Error};

#[cfg(feature = "scroll")]
const NUM_PREV_BLOCK_ALLOWED: u64 = 2;
#[cfg(not(feature = "scroll"))]
const NUM_PREV_BLOCK_ALLOWED: u64 = 257;

#[derive(Clone, Debug)]
pub(crate) struct BlockHashGadget<F> {
    same_context: SameContextGadget<F>,
    block_number: RandomLinearCombination<F, N_BYTES_U64>,
    current_block_number: Cell<F>,
    block_hash: Word<F>,
    block_lt: LtGadget<F, N_BYTES_U64>,
    diff_lt: LtGadget<F, N_BYTES_U64>,
}

impl<F: Field> ExecutionGadget<F> for BlockHashGadget<F> {
    const NAME: &'static str = "BLOCKHASH";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BLOCKHASH;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let block_number = cb.query_word_rlc();
        cb.stack_pop(block_number.expr());

        let current_block_number = cb.query_cell();
        // FIXME
        //cb.block_lookup(
        //    BlockContextFieldTag::Number.expr(),
        //    None,
        //    current_block_number.expr(),
        //);

        let block_lt = LtGadget::construct(
            cb,
            from_bytes::expr(&block_number.cells),
            current_block_number.expr(),
        );

        let diff_lt = LtGadget::construct(
            cb,
            current_block_number.expr(),
            NUM_PREV_BLOCK_ALLOWED.expr() + from_bytes::expr(&block_number.cells),
        );

        let block_hash = cb.query_word_rlc();
        cb.condition(block_lt.expr() * diff_lt.expr(), |cb| {
            cb.block_lookup(
                BlockContextFieldTag::BlockHash.expr(),
                from_bytes::expr(&block_number.cells),
                block_hash.expr(),
            );
        });
        cb.condition(not::expr(block_lt.expr() * diff_lt.expr()), |cb| {
            cb.require_zero("invalid range", block_hash.expr());
        });

        cb.stack_push(block_hash.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::BLOCKHASH.constant_gas_cost().expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);
        Self {
            same_context,
            block_number,
            current_block_number,
            block_hash,
            block_lt,
            diff_lt,
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
        self.same_context.assign_exec_step(region, offset, step)?;

        let block_number = block.rws[step.rw_indices[0]].stack_value();
        self.block_number.assign(
            region,
            offset,
            Some(
                block_number.to_le_bytes()[..N_BYTES_U64]
                    .try_into()
                    .unwrap(),
            ),
        )?;
        let block_number: F = block_number.to_scalar().unwrap();

        let current_block_number = block.context.ctxs[&tx.block_number].number;
        self.current_block_number.assign(
            region,
            offset,
            Value::known(
                current_block_number
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;
        let current_block_number: F = current_block_number.to_scalar().unwrap();

        self.block_hash.assign(
            region,
            offset,
            Some(block.rws[step.rw_indices[1]].stack_value().to_le_bytes()),
        )?;

        self.block_lt
            .assign(region, offset, block_number, current_block_number)?;

        self.diff_lt.assign(
            region,
            offset,
            current_block_number,
            block_number + F::from(257),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, U256};
    use mock::test_ctx::{helpers::*, TestContext};

    fn test_ok(block_number: usize, current_block_number: u64) {
        let code = bytecode! {
            PUSH32(block_number)
            BLOCKHASH
            STOP
        };

        // simple U256 values for history hashes
        let mut history_hashes = Vec::new();
        let range = if current_block_number < 256 {
            0..current_block_number
        } else {
            current_block_number - 256..current_block_number
        };
        for i in range {
            history_hashes.push(U256::from(0xbeefcafeu64 + i));
        }
        let ctx = TestContext::<2, 1>::new(
            Some(history_hashes),
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(current_block_number),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run()
    }

    #[test]
    fn blockhash_gadget_simple() {
        test_ok(0, 5);
        test_ok(1, 5);
        test_ok(2, 5);
        test_ok(3, 5);
        test_ok(4, 5);
        test_ok(5, 5);
        test_ok(6, 5);
    }

    #[test]
    fn blockhash_gadget_large() {
        test_ok(0xcafe - 257, 0xcafeu64);
        test_ok(0xcafe - 256, 0xcafeu64);
        test_ok(0xcafe - 1, 0xcafeu64);
        test_ok(0xcafe, 0xcafeu64);
        test_ok(0xcafe + 1, 0xcafeu64);
    }
}
