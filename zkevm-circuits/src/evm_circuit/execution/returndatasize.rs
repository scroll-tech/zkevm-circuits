use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_U64,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes, CachedRegion, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct ReturnDataSizeGadget<F> {
    same_context: SameContextGadget<F>,
    return_data_size: RandomLinearCombination<F, N_BYTES_U64>,
}

impl<F: Field> ExecutionGadget<F> for ReturnDataSizeGadget<F> {
    const NAME: &'static str = "RETURNDATASIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::RETURNDATASIZE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Add lookup constraint in the call context for the returndatasize field.
        let return_data_size = cb.query_word_rlc();
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::LastCalleeReturnDataLength,
            from_bytes::expr(&return_data_size.cells),
        );

        // The returndatasize should be pushed to the top of the stack.
        cb.stack_push(return_data_size.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::RETURNDATASIZE.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            return_data_size,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;
        let return_data_size = block.rws[step.rw_indices[1]].stack_value();
        self.return_data_size.assign(
            region,
            offset,
            Some(
                return_data_size.to_le_bytes()[..N_BYTES_U64]
                    .try_into()
                    .expect("could not encode return_data_size as byte array in little endian"),
            ),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, ToWord, Word};
    use mock::test_ctx::TestContext;

    fn test_ok_internal(return_data_offset: usize, return_data_size: usize) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        let pushdata = rand_bytes(32);
        let code_b = bytecode! {
            PUSH32(Word::from_big_endian(&pushdata))
            PUSH1(0)
            MSTORE

            PUSH32(return_data_size)
            PUSH1(return_data_offset)
            RETURN
            STOP
        };

        // code A calls code B.
        let code_a = bytecode! {
            // call ADDR_B.
            PUSH32(return_data_size) // retLength
            PUSH1(return_data_offset) // retOffset
            PUSH1(0x00) // argsLength
            PUSH1(0x00) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            RETURNDATASIZE
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn returndatasize_gadget_simple() {
        test_ok_internal(0x00, 0x02);
    }

    #[test]
    fn returndatasize_gadget_large() {
        test_ok_internal(0x00, 0x20);
    }

    #[test]
    fn returndatasize_gadget_zero_length() {
        test_ok_internal(0x00, 0x00);
    }

    #[test]
    fn test_simple() {
        let code = bytecode! {
            RETURNDATASIZE
            STOP
        };
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
        )
        .run();
    }
}
