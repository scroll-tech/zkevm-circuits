use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
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
use eth_types::{Field, ToAddress, ToLittleEndian};
use halo2_proofs::plonk::Error;
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct AddressGadget<F> {
    same_context: SameContextGadget<F>,
    address: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
}

impl<F: Field> ExecutionGadget<F> for AddressGadget<F> {
    const NAME: &'static str = "ADDRESS";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ADDRESS;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let address = cb.query_word_rlc();

        // Lookup callee address in call context.
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::CalleeAddress,
            from_bytes::expr(&address.cells),
        );

        cb.stack_push(address.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::ADDRESS.constant_gas_cost().expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address,
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

        let address = block.rws[step.rw_indices[1]].stack_value();
        debug_assert_eq!(call.callee_address, address.to_address());

        self.address.assign(
            region,
            offset,
            Some(
                address.to_le_bytes()[..N_BYTES_ACCOUNT_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, ToWord, Word};
    use mock::test_ctx::TestContext;

    fn test_root_ok() {
        let bytecode = bytecode! {
            ADDRESS
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    fn test_internal_ok(call_data_offset: usize, call_data_length: usize) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = bytecode! {
            ADDRESS
            STOP
        };

        // code A calls code B.
        let pushdata = rand_bytes(8);
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(call_data_length) // argsLength
            PUSH32(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
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
    fn address_gadget_root() {
        test_root_ok();
    }

    #[test]
    fn address_gadget_internal() {
        test_internal_ok(0x20, 0x00);
        test_internal_ok(0x20, 0x10);
        test_internal_ok(0x40, 0x20);
        test_internal_ok(0x1010, 0xff);
    }
}
