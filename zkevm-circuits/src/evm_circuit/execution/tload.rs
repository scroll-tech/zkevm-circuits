use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{EVMConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion, Cell, StepRws, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{Expr, Field},
};
use bus_mapping::evm::OpcodeId;
use eth_types::ToLittleEndian;
use gadgets::ToScalar;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct TloadGadget<F> {
    same_context: SameContextGadget<F>,
    tx_id: Cell<F>,
    callee_address: Cell<F>,
    key: Word<F>,
    value: Word<F>,
}

impl<F: Field> ExecutionGadget<F> for TloadGadget<F> {
    const NAME: &'static str = "TLOAD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::TLOAD;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let callee_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);

        let key = cb.query_word_rlc();
        // Pop the key from the stack
        cb.stack_pop(key.expr());

        let value = cb.query_word_rlc();
        cb.account_transient_storage_read(
            callee_address.expr(),
            key.expr(),
            value.expr(),
            tx_id.expr(),
        );

        cb.stack_push(value.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(5.expr()),
            program_counter: Delta(1.expr()),
            reversible_write_counter: Delta(0.expr()),
            gas_left: Delta(-OpcodeId::TLOAD.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            tx_id,
            callee_address,
            key,
            value,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        self.tx_id.assign(
            region,
            offset,
            Value::known(F::from(u64::try_from(tx.id).unwrap())),
        )?;
        self.callee_address.assign(
            region,
            offset,
            Value::known(call.callee_address.to_scalar().unwrap()),
        )?;

        let mut rws = StepRws::new(block, step);

        rws.offset_add(2);

        let key = rws.next().stack_value();
        rws.next(); // TLOAD rw
        let value = rws.next().stack_value();

        self.key.assign(region, offset, Some(key.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, Word};
    use mock::{test_ctx::helpers::tx_from_1_to_0, TestContext, MOCK_ACCOUNTS};

    fn test_ok(key: Word, value: Word) {
        // Here we use two bytecodes to test both is_persistent(STOP) or not(REVERT)
        // Besides, in bytecode we use two TLOADs,
        // the first TLOAD is used to test cold,  and the second is used to test warm
        let bytecode_success = bytecode! {
            PUSH32(key)
            TLOAD
            STOP
        };
        let bytecode_failure = bytecode! {
            PUSH32(key)
            TLOAD
            PUSH32(0)
            PUSH32(0)
            REVERT
        };
        for bytecode in [bytecode_success, bytecode_failure] {
            let ctx = TestContext::<2, 1>::new(
                None,
                |accs| {
                    accs[0]
                        .address(MOCK_ACCOUNTS[0])
                        .balance(Word::from(10u64.pow(19)))
                        .code(bytecode)
                        .storage(vec![(key, value)].into_iter());
                    accs[1]
                        .address(MOCK_ACCOUNTS[1])
                        .balance(Word::from(10u64.pow(19)));
                },
                tx_from_1_to_0,
                |block, _txs| block,
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        }
    }

    #[test]
    fn tload_gadget_simple() {
        let key = 0x030201.into();
        let value = 0x060504.into();
        test_ok(key, value);
    }

    #[test]
    fn tload_gadget_rand() {
        let key = rand_word();
        let value = rand_word();
        test_ok(key, value);
    }
}
