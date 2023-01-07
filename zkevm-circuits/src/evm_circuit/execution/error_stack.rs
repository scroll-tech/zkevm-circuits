use crate::evm_circuit::{
    execution::ExecutionGadget,
    step::ExecutionState,
    util::{
        common_gadget::RestoreContextGadget,
        constraint_builder::{
            ConstraintBuilder, StepStateTransition,
            Transition::{Delta, Same},
        },
        math_gadget::LtGadget,
        CachedRegion, Cell,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use crate::table::CallContextFieldTag;
use crate::util::Expr;
use eth_types::Field;
use halo2_proofs::{circuit::Value, plonk::Error};

const N_BYTES_STACK: usize = 2;

#[derive(Clone, Debug)]
pub(crate) struct ErrorStackGadget<F> {
    opcode: Cell<F>,
    min_stack_pointer: Cell<F>,
    max_stack_pointer: Cell<F>,
    is_overflow: LtGadget<F, N_BYTES_STACK>,
    is_underflow: LtGadget<F, N_BYTES_STACK>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorStackGadget<F> {
    const NAME: &'static str = "ErrorStack";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorStack;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        let min_stack_pointer = cb.query_cell();
        let max_stack_pointer = cb.query_cell();

        cb.opcode_stack_lookup(
            opcode.expr(),
            min_stack_pointer.expr(),
            max_stack_pointer.expr(),
        );
        // Check whether current stack pointer is underflow or overflow

        let is_overflow = LtGadget::construct(
            cb,
            cb.curr.state.stack_pointer.expr(),
            min_stack_pointer.expr(),
        );
        let is_underflow = LtGadget::construct(
            cb,
            max_stack_pointer.expr(),
            cb.curr.state.stack_pointer.expr(),
        );
        // is_overflow and is_underflow is bool ensure by LtGadget.

        // constrain one of [is_underflow, is_overflow] must be true when stack error
        // happens
        cb.require_equal(
            "is_underflow + is_overflow = 1",
            is_underflow.expr() + is_overflow.expr(),
            1.expr(),
        );

        // current call must be failed.
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 0.expr());

        // Go to EndTx only when is_root
        let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        cb.require_equal(
            "Go to EndTx if and only if is_root",
            cb.curr.state.is_root.expr(),
            is_to_end_tx,
        );

        // When it's a root call
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            // Do step state transition
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(1.expr() + cb.curr.state.reversible_write_counter.expr()),
                ..StepStateTransition::any()
            });
        });

        // When it's an internal call, need to restore caller's state as finishing this
        // call. Restore caller state to next StepState
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(
                cb,
                0.expr(),
                // rw_offset is handled in construct internally
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
            )
        });

        Self {
            opcode,
            min_stack_pointer,
            max_stack_pointer,
            is_overflow,
            is_underflow,
            restore_context,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();

        let (min_stack, max_stack) = opcode.valid_stack_ptr_range();

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        // Inputs/Outputs
        self.min_stack_pointer
            .assign(region, offset, Value::known(F::from(min_stack as u64)))?;
        self.max_stack_pointer
            .assign(region, offset, Value::known(F::from(max_stack as u64)))?;

        self.is_overflow.assign(
            region,
            offset,
            F::from(step.stack_pointer as u64),
            F::from(min_stack as u64),
        )?;
        self.is_underflow.assign(
            region,
            offset,
            F::from(max_stack as u64),
            F::from(step.stack_pointer as u64),
        )?;

        self.restore_context
            .assign(region, offset, block, call, step, 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{test::run_test_circuit, witness::block_convert};
    use crate::test_util::{run_test_circuits, run_test_circuits_with_params};

    use bus_mapping::circuit_input_builder::CircuitsParams;
    use bus_mapping::evm::OpcodeId;
    use eth_types::{
        self, address, bytecode, bytecode::Bytecode, geth_types::Account, Address, ToWord, Word,
    };
    use halo2_proofs::halo2curves::bn256::Fr;

    use mock::TestContext;

    fn test_stack_underflow(value: Word) {
        let bytecode = bytecode! {
            PUSH32(value)
            POP
            POP
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

    #[test]
    fn pop_gadget_underflow() {
        test_stack_underflow(Word::from(0x030201));
        test_stack_underflow(Word::from(0xab));
    }

    #[test]
    fn stack_overflow_simple() {
        test_stack_overflow(OpcodeId::PUSH1, &[123]);
        test_stack_overflow(
            OpcodeId::PUSH10,
            &[2, 10, 2, 5, 22, 100, 124, 210, 156, 120],
        );
        test_stack_overflow(
            OpcodeId::PUSH20,
            &[
                2, 10, 2, 5, 22, 100, 124, 210, 156, 120, 10, 28, 37, 87, 211, 255, 212, 60, 76,
                119,
            ],
        );
    }

    fn test_stack_overflow(opcode: OpcodeId, bytes: &[u8]) {
        assert!(bytes.len() == opcode.data_len());
        let mut bytecode = bytecode! {
            .write_op(opcode)
        };
        for b in bytes {
            bytecode.write(*b, false);
        }
        // still add 1024 causes stack overflow
        for _ in 0..1025 {
            bytecode.write_op(opcode);
            for b in bytes {
                bytecode.write(*b, false);
            }
        }
        // append final stop op code
        bytecode.write_op(OpcodeId::STOP);

        assert_eq!(
            run_test_circuits_with_params(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                None,
                CircuitsParams {
                    max_rws: 2048,
                    ..Default::default()
                }
            ),
            Ok(())
        );
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct Stack {
        gas: u64,
        value: Word,
        cd_offset: u64,
        cd_length: u64,
        rd_offset: u64,
        rd_length: u64,
    }

    fn caller() -> Account {
        let terminator = OpcodeId::REVERT;

        let stack = Stack {
            gas: 10,
            cd_offset: 64,
            cd_length: 320,
            rd_offset: 0,
            rd_length: 32,
            ..Default::default()
        };
        let bytecode = bytecode! {
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
            PUSH32(stack.value)
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            CALL
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
            PUSH32(stack.value)
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            CALL
            .write_op(terminator)
        };

        Account {
            address: Address::repeat_byte(0xfe),
            balance: Word::from(10).pow(20.into()),
            code: bytecode.to_vec().into(),
            ..Default::default()
        }
    }

    fn stack_error_internal_call(caller: Account, callee: Account) {
        let block = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(10u64.pow(19)));
                accs[1]
                    .address(caller.address)
                    .code(caller.code)
                    .nonce(caller.nonce)
                    .balance(caller.balance);
                accs[2]
                    .address(callee.address)
                    .code(callee.code)
                    .nonce(callee.nonce)
                    .balance(callee.balance);
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .to(accs[1].address)
                    .gas(23800.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        let block_data = bus_mapping::mock::BlockData::new_from_geth_data(block);
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&block_data.eth_block, &block_data.geth_traces)
            .unwrap();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db);
        assert_eq!(run_test_circuit(block.unwrap()), Ok(()));
    }

    fn callee(code: Bytecode) -> Account {
        let code = code.to_vec();
        let is_empty = code.is_empty();
        Account {
            address: Address::repeat_byte(0xff),
            code: code.into(),
            nonce: if is_empty { 0 } else { 1 }.into(),
            balance: if is_empty { 0 } else { 0xdeadbeefu64 }.into(),
            ..Default::default()
        }
    }

    // internal call error test
    #[test]
    fn test_stack_error_internal() {
        let bytecode = bytecode! {
            PUSH1(Word::from(11))
            POP
            POP // underflow occurs in this POP operation
            STOP
        };
        let callee = callee(bytecode);
        stack_error_internal_call(caller(), callee);
    }
}
