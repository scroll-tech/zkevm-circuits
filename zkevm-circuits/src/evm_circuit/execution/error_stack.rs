use crate::evm_circuit::{
    execution::ExecutionGadget,
    step::ExecutionState,
    table::{FixedTableTag, Lookup},
    util::{
        common_gadget::CommonErrorGadget, constraint_builder::ConstraintBuilder, CachedRegion, Cell,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use crate::util::Expr;
use eth_types::Field;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorStackGadget<F> {
    opcode: Cell<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorStackGadget<F> {
    const NAME: &'static str = "ErrorStack";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorStack;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        cb.add_lookup(
            "Responsible opcode lookup for invalid stack pointer",
            Lookup::Fixed {
                tag: FixedTableTag::ResponsibleOpcode.expr(),
                values: [
                    Self::EXECUTION_STATE.as_u64().expr(),
                    opcode.expr(),
                    cb.curr.state.stack_pointer.expr(),
                ],
            },
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 2.expr());

        Self {
            opcode,
            common_error_gadget,
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
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use crate::test_util::CircuitTestBuilder;
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use bus_mapping::evm::OpcodeId;
    use eth_types::{
        self, address, bytecode, bytecode::Bytecode, geth_types::Account, Address, ToWord, Word,
    };

    use mock::TestContext;

    fn test_stack_underflow(value: Word) {
        let bytecode = bytecode! {
            PUSH32(value)
            POP
            POP
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
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

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .params(CircuitsParams {
            max_rws: 2048,
            ..Default::default()
        })
        .run();
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
        let ctx = TestContext::<3, 1>::new(
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
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
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
