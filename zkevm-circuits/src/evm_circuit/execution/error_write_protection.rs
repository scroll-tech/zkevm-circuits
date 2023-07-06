use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::IsZeroGadget,
            CachedRegion, Cell, Word as RLCWord,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian, U256};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorWriteProtectionGadget<F> {
    opcode: Cell<F>,
    is_call: IsZeroGadget<F>,
    gas: RLCWord<F>,
    code_address: RLCWord<F>,
    value: RLCWord<F>,
    is_value_zero: IsZeroGadget<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorWriteProtectionGadget<F> {
    const NAME: &'static str = "ErrorWriteProtection";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorWriteProtection;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let is_call = IsZeroGadget::construct(cb, "", opcode.expr() - OpcodeId::CALL.expr());
        let gas_word = cb.query_word_rlc();
        let code_address_word = cb.query_word_rlc();
        let value = cb.query_word_rlc();
        let is_value_zero = IsZeroGadget::construct(cb, "", value.expr());

        // require_in_set method will spilit into more low degree expressions if exceed
        // max_degree. otherwise need to do fixed lookup for these opcodes
        // checking.
        cb.require_in_set(
            "ErrorWriteProtection only happens in [CALL, SSTORE, CREATE, CREATE2, SELFDESTRUCT, LOG0..4 ]",
            opcode.expr(),
            vec![
                OpcodeId::CALL.expr(),
                OpcodeId::SSTORE.expr(),
                OpcodeId::CREATE.expr(),
                OpcodeId::CREATE2.expr(),
                OpcodeId::SELFDESTRUCT.expr(),
                OpcodeId::LOG0.expr(),
                OpcodeId::LOG1.expr(),
                OpcodeId::LOG2.expr(),
                OpcodeId::LOG3.expr(),
                OpcodeId::LOG4.expr(),
            ],
        );

        // Lookup values from stack if opcode is call
        // Precondition: If there's a StackUnderflow CALL, is handled before this error
        cb.condition(is_call.expr(), |cb| {
            cb.stack_pop(gas_word.expr());
            cb.stack_pop(code_address_word.expr());
            cb.stack_pop(value.expr());
            //cb.require_zero("value of call is not zero",
            // is_value_zero.expr());
        });

        // current call context is readonly
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsStatic, 1.expr());

        // constrain not root call as at least one previous staticcall preset.
        cb.require_zero(
            "ErrorWriteProtection only happen in internal call",
            cb.curr.state.is_root.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 0.expr());

        Self {
            opcode,
            is_call,
            gas: gas_word,
            code_address: code_address_word,
            value,
            is_value_zero,
            common_error_gadget,
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
        let opcode = step.opcode.unwrap();
        let is_call = opcode == OpcodeId::CALL;
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        let [mut gas, mut code_address, mut value] = [U256::zero(), U256::zero(), U256::zero()];

        if is_call {
            [gas, code_address, value] =
                [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
                    .map(|idx| block.rws[idx].stack_value());
        }

        self.gas.assign(region, offset, Some(gas.to_le_bytes()))?;
        self.code_address
            .assign(region, offset, Some(code_address.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        self.is_call.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::CALL.as_u64()),
        )?;
        self.is_value_zero
            .assign_value(region, offset, region.word_rlc(value))?;

        self.common_error_gadget.assign(
            region,
            offset,
            block,
            call,
            step,
            3 + (is_call as usize * 3),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{
        address, bytecode, bytecode::Bytecode, evm_types::OpcodeId, geth_types::Account, Address,
        ToWord, Word,
    };
    use mock::TestContext;

    // internal call test
    struct Stack {
        gas: u64,
        value: Word,
        cd_offset: u64,
        cd_length: u64,
        rd_offset: u64,
        rd_length: u64,
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

    fn caller(opcode: OpcodeId, stack: Stack, caller_is_success: bool) -> Account {
        let is_call = opcode == OpcodeId::CALL;
        let terminator = if caller_is_success {
            OpcodeId::RETURN
        } else {
            OpcodeId::REVERT
        };

        let mut bytecode = bytecode! {
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
        };
        if is_call {
            bytecode.push(32, stack.value);
        }
        bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            .write_op(opcode)
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
        });
        if is_call {
            bytecode.push(32, stack.value);
        }
        bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            .write_op(opcode)
            PUSH1(0)
            PUSH1(0)
            .write_op(terminator)
        });

        Account {
            address: Address::repeat_byte(0xfe),
            balance: Word::from(10).pow(20.into()),
            code: bytecode.to_vec().into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_write_protection() {
        // test sstore with write protection error
        test_internal_write_protection(false);
        // test call with write protection error
        test_internal_write_protection(true);
    }

    // ErrorWriteProtection error happen in internal call
    fn test_internal_write_protection(is_call: bool) {
        let mut caller_bytecode = bytecode! {
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            //PUSH1(100) //skip value for static call
        };

        caller_bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH2(40000) // gas
            STATICCALL //CALL
            STOP
        });

        let mut callee_bytecode = bytecode! {
            PUSH1(42)
            PUSH1(0x02)
        };

        if is_call {
            callee_bytecode.append(&bytecode! {
                PUSH1(0)
                PUSH1(0)
                PUSH1(10)
                PUSH1(200)  // non zero value
                PUSH20(Address::repeat_byte(0xff).to_word())
                PUSH2(10000)  // gas
                //this call got error: ErrorWriteProtection
                CALL
                RETURN
                STOP
            });
        } else {
            callee_bytecode.append(&bytecode! {
                // this SSTORE got error: ErrorWriteProtection
                SSTORE
                STOP
            });
        }

        test_ok(
            Account {
                address: Address::repeat_byte(0xfe),
                balance: Word::from(10).pow(20.into()),
                code: caller_bytecode.into(),
                ..Default::default()
            },
            callee(callee_bytecode),
        );
    }

    fn test_ok(caller: Account, callee: Account) {
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
                    .gas(150000.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
