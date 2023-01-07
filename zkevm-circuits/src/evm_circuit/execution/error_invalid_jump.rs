use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_PROGRAM_COUNTER,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, Same},
            },
            from_bytes,
            math_gadget::{IsEqualGadget, IsZeroGadget, LtGadget},
            CachedRegion, Cell, RandomLinearCombination, Word as RLCWord,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian, Word};

use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidJumpGadget<F> {
    opcode: Cell<F>,
    destination: RandomLinearCombination<F, N_BYTES_PROGRAM_COUNTER>,
    code_length: Cell<F>,
    value: Cell<F>,
    is_code: Cell<F>,
    within_range: LtGadget<F, N_BYTES_PROGRAM_COUNTER>,
    is_jump_dest: IsEqualGadget<F>,
    is_jumpi: IsEqualGadget<F>,
    condition: Cell<F>,
    is_condition_zero: IsZeroGadget<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidJumpGadget<F> {
    const NAME: &'static str = "ErrorInvalidJump";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidJump;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let destination = cb.query_rlc();
        let opcode = cb.query_cell();
        let value = cb.query_cell();
        let is_code = cb.query_cell();
        let condition = cb.query_cell();

        cb.require_in_set(
            "ErrorInvalidJump only happend in JUMP or JUMPI",
            opcode.expr(),
            vec![OpcodeId::JUMP.expr(), OpcodeId::JUMPI.expr()],
        );

        let is_jumpi = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::JUMPI.expr());

        // initialize is_jump_dest
        let is_jump_dest = IsEqualGadget::construct(cb, value.expr(), OpcodeId::JUMPDEST.expr());

        // first default this condition, if use will re-construct with real condition
        // value
        let is_condition_zero = IsZeroGadget::construct(cb, condition.expr());

        // Pop the value from the stack
        cb.stack_pop(destination.expr());

        cb.condition(is_jumpi.expr(), |cb| {
            cb.stack_pop(condition.expr());
            // if condition is zero, jump will not happen, so constrain condition not zero
            cb.require_zero("condition is not zero", is_condition_zero.expr());
        });

        // look up bytecode length
        let code_length = cb.bytecode_length(cb.curr.state.code_hash.expr());
        let dest_value = from_bytes::expr(&destination.cells);

        let within_range = LtGadget::construct(cb, dest_value.expr(), code_length.expr());
        //if not out of range, check `dest` is invalid
        cb.condition(within_range.expr(), |cb| {
            // if not out of range, Lookup real value
            cb.bytecode_lookup(
                cb.curr.state.code_hash.expr(),
                dest_value.clone(),
                is_code.expr(),
                value.expr(),
            );
            cb.require_zero(
                "is_code is false or not JUMPDEST",
                is_code.expr() * is_jump_dest.expr(),
            );
        });

        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 0.expr());

        // Go to EndTx only when is_root
        let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        cb.require_equal(
            "Go to EndTx only when is_root",
            cb.curr.state.is_root.expr(),
            is_to_end_tx,
        );

        // When it's a root call
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            // Do step state transition
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(
                    2.expr() + is_jumpi.expr() + cb.curr.state.reversible_write_counter.expr(),
                ),

                ..StepStateTransition::any()
            });
        });

        // When it's an internal call, need to restore caller's state as finishing this
        // call. Restore caller state to next StepState
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(
                cb,
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
            )
        });

        Self {
            opcode,
            destination,
            code_length,
            value,
            is_code,
            within_range,
            is_jump_dest,
            is_jumpi,
            condition,
            is_condition_zero,
            restore_context,
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
        let is_jumpi = opcode == OpcodeId::JUMPI;

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        let destination = block.rws[step.rw_indices[0]].stack_value();
        let condition = if is_jumpi {
            block.rws[step.rw_indices[1]].stack_value()
        } else {
            Word::zero()
        };
        let condition_rlc =
            RLCWord::random_linear_combine(condition.to_le_bytes(), block.randomness);

        self.destination.assign(
            region,
            offset,
            Some(
                destination.to_le_bytes()[..N_BYTES_PROGRAM_COUNTER]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        let code = block
            .bytecodes
            .get(&call.code_hash)
            .expect("could not find current environment's bytecode");
        let code_length = code.bytes.len() as u64;
        self.code_length
            .assign(region, offset, Value::known(F::from(code_length)))?;

        // set default value in case can not find value, is_code from bytecode table
        let mut code_pair = [0u8, 0u8];
        if destination.as_u64() < code_length {
            // get real value from bytecode table
            code_pair = code.get(destination.as_usize());
        }

        self.value
            .assign(region, offset, Value::known(F::from(code_pair[0] as u64)))?;
        self.is_code
            .assign(region, offset, Value::known(F::from(code_pair[1] as u64)))?;
        self.is_jump_dest.assign(
            region,
            offset,
            F::from(code_pair[0] as u64),
            F::from(OpcodeId::JUMPDEST.as_u64()),
        )?;

        self.within_range.assign(
            region,
            offset,
            F::from(destination.as_u64()),
            F::from(code_length),
        )?;

        self.is_jumpi.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::JUMPI.as_u64()),
        )?;

        self.condition
            .assign(region, offset, Value::known(condition_rlc))?;
        self.is_condition_zero
            .assign(region, offset, condition_rlc)?;

        self.restore_context
            .assign(region, offset, block, call, step, 2 + is_jumpi as usize)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::run_test_circuit;
    use crate::evm_circuit::witness::block_convert;
    use crate::test_util::run_test_circuits;
    use eth_types::bytecode::Bytecode;
    use eth_types::evm_types::OpcodeId;
    use eth_types::geth_types::Account;
    use eth_types::{address, bytecode, Address, ToWord, Word};
    use halo2_proofs::halo2curves::bn256::Fr;
    use mock::TestContext;

    fn test_invalid_jump(destination: usize, out_of_range: bool) {
        let mut bytecode = bytecode! {
            PUSH32(if out_of_range { destination + 10} else { destination })
            JUMP
        };

        // incorrect assigning for invalid jump
        for _ in 0..(destination - 33) {
            bytecode.write(0, false);
        }
        bytecode.append(&bytecode! {
            JUMPDEST
            STOP
        });

        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                None
            ),
            Ok(())
        );
    }

    #[test]
    fn invalid_jump_err() {
        test_invalid_jump(34, false);
    }

    #[test]
    fn invalid_jump_outofrange() {
        test_invalid_jump(40, true);
    }

    #[test]
    fn invalid_jump_internal() {
        // test jump error in internal call
        test_internal_jump_error(false);
        // test jumpi error in internal call
        test_internal_jump_error(true);
    }

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

        // Call twice for testing both cold and warm access
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

    // jump or jumpi error happen in internal call
    fn test_internal_jump_error(is_jumpi: bool) {
        let mut caller_bytecode = bytecode! {
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
        };

        caller_bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH2(10000)
            CALL
            STOP
        });

        let opcode = if is_jumpi {
            OpcodeId::JUMPI
        } else {
            OpcodeId::JUMP
        };

        let mut callee_bytecode = bytecode! {
            PUSH1(1) //  work as condition if is_jumpi
            PUSH1(42) // jump dest 45
            .write_op(opcode)

            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
        };

        callee_bytecode.append(&bytecode! {
            PUSH20(Address::repeat_byte(0xff).to_word())
            PUSH1(132) // gas

            JUMPDEST
            GAS
            PUSH1(1)
            AND
            PUSH1(56)
            JUMPI

            PUSH1(0)
            PUSH1(0)
            REVERT

            JUMPDEST
            STOP
        });
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
                    .gas(100000.into());
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
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        assert_eq!(run_test_circuit(block), Ok(()));
    }

    fn test_invalid_jumpi(destination: usize) {
        let mut bytecode = bytecode! {
            PUSH32(destination)
            PUSH32(100) // condition
            JUMPI
        };

        // incorrect assigning for invalid jump
        for _ in 0..(destination - 33) {
            bytecode.write(0, false);
        }
        bytecode.append(&bytecode! {
            JUMPDEST
            STOP
        });

        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                None
            ),
            Ok(())
        );
    }

    #[test]
    fn invalid_jumpi_err_root() {
        test_invalid_jumpi(34);
    }
}
