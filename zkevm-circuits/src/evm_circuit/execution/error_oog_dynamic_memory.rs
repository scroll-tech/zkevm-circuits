use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, Same},
            },
            math_gadget::{IsEqualGadget, LtGadget},
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryExpandedAddressGadget, MemoryExpansionGadget,
            },
            or, CachedRegion, Cell, Word,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian};
use gadgets::util::{not, select, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGDynamicMemoryGadget<F> {
    opcode: Cell<F>,
    is_create: IsEqualGadget<F>,
    is_return: IsEqualGadget<F>,
    value: Word<F>,
    memory_address: MemoryExpandedAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    rw_counter_end_of_reversion: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGDynamicMemoryGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasDynamicMemoryExpansion";
    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasDynamicMemoryExpansion;

    // Support other OOG due to pure memory including CREATE, RETURN and REVERT
    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        let is_create = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::CREATE.expr());
        let is_return = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::RETURN.expr());

        cb.require_equal(
            "ErrorOutOfGasDynamicMemoryExpansion opcode must be CREATE or RETURN or REVERT",
            opcode.expr(),
            select::expr(
                is_create.expr(),
                OpcodeId::CREATE.expr(),
                select::expr(
                    is_return.expr(),
                    OpcodeId::RETURN.expr(),
                    OpcodeId::REVERT.expr(),
                ),
            ),
        );

        let memory_address = MemoryExpandedAddressGadget::construct_self(cb);

        let value = cb.query_word_rlc();
        cb.condition(is_create.expr(), |cb| {
            cb.stack_pop(value.expr());
        });

        cb.stack_pop(memory_address.offset_rlc());
        cb.stack_pop(memory_address.length_rlc());

        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);

        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            select::expr(
                is_create.expr(),
                OpcodeId::CREATE.constant_gas_cost().expr(),
                select::expr(
                    is_return.expr(),
                    OpcodeId::RETURN.constant_gas_cost().expr(),
                    OpcodeId::REVERT.constant_gas_cost().expr(),
                ),
            ) + memory_expansion.gas_cost(),
        );

        cb.require_equal(
            "Memory address is overflow or gas left is less than cost",
            or::expr([memory_address.overflow(), insufficient_gas.expr()]),
            1.expr(),
        );

        // Current call must fail.
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 0.expr());

        let rw_counter_end_of_reversion = cb.query_cell();
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::RwCounterEndOfReversion,
            rw_counter_end_of_reversion.expr(),
        );

        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(
                    4.expr() + is_create.expr() + cb.curr.state.reversible_write_counter.expr(),
                ),
                ..StepStateTransition::any()
            });
        });
        let restore_context = cb.condition(not::expr(cb.curr.state.is_root.expr()), |cb| {
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
            is_create,
            is_return,
            value,
            memory_address,
            memory_expansion,
            insufficient_gas,
            rw_counter_end_of_reversion,
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

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.is_create.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::CREATE.as_u64()),
        )?;
        self.is_return.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::RETURN.as_u64()),
        )?;

        let mut rw_offset = 0;
        if opcode == OpcodeId::CREATE {
            let value = block.rws[step.rw_indices[rw_offset]].stack_value();
            self.value
                .assign(region, offset, Some(value.to_le_bytes()))?;
            rw_offset += 1;
        }
        let memory_offset = block.rws[step.rw_indices[rw_offset]].stack_value();
        let memory_length = block.rws[step.rw_indices[rw_offset + 1]].stack_value();
        let memory_address =
            self.memory_address
                .assign(region, offset, memory_offset, memory_length)?;

        let memory_expansion_gas = self
            .memory_expansion
            .assign(region, offset, step.memory_word_size(), [memory_address])?
            .1;
        let constant_gas_cost = opcode.constant_gas_cost().0;

        self.insufficient_gas.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(memory_expansion_gas + constant_gas_cost),
        )?;

        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Value::known(F::from(call.rw_counter_end_of_reversion as u64)),
        )?;

        self.restore_context.assign(
            region,
            offset,
            block,
            call,
            step,
            if opcode == OpcodeId::CREATE { 5 } else { 4 },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, word, Bytecode, ToWord, U256};
    use mock::{
        eth, test_ctx::helpers::account_0_code_account_1_no_code, TestContext, MOCK_ACCOUNTS,
    };

    #[test]
    fn test_oog_dynamic_memory_simple() {
        for code in testing_bytecodes(0xffffffff_u64.into(), 0xff.into()).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    #[test]
    fn test_oog_dynamic_memory_max_expanded_address() {
        // 0xffffffff1 + 0xffffffff0 = 0x1fffffffe1
        // > MAX_EXPANDED_MEMORY_ADDRESS (0x1fffffffe0)
        for code in testing_bytecodes(0xffffffff1_u64.into(), 0xffffffff0_u64.into()).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    #[test]
    fn test_oog_dynamic_memory_max_u64_address() {
        for code in testing_bytecodes(u64::MAX.into(), u64::MAX.into()).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    #[test]
    fn test_oog_dynamic_memory_max_word_address() {
        for code in testing_bytecodes(U256::MAX, U256::MAX).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    fn test_root(code: &Bytecode) {
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code.clone()),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(word!("0xFFFF"));
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn test_internal(code: &Bytecode) {
        let code_a = bytecode! {
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(0x00) // argsLength
            PUSH32(0x00) // argsOffset
            PUSH1(0x00) // value
            PUSH32(MOCK_ACCOUNTS[1].to_word()) // addr
            PUSH32(0xFFFF) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).code(code_a);
                accs[1].address(MOCK_ACCOUNTS[1]).code(code.clone());
                accs[2].address(MOCK_ACCOUNTS[2]).balance(eth(1));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[2].address)
                    .to(accs[0].address)
                    .gas(word!("0xFFFFF"));
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn testing_bytecodes(offset: U256, size: U256) -> Vec<Bytecode> {
        vec![
            bytecode! {
                PUSH32(size)
                PUSH32(offset)
                RETURN
            },
            bytecode! {
                PUSH32(size)
                PUSH32(offset)
                REVERT
            },
            bytecode! {
                PUSH32(size)
                PUSH32(offset)
                PUSH8(0) // value
                CREATE
                STOP
            },
        ]
    }
}
