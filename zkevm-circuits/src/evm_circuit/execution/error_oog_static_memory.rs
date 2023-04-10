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
            not, or, select, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGStaticMemoryGadget<F> {
    opcode: Cell<F>,
    memory_address: MemoryExpandedAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    is_mload: IsEqualGadget<F>,
    is_mstore8: IsEqualGadget<F>,
    rw_counter_end_of_reversion: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGStaticMemoryGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasStaticMemoryExpansion";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasStaticMemoryExpansion;

    // Support other OOG due to pure memory including MSTORE, MSTORE8 and MLOAD
    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        let memory_address = MemoryExpandedAddressGadget::construct_self(cb);
        cb.stack_pop(memory_address.offset_rlc());

        // Check if this is an MSTORE8
        let is_mload = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::MLOAD.expr());
        let is_mstore8 = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::MSTORE8.expr());

        cb.require_equal(
            "ErrorOutOfGasStaticMemoryExpansion opcode must be MLOAD or MSTORE or MSTORE8",
            opcode.expr(),
            select::expr(
                is_mload.expr(),
                OpcodeId::MLOAD.expr(),
                select::expr(
                    is_mstore8.expr(),
                    OpcodeId::MSTORE8.expr(),
                    OpcodeId::MSTORE.expr(),
                ),
            ),
        );

        cb.require_equal(
            "Memory length must be 32 for MLOAD and MSTORE, and 1 for MSTORE8",
            memory_address.length_rlc(),
            select::expr(is_mstore8.expr(), 1.expr(), 32.expr()),
        );

        // Get the next memory size and the gas cost for this memory access
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);

        // Check if the amount of gas available is less than the amount of gas
        // required
        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            OpcodeId::MLOAD.constant_gas_cost().expr() + memory_expansion.gas_cost(),
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
                rw_counter: Delta(3.expr() + cb.curr.state.reversible_write_counter.expr()),
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
            memory_address,
            memory_expansion,
            insufficient_gas,
            is_mload,
            is_mstore8,
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

        // Inputs/Outputs
        let memory_offset = block.rws[step.rw_indices[0]].stack_value();

        // Memory lengths are set to default values for MLOAD, MSTORE and
        // MSTORE8 in go-ethereum.
        // <https://github.com/ethereum/go-ethereum/blob/4a9fa31450d3cdcea84735b68cd5a0a8450473f8/core/vm/memory_table.go#L39>
        let memory_length = match opcode {
            OpcodeId::MLOAD | OpcodeId::MSTORE => 32,
            OpcodeId::MSTORE8 => 1,
            _ => unreachable!(),
        };

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.is_mload.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::MLOAD.as_u64()),
        )?;
        self.is_mstore8.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::MSTORE8.as_u64()),
        )?;

        let memory_address =
            self.memory_address
                .assign(region, offset, memory_offset, memory_length.into())?;

        let memory_expansion_cost = self
            .memory_expansion
            .assign(region, offset, step.memory_word_size(), [memory_address])?
            .1;

        // Gas insufficient check
        // Get `gas_available` variable here once it's available
        self.insufficient_gas.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(OpcodeId::MLOAD.constant_gas_cost().0 + memory_expansion_cost),
        )?;

        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Value::known(F::from(call.rw_counter_end_of_reversion as u64)),
        )?;
        self.restore_context
            .assign(region, offset, block, call, step, 3)?;

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
    fn test_oog_static_memory_simple() {
        for code in testing_bytecodes(0xffffffff_u64.into()).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    #[test]
    fn test_oog_static_memory_max_expanded_address() {
        // > MAX_EXPANDED_MEMORY_ADDRESS (0x1fffffffe0)
        for code in testing_bytecodes(0x1fffffffe1_u64.into()).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    #[test]
    fn test_oog_static_memory_max_u64_address() {
        for code in testing_bytecodes(u64::MAX.into()).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    #[test]
    fn test_oog_static_memory_max_word_address() {
        for code in testing_bytecodes(U256::MAX).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    fn testing_bytecodes(offset: U256) -> Vec<Bytecode> {
        vec![
            bytecode! {
                PUSH8(0xff)
                PUSH32(offset)
                MSTORE
                STOP
            },
            bytecode! {
                PUSH8(0xff)
                PUSH32(offset)
                MSTORE8
                STOP
            },
            bytecode! {
                PUSH32(offset)
                MLOAD
                STOP
            },
        ]
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
            // Decrease expected gas cost (by 1) to trigger out of gas error.
            PUSH32(0xF) // gas
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
                    .gas(word!("0xFFFF"));
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
