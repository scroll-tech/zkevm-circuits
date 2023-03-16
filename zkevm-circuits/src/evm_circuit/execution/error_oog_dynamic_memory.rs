use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::{N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS};
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::RestoreContextGadget;
use crate::evm_circuit::util::constraint_builder::Transition::{Delta, Same};
use crate::evm_circuit::util::constraint_builder::{ConstraintBuilder, StepStateTransition};
use crate::evm_circuit::util::math_gadget::{IsEqualGadget, IsZeroGadget, LtGadget};
use crate::evm_circuit::util::memory_gadget::{address_high, address_low, MemoryExpansionGadget};
use crate::evm_circuit::util::{CachedRegion, Cell, Word};
use crate::table::CallContextFieldTag;
use crate::witness::{Block, Call, ExecStep, Transaction};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use gadgets::util::{and, not, select, Expr};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGDynamicMemoryGadget<F> {
    opcode: Cell<F>,
    is_create: IsEqualGadget<F>,
    is_return: IsEqualGadget<F>,
    value: Word<F>,
    address: Word<F>,
    size: Word<F>,
    address_in_range_high: IsZeroGadget<F>,
    size_in_range_high: IsZeroGadget<F>,
    expanded_address_in_range: LtGadget<F, { N_BYTES_MEMORY_ADDRESS + 1 }>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_ADDRESS>,
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

        let value = cb.query_word_rlc();
        cb.condition(is_create.expr(), |cb| {
            cb.stack_pop(value.expr());
        });

        let address = cb.query_word_rlc();
        cb.stack_pop(address.expr());
        let size = cb.query_word_rlc();
        cb.stack_pop(size.expr());

        let address_high = address_high::expr(&address);
        let address_in_range_high = IsZeroGadget::construct(cb, address_high);
        let size_high = address_high::expr(&size);
        let size_in_range_high = IsZeroGadget::construct(cb, size_high);

        let address_low = address_low::expr(&address);
        let size_low = address_low::expr(&size);
        let expanded_address = address_low.expr() + size_low.expr();
        let expanded_address_in_range = LtGadget::construct(
            cb,
            expanded_address.expr(),
            (1u64 << (N_BYTES_MEMORY_ADDRESS * 8)).expr(),
        );

        cb.require_equal(
            "address and size must less than 5 bytes",
            and::expr([
                address_in_range_high.expr(),
                size_in_range_high.expr(),
                expanded_address_in_range.expr(),
            ]),
            true.expr(),
        );

        let memory_expansion =
            MemoryExpansionGadget::construct(cb, [address_low::expr(&address) + size_low.expr()]);

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
            "gas_left must less than gas_cost",
            insufficient_gas.expr(),
            true.expr(),
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
            address,
            size,
            address_in_range_high,
            size_in_range_high,
            expanded_address_in_range,
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
        let address = block.rws[step.rw_indices[rw_offset]].stack_value();
        let size = block.rws[step.rw_indices[rw_offset + 1]].stack_value();
        self.address
            .assign(region, offset, Some(address.to_le_bytes()))?;
        self.size.assign(region, offset, Some(size.to_le_bytes()))?;

        let address_high = address_high::value::<F>(address.to_le_bytes());
        assert_eq!(
            address_high,
            F::zero(),
            "address overflow {} bytes",
            N_BYTES_MEMORY_ADDRESS
        );
        self.address_in_range_high
            .assign(region, offset, address_high)?;
        let size_high = address_high::value::<F>(size.to_le_bytes());
        assert_eq!(
            size_high,
            F::zero(),
            "size overflow {} bytes",
            N_BYTES_MEMORY_ADDRESS
        );
        self.size_in_range_high.assign(region, offset, size_high)?;

        let address_value = address_low::value(address.to_le_bytes());
        let size_value = address_low::value(size.to_le_bytes());
        let expanded_address = address_value
            .checked_add(size_value)
            .expect("address overflow u64");
        assert!(
            expanded_address < (1u64 << (N_BYTES_MEMORY_ADDRESS * 8)),
            "expanded address overflow {} bytes",
            N_BYTES_MEMORY_ADDRESS
        );
        self.expanded_address_in_range.assign(
            region,
            offset,
            F::from(expanded_address),
            F::from(1u64 << (N_BYTES_MEMORY_ADDRESS * 8)),
        )?;

        let memory_expansion_gas = self
            .memory_expansion
            .assign(region, offset, step.memory_word_size(), [expanded_address])?
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
    use eth_types::{bytecode, word, Bytecode, ToWord};
    use mock::test_ctx::helpers::account_0_code_account_1_no_code;
    use mock::{eth, TestContext, MOCK_ACCOUNTS};

    #[test]
    fn test() {
        let codes = [
            bytecode! {
                PUSH8(0xFF)
                PUSH32(word!("0xffffffff")) // offset
                RETURN
            },
            bytecode! {
                PUSH8(0xFF)
                PUSH32(word!("0xffffffff")) // offset
                REVERT
            },
            bytecode! {
                PUSH8(0xFF)
                PUSH32(word!("0xffffffff")) // offset
                PUSH8(0x0) // value
                CREATE
                STOP
            },
        ];

        for code in codes.iter() {
            test_root(code.clone());
            test_internal(code.clone());
        }
    }

    fn test_root(code: Bytecode) {
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
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

    fn test_internal(code: Bytecode) {
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
                accs[1].address(MOCK_ACCOUNTS[1]).code(code);
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
}
