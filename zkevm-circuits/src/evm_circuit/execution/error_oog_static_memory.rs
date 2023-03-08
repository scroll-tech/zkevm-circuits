use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            and,
            common_gadget::RestoreContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta, Transition::Same,
            },
            math_gadget::{IsEqualGadget, IsZeroGadget, LtGadget},
            memory_gadget::{address_high, address_low, MemoryExpansionGadget},
            not, select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGStaticMemoryGadget<F> {
    opcode: Cell<F>,
    address: Word<F>,
    // Allow memory size to expand to 5 bytes, because memory address could be
    // at most 2^40 - 1, after constant division by 32, the memory word size
    // then could be at most 2^35 - 1.
    // So generic N_BYTES_MEMORY_WORD_SIZE for MemoryExpansionGadget needs to
    // be larger by 1 than normal usage (to be 5), to be able to contain
    // number up to 2^35 - 1.
    address_in_range_high: IsZeroGadget<F>,
    expanded_address_in_range: LtGadget<F, { N_BYTES_MEMORY_ADDRESS + 1 }>,
    memory_expansion: MemoryExpansionGadget<F, 1, { N_BYTES_MEMORY_WORD_SIZE + 1 }>,
    // Even memory size at most could be 2^35 - 1, the qudratic part of memory
    // expansion gas cost could be at most 2^61 - 2^27, due to the constant
    // division by 512, which still fits in 8 bytes.
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

        // Query address by a full word
        let address = cb.query_word_rlc();
        cb.stack_pop(address.expr());

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

        // Check if the memory address is too large
        let address_low = address_low::expr(&address);
        let address_high = address_high::expr(&address);
        let size = select::expr(is_mstore8.expr(), 1.expr(), 32.expr());
        let expanded_address = address_low.expr() + size.expr();

        // sanity check
        let address_in_range_high = IsZeroGadget::construct(cb, address_high);
        let expanded_address_in_range = LtGadget::construct(
            cb,
            expanded_address.expr(),
            (1u64 << (N_BYTES_MEMORY_ADDRESS * 8)).expr(),
        );

        cb.require_equal(
            "address must less than 5 bytes",
            and::expr([
                address_in_range_high.expr(),
                expanded_address_in_range.expr(),
            ]),
            true.expr(),
        );

        // Get the next memory size and the gas cost for this memory access
        let memory_expansion = MemoryExpansionGadget::construct(cb, [expanded_address]);

        // Check if the amount of gas available is less than the amount of gas
        // required
        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            OpcodeId::MLOAD.constant_gas_cost().expr() + memory_expansion.gas_cost(),
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
            address,
            address_in_range_high,
            expanded_address_in_range,
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
        let address = block.rws[step.rw_indices[0]].stack_value();
        self.address
            .assign(region, offset, Some(address.to_le_bytes()))?;

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

        // Address in range check
        let address_high = address_high::value::<F>(address.to_le_bytes());
        self.address_in_range_high
            .assign(region, offset, address_high)?;

        let address_value = address_low::value(address.to_le_bytes());
        let size = if opcode == OpcodeId::MSTORE8 { 1 } else { 32 };

        let expanded_address = address_value
            .checked_add(size)
            .expect("address overflow u64");
        self.expanded_address_in_range.assign(
            region,
            offset,
            F::from(expanded_address),
            F::from(1u64 << (N_BYTES_MEMORY_ADDRESS * 8)),
        )?;

        // TODO: sanity check, remove this after fixing #347 missing ErrGasUintOverflow
        if address_high != F::zero() || expanded_address > (1u64 << (N_BYTES_MEMORY_ADDRESS * 8)) {
            panic!("address overflow {} bytes", N_BYTES_MEMORY_ADDRESS);
        }

        self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [expanded_address],
        )?;

        // Gas insufficient check
        // Get `gas_available` variable here once it's available
        self.insufficient_gas.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(step.gas_cost),
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
    use eth_types::{bytecode, word, Bytecode, ToWord};
    use mock::test_ctx::helpers::account_0_code_account_1_no_code;
    use mock::{eth, TestContext, MOCK_ACCOUNTS};

    #[test]
    fn test() {
        let codes = [
            bytecode! {
                PUSH8(0xFF)
                PUSH32(word!("0xffffffff")) // offset
                MSTORE
                STOP
            },
            bytecode! {
                PUSH8(0xFF)
                PUSH32(word!("0xffffffff")) // offset
                MSTORE8
                STOP
            },
            bytecode! {
                PUSH32(word!("0xffffffff")) // offset
                MLOAD
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
            // Decrease expected gas cost (by 1) to trigger out of gas error.
            PUSH32(0xF) // gas
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
                    .gas(word!("0xFFFF"));
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
