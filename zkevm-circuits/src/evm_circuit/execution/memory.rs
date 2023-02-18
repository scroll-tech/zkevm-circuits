use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes,
            math_gadget::IsEqualGadget,
            memory_gadget::MemoryExpansionGadget,
            not, CachedRegion, MemoryAddress, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct MemoryGadget<F> {
    same_context: SameContextGadget<F>,
    address: MemoryAddress<F>,
    value: Word<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    is_mload: IsEqualGadget<F>,
    is_mstore8: IsEqualGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for MemoryGadget<F> {
    const NAME: &'static str = "MEMORY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MEMORY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // In successful case the address must be in 5 bytes
        let address = cb.query_word_rlc();
        let value = cb.query_word_rlc();

        // Check if this is an MLOAD
        let is_mload = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::MLOAD.expr());
        // Check if this is an MSTORE8
        let is_mstore8 = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::MSTORE8.expr());
        // This is an MSTORE/MSTORE8
        let is_store = not::expr(is_mload.expr());
        // This is an MSTORE/MLOAD
        let is_not_mstore8 = not::expr(is_mstore8.expr());

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            [from_bytes::expr(&address.cells) + 1.expr() + (is_not_mstore8.clone() * 31.expr())],
        );

        /* Stack operations */
        // Pop the address from the stack
        cb.stack_pop(address.expr());
        // For MLOAD push the value to the stack
        // FOR MSTORE pop the value from the stack
        cb.stack_lookup(
            is_mload.expr(),
            cb.stack_pointer_offset().expr() - is_mload.expr(),
            value.expr(),
        );

        cb.condition(is_mstore8.expr(), |cb| {
            cb.memory_lookup(
                1.expr(),
                from_bytes::expr(&address.cells),
                value.cells[0].expr(),
                None,
            );
        });

        cb.condition(is_not_mstore8, |cb| {
            for idx in 0..32 {
                cb.memory_lookup(
                    is_store.clone(),
                    from_bytes::expr(&address.cells) + idx.expr(),
                    value.cells[31 - idx].expr(),
                    None,
                );
            }
        });

        // State transition
        // - `rw_counter` needs to be increased by 34 when is_not_mstore8, otherwise to
        //   be increased by 31
        // - `program_counter` needs to be increased by 1
        // - `stack_pointer` needs to be increased by 2 when is_store, otherwise to be
        //   same
        // - `memory_size` needs to be set to `next_memory_size`
        let gas_cost = OpcodeId::MLOAD.constant_gas_cost().expr() + memory_expansion.gas_cost();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(34.expr() - is_mstore8.expr() * 31.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(is_store * 2.expr()),
            gas_left: Delta(-gas_cost),
            memory_word_size: To(memory_expansion.next_memory_word_size()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address,
            value,
            memory_expansion,
            is_mload,
            is_mstore8,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();

        // Inputs/Outputs
        let [address, value] =
            [step.rw_indices[0], step.rw_indices[1]].map(|idx| block.rws[idx].stack_value());
        self.address.assign(
            region,
            offset,
            Some(
                address.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        // Check if this is an MLOAD
        self.is_mload.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::MLOAD.as_u64()),
        )?;
        // Check if this is an MSTORE8
        let is_mstore8 = self.is_mstore8.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::MSTORE8.as_u64()),
        )?;

        // Memory expansion
        self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [address.as_u64() + if is_mstore8 == F::one() { 1 } else { 32 }],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_word;
    use crate::test_util::CircuitTestBuilder;
    use eth_types::bytecode;
    use eth_types::evm_types::{GasCost, OpcodeId};
    use eth_types::Word;
    use mock::test_ctx::{helpers::*, TestContext};
    use std::iter;

    fn test_ok(opcode: OpcodeId, address: Word, value: Word, gas_cost: u64) {
        let bytecode = bytecode! {
            PUSH32(value)
            PUSH32(address)
            .write_op(opcode)
            STOP
        };

        let gas_limit =
            GasCost::TX.as_u64() + OpcodeId::PUSH32.as_u64() + OpcodeId::PUSH32.as_u64() + gas_cost;

        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(bytecode),
            |mut txs, accs| {
                txs[0]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .gas(Word::from(gas_limit));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn memory_gadget_simple() {
        test_ok(
            OpcodeId::MSTORE,
            Word::from(0x12FFFF),
            Word::from_big_endian(&(1..33).collect::<Vec<_>>()),
            3074206,
        );
        test_ok(
            OpcodeId::MLOAD,
            Word::from(0x12FFFF),
            Word::from_big_endian(&(1..33).collect::<Vec<_>>()),
            3074206,
        );
        test_ok(
            OpcodeId::MLOAD,
            Word::from(0x12FFFF) + 16,
            Word::from_big_endian(&(17..33).chain(iter::repeat(0).take(16)).collect::<Vec<_>>()),
            3074361,
        );
        test_ok(
            OpcodeId::MSTORE8,
            Word::from(0x12FFFF),
            Word::from_big_endian(&(1..33).collect::<Vec<_>>()),
            3074051,
        );
    }

    #[test]
    fn memory_gadget_rand() {
        let calc_gas_cost = |opcode, memory_address: Word| {
            let memory_address = memory_address.as_u64()
                + match opcode {
                    OpcodeId::MSTORE | OpcodeId::MLOAD => 32,
                    OpcodeId::MSTORE8 => 1,
                    _ => 0,
                }
                + 31;
            let memory_size = memory_address / 32;

            GasCost::FASTEST.as_u64() + 3 * memory_size + memory_size * memory_size / 512
        };

        for opcode in [OpcodeId::MSTORE, OpcodeId::MLOAD, OpcodeId::MSTORE8] {
            // we use 15-bit here to reduce testing resource consumption.
            // In real cases the memory_address is 5 bytes (40 bits)
            let max_memory_address_pow_of_two = 15;
            let memory_address = rand_word() % (1u64 << max_memory_address_pow_of_two);
            let value = rand_word();
            test_ok(
                opcode,
                memory_address,
                value,
                calc_gas_cost(opcode, memory_address),
            );
        }
    }

    #[test]
    fn oog_static_memory_case() {
        test_ok(
            OpcodeId::MSTORE,
            Word::from(0x12FFFF),
            Word::from_big_endian(&(1..33).collect::<Vec<_>>()),
            // insufficient gas
            3000000,
        );
        test_ok(
            OpcodeId::MLOAD,
            Word::from(0x12FFFF),
            Word::from_big_endian(&(1..33).collect::<Vec<_>>()),
            // insufficient gas
            21000,
        );
    }
}
