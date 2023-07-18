use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_MEMORY_WORD_SIZE,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                EVMConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes,
            math_gadget::IsEqualGadget,
            memory_gadget::{MemoryExpansionGadget, MemoryMask, MemoryWordAddress},
            not, CachedRegion, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian, U256};
use halo2_proofs::plonk::Error;

// MemoryGadget handles mload/mstore/mstore8 op codes gadget
#[derive(Clone, Debug)]
pub(crate) struct MemoryGadget<F> {
    same_context: SameContextGadget<F>,
    address: MemoryWordAddress<F>,
    mask: MemoryMask<F>,
    // consider move to MemoryWordAddress ?
    /// The value poped from or pushed to the stack.
    value: Word<F>,
    /// The left memory word read or written.
    value_left: Word<F>,
    /// The left memory word before the write.
    value_left_prev: Word<F>,
    /// The right memory word read or written.
    value_right: Word<F>,
    /// The right memory word before the write.
    value_right_prev: Word<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    is_mload: IsEqualGadget<F>,
    is_mstore8: IsEqualGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for MemoryGadget<F> {
    const NAME: &'static str = "MEMORY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MEMORY;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // In successful case the address must be in 5 bytes
        let address = cb.query_word_rlc();
        let address_word = MemoryWordAddress::construct(cb, address.clone());
        let value = cb.query_word_rlc();
        let value_left = cb.query_word_rlc();
        let value_left_prev = cb.query_word_rlc();
        let value_right = cb.query_word_rlc();
        let value_right_prev = cb.query_word_rlc();
        // Optimization possible: MSTORE does not need the value bytes, only the RLC. MSTORE8 does
        // not need the right value. So we could repurpose the same cells.

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

        let mask = MemoryMask::construct(cb, &address_word.shift_bits(), is_mstore8.expr());

        // Check the unchanged part of the memory words, i.e. the bytes that are not overwritten.
        mask.require_left_equal(cb, &value_left, &value_left_prev);
        mask.require_right_equal(cb, &value_right, &value_right_prev);

        // Stack operations
        // Pop the address from the stack
        cb.stack_pop(address.expr());
        // For MLOAD push the value to the stack
        // FOR MSTORE pop the value from the stack
        cb.stack_lookup(
            is_mload.expr(),
            cb.stack_pointer_offset().expr() - is_mload.expr(),
            value.expr(),
        );

        // Read or update the left word.
        cb.memory_lookup(
            is_store.clone(),
            address_word.addr_left(),
            value_left.expr(),
            value_left_prev.expr(),
            None,
        );

        cb.condition(is_mstore8.expr(), |cb| {
            // Check the byte that is written.
            let first_byte = value.cells[0].expr();
            mask.require_equal_unaligned_byte(cb, first_byte, &value_left);
        });

        cb.condition(is_not_mstore8, |cb| {
            // Check the bytes that are read or written from the left and right words.
            mask.require_equal_unaligned_word(cb, value.expr(), &value_left, &value_right);

            // Read or update the right word.
            cb.memory_lookup(
                is_store.clone(),
                address_word.addr_right(),
                value_right.expr(),
                value_right_prev.expr(),
                None,
            );
        });

        // State transition
        // - `rw_counter` needs to be increased by 34 when is_not_mstore8, otherwise to be increased
        //   by 31
        // - `program_counter` needs to be increased by 1
        // - `stack_pointer` needs to be increased by 2 when is_store, otherwise to be same
        // - `memory_size` needs to be set to `next_memory_size`
        let gas_cost = OpcodeId::MLOAD.constant_gas_cost().expr() + memory_expansion.gas_cost();
        let step_state_transition = StepStateTransition {
            //TODO: update rw_counter
            rw_counter: Delta(4.expr() - is_mstore8.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(is_store * 2.expr()),
            gas_left: Delta(-gas_cost),
            memory_word_size: To(memory_expansion.next_memory_word_size()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address: address_word,
            value,
            value_left,
            value_left_prev,
            value_right,
            value_right_prev,
            memory_expansion,
            is_mload,
            is_mstore8,
            mask,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();

        // Inputs/Outputs
        let [address, value] =
            [step.rw_indices[0], step.rw_indices[1]].map(|idx| block.rws[idx].stack_value());
        let address = address.as_u64();

        self.address.assign(region, offset, address)?;
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

        let shift = address % 32;
        self.mask
            .assign(region, offset, shift, is_mstore8 == F::one())?;

        // Memory expansion
        self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [address + if is_mstore8 == F::one() { 1 } else { 32 }],
        )?;

        // assign value_left value_right word
        let (value_left, value_left_prev) = block.rws[step.rw_indices[2]].memory_word_pair();
        let (value_right, value_right_prev) = if is_mstore8 == F::one() {
            (U256::zero(), U256::zero())
        } else {
            block.rws[step.rw_indices[3]].memory_word_pair()
        };

        self.value_left
            .assign(region, offset, Some(value_left.to_le_bytes()))?;
        self.value_left_prev
            .assign(region, offset, Some(value_left_prev.to_le_bytes()))?;

        self.value_right
            .assign(region, offset, Some(value_right.to_le_bytes()))?;
        self.value_right_prev
            .assign(region, offset, Some(value_right_prev.to_le_bytes()))?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::{
        bytecode,
        evm_types::{GasCost, OpcodeId},
        Word,
    };
    use log::trace;
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
        let val = Word::from_big_endian(&(1..33).collect::<Vec<_>>());
        trace!("value is {val}");
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
