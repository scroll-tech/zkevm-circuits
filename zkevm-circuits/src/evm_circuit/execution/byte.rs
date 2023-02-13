use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{IsEqualGadget, IsZeroGadget},
            sum, CachedRegion, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use array_init::array_init;
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use eth_types::ToLittleEndian;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct ByteGadget<F> {
    same_context: SameContextGadget<F>,
    index: Word<F>,
    value: Word<F>,
    is_msb_sum_zero: IsZeroGadget<F>,
    is_byte_selected: [IsEqualGadget<F>; 32],
}

impl<F: Field> ExecutionGadget<F> for ByteGadget<F> {
    const NAME: &'static str = "BYTE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BYTE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let index = cb.query_word_rlc();
        let value = cb.query_word_rlc();

        // If any of the non-LSB bytes of the index word are non-zero we never
        // need to copy any bytes. So just sum all the non-LSB byte
        // values here and then check if it's non-zero so we can use
        // that as an additional condition when to copy the byte value.
        let is_msb_sum_zero = IsZeroGadget::construct(cb, sum::expr(&index.cells[1..32]));

        // Now we just need to check that `result[0]` is the sum of all copied
        // bytes. We go byte by byte and check if `idx == index[0]`.
        // If they are equal (at most once) we add the byte value to the sum,
        // else we add 0. The additional condition for this is that none
        // of the non-LSB bytes are non-zero (see above). At the end
        // this sum needs to equal `result[0]`.
        let is_byte_selected = array_init(|idx| {
            // Check if this byte is selected looking only at the LSB of the
            // index word
            IsEqualGadget::construct(cb, index.cells[0].expr(), (31 - idx).expr())
        });

        // Sum all possible selected bytes
        let selected_byte = value.cells.iter().zip(is_byte_selected.iter()).fold(
            0.expr(),
            |acc, (cell, is_selected)| {
                acc + is_selected.expr() * is_msb_sum_zero.expr() * cell.expr()
            },
        );

        // Pop the byte index and the value from the stack,
        // push the selected byte on the stack
        // We can push the selected byte here directly because
        // it only uses the LSB of a word.
        cb.stack_pop(index.expr());
        cb.stack_pop(value.expr());
        cb.stack_push(selected_byte);

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::BYTE.constant_gas_cost().expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            index,
            value,
            is_msb_sum_zero,
            is_byte_selected,
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

        // Inputs/Outputs
        let index = block.rws[step.rw_indices[0]].stack_value().to_le_bytes();
        let value = block.rws[step.rw_indices[1]].stack_value().to_le_bytes();
        self.index.assign(region, offset, Some(index))?;
        self.value.assign(region, offset, Some(value))?;

        // Set `is_msb_sum_zero`
        self.is_msb_sum_zero
            .assign(region, offset, sum::value(&index[1..32]))?;

        // Set `is_byte_selected`
        for i in 0..32 {
            self.is_byte_selected[i].assign(
                region,
                offset,
                F::from(index[0] as u64),
                F::from((31 - i) as u64),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(index: Word, value: Word) {
        let bytecode = bytecode! {
            PUSH32(value)
            PUSH32(index)
            BYTE
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn byte_gadget_simple() {
        // Select byte 29 (MSB is at 0)
        test_ok(29.into(), 0x030201.into());
        // Select byte 256
        test_ok(256.into(), 0x030201.into());
    }

    #[test]
    fn byte_gadget_rand() {
        let index = rand_word();
        let value = rand_word();
        test_ok(index, value);
        test_ok(index % Word::from(32u8), value);
    }

    #[test]
    #[ignore]
    fn byte_gadget_exhaustive() {
        let value = Word::from_big_endian(&(1..33).collect::<Vec<_>>()[..]);
        for idx in 0..33 {
            test_ok(idx.into(), value);
        }
    }
}
