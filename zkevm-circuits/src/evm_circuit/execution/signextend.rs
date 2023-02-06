use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::{FixedTableTag, Lookup},
        util::{
            and,
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{IsEqualGadget, IsZeroGadget},
            rlc, select, sum, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use array_init::array_init;
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct SignextendGadget<F> {
    same_context: SameContextGadget<F>,
    index: Word<F>,
    value: Word<F>,
    sign_byte: Cell<F>,
    is_msb_sum_zero: IsZeroGadget<F>,
    is_byte_selected: [IsEqualGadget<F>; 31],
    selectors: [Cell<F>; 31],
}

impl<F: Field> ExecutionGadget<F> for SignextendGadget<F> {
    const NAME: &'static str = "SIGNEXTEND";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SIGNEXTEND;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let index = cb.query_word_rlc();
        let value = cb.query_word_rlc();
        let sign_byte = cb.query_cell();
        let selectors = array_init(|_| cb.query_bool());

        // Generate the selectors.
        // If any of the non-LSB bytes of the index word are non-zero we never
        // need to do any changes. So just sum all the non-LSB byte
        // values here and then check if it's non-zero so we can use
        // that as an additional condition to enable the selector.
        let is_msb_sum_zero = IsZeroGadget::construct(cb, sum::expr(&index.cells[1..32]));

        // Check if this byte is selected looking only at the LSB of the index
        // word
        let is_byte_selected =
            array_init(|idx| IsEqualGadget::construct(cb, index.cells[0].expr(), idx.expr()));

        // We need to find the byte we have to get the sign from so we can
        // extend correctly. We go byte by byte and check if `idx ==
        // index[0]`. If they are equal (at most once) we add the byte
        // value to the sum, else we add 0. We also generate the
        // selectors, which we'll use to decide if we need to
        // replace bytes with the sign byte.
        // There is no need to check the MSB, even if the MSB is selected no
        // bytes need to be changed.
        let mut selected_byte = 0.expr();
        for idx in 0..31 {
            // Check if this byte is selected
            // The additional condition for this is that none of the non-LSB
            // bytes are non-zero (see above).
            let is_selected = and::expr(&[is_byte_selected[idx].expr(), is_msb_sum_zero.expr()]);

            // Add the byte to the sum when this byte is selected
            selected_byte = selected_byte + (is_selected.clone() * value.cells[idx].expr());

            // Verify the selector.
            // Cells are used here to store intermediate results, otherwise
            // these sums are very long expressions.
            // The selector for a byte position is enabled when its value needs
            // to change to the sign byte. Once a byte was selected,
            // all following bytes need to be replaced as well, so a
            // selector is the sum of the current and all previous `is_selected`
            // values.
            cb.require_equal(
                "Constrain selector == 1 when is_selected == 1 || previous selector == 1",
                is_selected.clone()
                    + if idx > 0 {
                        selectors[idx - 1].expr()
                    } else {
                        0.expr()
                    },
                selectors[idx].expr(),
            );
        }

        // Lookup the sign byte.
        // This will use the most significant bit of the selected byte to return
        // the sign byte, which is a byte with all its bits set to the
        // sign of the selected byte.
        cb.add_lookup(
            "SignByte lookup",
            Lookup::Fixed {
                tag: FixedTableTag::SignByte.expr(),
                values: [selected_byte, sign_byte.expr(), 0.expr()],
            },
        );

        // Verify the result.
        // The LSB always remains the same, all other bytes with their selector
        // enabled need to be changed to the sign byte.
        // When a byte was selected all the **following** bytes need to be
        // replaced (hence the `selectors[idx - 1]`).
        let result = rlc::expr(
            &array_init::<_, _, 32>(|idx| {
                if idx == 0 {
                    value.cells[idx].expr()
                } else {
                    select::expr(
                        selectors[idx - 1].expr(),
                        sign_byte.expr(),
                        value.cells[idx].expr(),
                    )
                }
            }),
            cb.challenges().evm_word(),
        );

        // Pop the byte index and the value from the stack, push the result on
        // the stack
        cb.stack_pop(index.expr());
        cb.stack_pop(value.expr());
        cb.stack_push(result);

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::SIGNEXTEND.constant_gas_cost().expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            index,
            value,
            sign_byte,
            is_msb_sum_zero,
            is_byte_selected,
            selectors,
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

        // Generate the selectors
        let msb_sum_zero =
            self.is_msb_sum_zero
                .assign(region, offset, sum::value(&index[1..32]))?;
        let mut previous_selector_value: F = 0.into();
        for i in 0..31 {
            let selected = and::value(vec![
                self.is_byte_selected[i].assign(
                    region,
                    offset,
                    F::from(index[0] as u64),
                    F::from(i as u64),
                )?,
                msb_sum_zero,
            ]);
            let selector_value = selected + previous_selector_value;
            self.selectors[i]
                .assign(region, offset, Value::known(selector_value))
                .unwrap();
            previous_selector_value = selector_value;
        }

        // Set the sign byte
        let mut sign = 0u64;
        if index[0] < 31 && msb_sum_zero == F::one() {
            sign = (value[index[0] as usize] >> 7) as u64;
        }
        self.sign_byte
            .assign(region, offset, Value::known(F::from(sign * 0xFF)))
            .unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, ToLittleEndian, Word};
    use mock::TestContext;

    fn test_ok(index: Word, value: Word, _result: Word) {
        let bytecode = bytecode! {
            PUSH32(value)
            PUSH32(index)
            SIGNEXTEND
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn signextend_gadget_simple() {
        // Extend byte 2 (negative)
        test_ok(
            2.into(),
            0xF00201.into(),
            Word::from_little_endian(&[
                0x01, 0x02, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF,
            ]),
        );
        // Extend byte 0 (positive)
        test_ok(0.into(), 0xFF01.into(), 1.into());
        // Extend byte 258
        test_ok(258.into(), 0xF00201.into(), 0xF00201.into());
    }

    #[test]
    fn signextend_gadget_rand() {
        let signextend = |index: Word, value: Word| -> Word {
            if index < Word::from(32u8) {
                let index = index.to_le_bytes()[0] as usize;
                let mask = (Word::one() << (index * 8 + 7)) - Word::one();
                if value.to_le_bytes()[index] >> 7 == 1 {
                    value | (!mask)
                } else {
                    value & mask
                }
            } else {
                value
            }
        };

        let index = rand_word();
        let value = rand_word();
        test_ok(index, value, signextend(index, value));
        test_ok(
            index % Word::from(32u8),
            value,
            signextend(index % Word::from(32u8), value),
        );
    }

    #[test]
    #[ignore]
    fn signextend_gadget_exhaustive() {
        let pos_value: [u8; 32] = [0b01111111u8; 32];
        let neg_value: [u8; 32] = [0b10000000u8; 32];

        let pos_extend = 0u8;
        let neg_extend = 0xFFu8;

        for (value, byte_extend) in vec![(pos_value, pos_extend), (neg_value, neg_extend)].iter() {
            for idx in 0..33 {
                test_ok(
                    (idx as u64).into(),
                    Word::from_little_endian(value),
                    Word::from_little_endian(
                        &(0..32)
                            .map(|i| if i > idx { *byte_extend } else { value[i] })
                            .collect::<Vec<u8>>(),
                    ),
                );
            }
        }
    }
}
