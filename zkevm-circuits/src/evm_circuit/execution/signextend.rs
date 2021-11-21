use crate::{
    evm_circuit::{
        execution::{bus_mapping_tmp::ExecTrace, ExecutionGadget},
        step::ExecutionResult,
        table::{FixedTableTag, Lookup},
        util::{
            and,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            math_gadget::{IsEqualGadget, IsZeroGadget, RangeCheckGadget},
            select, sum, Cell, Word,
        },
    },
    util::Expr,
};
use array_init::array_init;
use bus_mapping::{eth_types::ToLittleEndian, evm::GasCost};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone)]
pub(crate) struct SignextendGadget<F> {
    opcode: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, 8>,
    index: Word<F>,
    value: Word<F>,
    sign_byte: Cell<F>,
    is_msb_sum_zero: IsZeroGadget<F>,
    is_byte_selected: [IsEqualGadget<F>; 31],
    selectors: [Cell<F>; 31],
}

impl<F: FieldExt> ExecutionGadget<F> for SignextendGadget<F> {
    const NAME: &'static str = "SIGNEXTEND";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::SIGNEXTEND;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr());

        let sufficient_gas_left =
            cb.require_sufficient_gas_left(GasCost::FAST.expr());

        let index = cb.query_word();
        let value = cb.query_word();
        let sign_byte = cb.query_cell();
        let selectors = array_init(|_| cb.query_bool());

        // Generate the selectors.
        // If any of the non-LSB bytes of the index word are non-zero we never need to do any changes.
        // So just sum all the non-LSB byte values here and then check if it's non-zero
        // so we can use that as an additional condition to enable the selector.
        let is_msb_sum_zero =
            IsZeroGadget::construct(cb, sum::expr(&index.cells[1..32]));

        // Check if this byte is selected looking only at the LSB of the index word
        let is_byte_selected = array_init(|idx| {
            IsEqualGadget::construct(cb, index.cells[0].expr(), idx.expr())
        });

        // We need to find the byte we have to get the sign from so we can extend correctly.
        // We go byte by byte and check if `idx == index[0]`.
        // If they are equal (at most once) we add the byte value to the sum, else we add 0.
        // We also generate the selectors, which we'll use to decide if we need to
        // replace bytes with the sign byte.
        // There is no need to check the MSB, even if the MSB is selected no bytes need to be changed.
        let mut selected_byte = 0.expr();
        for idx in 0..31 {
            // Check if this byte is selected
            // The additional condition for this is that none of the non-LSB bytes are non-zero (see above).
            let is_selected = and::expr(vec![
                is_byte_selected[idx].expr(),
                is_msb_sum_zero.expr(),
            ]);

            // Add the byte to the sum when this byte is selected
            selected_byte =
                selected_byte + (is_selected.clone() * value.cells[idx].expr());

            // Verify the selector.
            // Cells are used here to store intermediate results, otherwise these sums
            // are very long expressions.
            // The selector for a byte position is enabled when its value needs to change to the sign byte.
            // Once a byte was selected, all following bytes need to be replaced as well,
            // so a selector is the sum of the current and all previous `is_selected` values.
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
        // This will use the most significant bit of the selected byte to return the sign byte,
        // which is a byte with all its bits set to the sign of the selected byte.
        cb.add_lookup(Lookup::Fixed {
            tag: FixedTableTag::SignByte.expr(),
            values: [selected_byte, sign_byte.expr(), 0.expr()],
        });

        // Verify the result.
        // The LSB always remains the same, all other bytes with their selector enabled
        // need to be changed to the sign byte.
        // When a byte was selected all the **following** bytes need to be replaced
        // (hence the `selectors[idx - 1]`).
        let result = Word::random_linear_combine_expr(
            array_init(|idx| {
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
            cb.randomness(),
        );

        // Pop the byte index and the value from the stack, push the result on the stack
        cb.stack_pop(index.expr());
        cb.stack_pop(value.expr());
        cb.stack_push(result);

        // State transitions
        let state_transition = StateTransition {
            rw_counter: Delta(cb.rw_counter_offset().expr()),
            program_counter: Delta(cb.program_counter_offset().expr()),
            stack_pointer: Delta(cb.stack_pointer_offset().expr()),
            gas_left: Delta(-GasCost::FAST.expr()),
            ..Default::default()
        };
        cb.require_state_transition(state_transition);

        Self {
            opcode,
            sufficient_gas_left,
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
        region: &mut Region<'_, F>,
        offset: usize,
        exec_trace: &ExecTrace<F>,
        step_idx: usize,
    ) -> Result<(), Error> {
        let step = &exec_trace.steps[step_idx];

        let opcode = step.opcode.unwrap();
        self.opcode.assign(
            region,
            offset,
            Some(F::from_u64(opcode.as_u64())),
        )?;

        self.sufficient_gas_left.assign(
            region,
            offset,
            F::from_u64((step.gas_left - step.gas_cost) as u64),
        )?;

        // Inputs/Outputs
        let index = exec_trace.rws[step.rw_indices[0]]
            .stack_value()
            .to_le_bytes();
        let value = exec_trace.rws[step.rw_indices[1]]
            .stack_value()
            .to_le_bytes();
        self.index.assign(region, offset, Some(index))?;
        self.value.assign(region, offset, Some(value))?;

        // Generate the selectors
        let msb_sum_zero = self.is_msb_sum_zero.assign(
            region,
            offset,
            sum::value(&index[1..32]),
        )?;
        let mut previous_selector_value: F = 0.into();
        for i in 0..31 {
            let selected = and::value(vec![
                self.is_byte_selected[i].assign(
                    region,
                    offset,
                    F::from_u64(index[0] as u64),
                    F::from_u64(i as u64),
                )?,
                msb_sum_zero,
            ]);
            let selector_value = selected + previous_selector_value;
            self.selectors[i]
                .assign(region, offset, Some(selector_value))
                .unwrap();
            previous_selector_value = selector_value;
        }

        // Set the sign byte
        let mut sign = 0u64;
        if index[0] < 31 && msb_sum_zero == F::one() {
            sign = (value[index[0] as usize] >> 7) as u64;
        }
        self.sign_byte
            .assign(region, offset, Some(F::from_u64(sign * 0xFF)))
            .unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::bus_mapping_tmp::{Bytecode, Call, ExecStep, ExecTrace, Rw},
        step::ExecutionResult,
        test::{rand_word, try_test_circuit},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok(index: Word, value: Word, result: Word) {
        let randomness = Base::rand();
        let bytecode = Bytecode::new(
            [
                vec![0x7f],
                value.to_be_bytes().to_vec(),
                vec![0x7f],
                index.to_be_bytes().to_vec(),
                vec![OpcodeId::SIGNEXTEND.as_u8(), 0x00],
            ]
            .concat(),
        );
        let exec_trace = ExecTrace {
            randomness,
            steps: vec![
                ExecStep {
                    rw_indices: vec![0, 1, 2],
                    execution_result: ExecutionResult::SIGNEXTEND,
                    rw_counter: 1,
                    program_counter: 66,
                    stack_pointer: 1022,
                    gas_left: 5,
                    gas_cost: 5,
                    opcode: Some(OpcodeId::SIGNEXTEND),
                    ..Default::default()
                },
                ExecStep {
                    execution_result: ExecutionResult::STOP,
                    rw_counter: 4,
                    program_counter: 67,
                    stack_pointer: 1023,
                    gas_left: 0,
                    opcode: Some(OpcodeId::STOP),
                    ..Default::default()
                },
            ],
            txs: vec![],
            calls: vec![Call {
                id: 1,
                is_root: false,
                is_create: false,
                opcode_source: RandomLinearCombination::random_linear_combine(
                    bytecode.hash.to_le_bytes(),
                    randomness,
                ),
            }],
            rws: vec![
                Rw::Stack {
                    rw_counter: 1,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1022,
                    value: index,
                },
                Rw::Stack {
                    rw_counter: 2,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1023,
                    value,
                },
                Rw::Stack {
                    rw_counter: 3,
                    is_write: true,
                    call_id: 1,
                    stack_pointer: 1023,
                    value: result,
                },
            ],
            bytecodes: vec![bytecode],
        };
        try_test_circuit(exec_trace, Ok(()));
    }

    #[test]
    fn signextend_gadget_simple() {
        // Extend byte 2 (negative)
        test_ok(
            2.into(),
            0xF00201.into(),
            Word::from_little_endian(&[
                0x01, 0x02, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF,
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
            if index < 32.into() {
                let index = index.to_le_bytes()[0] as usize;
                let mask = (Word::one() << (index * 8 + 7)) - 1;
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
        test_ok(index % 32, value, signextend(index % 32, value));
    }

    #[test]
    #[ignore]
    fn signextend_gadget_exhaustive() {
        let pos_value: [u8; 32] = [0b01111111u8; 32];
        let neg_value: [u8; 32] = [0b10000000u8; 32];

        let pos_extend = 0u8;
        let neg_extend = 0xFFu8;

        for (value, byte_extend) in
            vec![(pos_value, pos_extend), (neg_value, neg_extend)].iter()
        {
            for idx in 0..33 {
                test_ok(
                    (idx as u64).into(),
                    Word::from_little_endian(value),
                    Word::from_little_endian(
                        &(0..32)
                            .map(
                                |i| {
                                    if i > idx {
                                        *byte_extend
                                    } else {
                                        value[i]
                                    }
                                },
                            )
                            .collect::<Vec<u8>>(),
                    ),
                );
            }
        }
    }
}
