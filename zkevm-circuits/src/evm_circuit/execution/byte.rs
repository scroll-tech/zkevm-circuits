use crate::{
    evm_circuit::{
        execution::{
            bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
            ExecutionGadget,
        },
        step::ExecutionResult,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            math_gadget::{IsEqualGadget, IsZeroGadget},
            sum, Word,
        },
    },
    util::Expr,
};
use array_init::array_init;
use bus_mapping::eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ByteGadget<F> {
    same_context: SameContextGadget<F>,
    index: Word<F>,
    value: Word<F>,
    is_msb_sum_zero: IsZeroGadget<F>,
    is_byte_selected: [IsEqualGadget<F>; 32],
}

impl<F: FieldExt> ExecutionGadget<F> for ByteGadget<F> {
    const NAME: &'static str = "BYTE";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::BYTE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let index = cb.query_word();
        let value = cb.query_word();

        // If any of the non-LSB bytes of the index word are non-zero we never
        // need to copy any bytes. So just sum all the non-LSB byte
        // values here and then check if it's non-zero so we can use
        // that as an additional condition when to copy the byte value.
        let is_msb_sum_zero =
            IsZeroGadget::construct(cb, sum::expr(&index.cells[1..32]));

        // Now we just need to check that `result[0]` is the sum of all copied
        // bytes. We go byte by byte and check if `idx == index[0]`.
        // If they are equal (at most once) we add the byte value to the sum,
        // else we add 0. The additional condition for this is that none
        // of the non-LSB bytes are non-zero (see above). At the end
        // this sum needs to equal `result[0]`.
        let is_byte_selected = array_init(|idx| {
            // Check if this byte is selected looking only at the LSB of the
            // index word
            IsEqualGadget::construct(
                cb,
                index.cells[0].expr(),
                (31 - idx).expr(),
            )
        });

        // Sum all possible selected bytes
        let selected_byte = value
            .cells
            .iter()
            .zip(is_byte_selected.iter())
            .fold(0.expr(), |acc, (cell, is_selected)| {
                acc + is_selected.expr() * is_msb_sum_zero.expr() * cell.expr()
            });

        // Pop the byte index and the value from the stack,
        // push the selected byte on the stack
        // We can push the selected byte here directly because
        // it only uses the LSB of a word.
        cb.stack_pop(index.expr());
        cb.stack_pop(value.expr());
        cb.stack_push(selected_byte);

        // State transition
        let state_transition = StateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

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
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // Inputs/Outputs
        let index = block.rws[step.rw_indices[0]].stack_value().to_le_bytes();
        let value = block.rws[step.rw_indices[1]].stack_value().to_le_bytes();
        self.index.assign(region, offset, Some(index))?;
        self.value.assign(region, offset, Some(value))?;

        // Set `is_msb_sum_zero`
        self.is_msb_sum_zero.assign(
            region,
            offset,
            sum::value(&index[1..32]),
        )?;

        // Set `is_byte_selected`
        for i in 0..32 {
            self.is_byte_selected[i].assign(
                region,
                offset,
                F::from_u64(index[0] as u64),
                F::from_u64((31 - i) as u64),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::bus_mapping_tmp::{
            Block, Bytecode, Call, ExecStep, Rw, Transaction,
        },
        step::ExecutionResult,
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok(index: Word, value: Word, byte: Word) {
        let randomness = Base::rand();
        let bytecode = Bytecode::new(
            [
                vec![OpcodeId::PUSH32.as_u8()],
                value.to_be_bytes().to_vec(),
                vec![OpcodeId::PUSH32.as_u8()],
                index.to_be_bytes().to_vec(),
                vec![OpcodeId::BYTE.as_u8(), OpcodeId::STOP.as_u8()],
            ]
            .concat(),
        );
        let block = Block {
            randomness,
            txs: vec![Transaction {
                calls: vec![Call {
                    id: 1,
                    is_root: false,
                    is_create: false,
                    opcode_source:
                        RandomLinearCombination::random_linear_combine(
                            bytecode.hash.to_le_bytes(),
                            randomness,
                        ),
                }],
                steps: vec![
                    ExecStep {
                        rw_indices: vec![0, 1, 2],
                        execution_result: ExecutionResult::BYTE,
                        rw_counter: 1,
                        program_counter: 66,
                        stack_pointer: 1022,
                        gas_left: 3,
                        gas_cost: 3,
                        opcode: Some(OpcodeId::BYTE),
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
                ..Default::default()
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
                    value: byte,
                },
            ],
            bytecodes: vec![bytecode],
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn byte_gadget_simple() {
        // Select byte 29 (MSB is at 0)
        test_ok(29.into(), 0x030201.into(), 0x03.into());
        // Select byte 256
        test_ok(256.into(), 0x030201.into(), 0.into());
    }

    #[test]
    fn byte_gadget_rand() {
        let byte = |index: Word, value: Word| -> Word {
            if index < 32.into() {
                value.to_be_bytes()[index.to_le_bytes()[0] as usize].into()
            } else {
                Word::zero()
            }
        };

        let index = rand_word();
        let value = rand_word();
        test_ok(index, value, byte(index, value));
        test_ok(index % 32, value, byte(index % 32, value));
    }

    #[test]
    #[ignore]
    fn byte_gadget_exhaustive() {
        let value = Word::from_big_endian(&(1..33).collect::<Vec<_>>()[..]);
        for idx in 0..33 {
            test_ok(
                idx.into(),
                value,
                (if idx < 32 { idx + 1 } else { 0 }).into(),
            );
        }
    }
}
