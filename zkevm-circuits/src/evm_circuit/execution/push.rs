use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_PROGRAM_COUNTER,
        step::ExecutionState,
        util::{
            and,
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::Delta,
            },
            math_gadget::{IsZeroGadget, LtGadget},
            not, or, select, sum, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use array_init::array_init;
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian, U256};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct PushGadget<F> {
    same_context: SameContextGadget<F>,
    is_push0: IsZeroGadget<F>,
    value: Word<F>,
    is_pushed: [Cell<F>; 32],
    is_padding: [Cell<F>; 32],
    code_length: Cell<F>,
    is_out_of_bound: LtGadget<F, N_BYTES_PROGRAM_COUNTER>,
}

impl<F: Field> ExecutionGadget<F> for PushGadget<F> {
    const NAME: &'static str = "PUSH";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PUSH;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_push0 = IsZeroGadget::construct(cb, "", opcode.expr() - OpcodeId::PUSH0.expr());

        let value = cb.query_word_rlc();
        cb.stack_push(value.expr());

        // Query selectors for each opcode_lookup whether byte in value needs to be pushed
        let is_pushed = array_init(|_| cb.query_bool());
        let is_padding = array_init(|_| cb.query_bool());

        let code_length = cb.query_cell();
        let code_length_left = code_length.expr() - cb.curr.state.program_counter.expr() - 1.expr();
        cb.bytecode_length(cb.curr.state.code_hash.expr(), code_length.expr());

        let num_bytes_needed = opcode.expr() - OpcodeId::PUSH0.expr();
        let is_out_of_bound =
            LtGadget::construct(cb, code_length_left.expr(), num_bytes_needed.expr());
        let num_bytes_padding = select::expr(
            is_out_of_bound.expr(),
            num_bytes_needed.expr() - code_length_left.expr(),
            0.expr(),
        );

        // The pushed bytes are viewed as left-padded big-endian, but our random
        // linear combination uses little-endian, so we lookup from the LSB
        // which has index (program_counter + num_pushed), and then move left
        // (program_counter + num_pushed - idx) to lookup all 32 bytes
        // conditionally by selectors.
        // For PUSH2 as an example, we lookup from byte0, byte1, ..., byte31,
        // where the byte2 is actually the PUSH2 itself, and lookup are only
        // enabled for byte0 and byte1.
        //
        //                    program_counter    program_counter + num_pushed(2)
        //                           ▼                     ▼
        //   [byte31,     ...,     byte2,     byte1,     byte0]
        //
        let mut is_pushed_cell_prev = true.expr();
        let mut is_padding_cell_prev = true.expr();
        for (idx, (is_pushed_cell, is_padding_cell)) in
            is_pushed.iter().zip(is_padding.iter()).enumerate()
        {
            let byte = &value.cells[idx];
            let index =
                cb.curr.state.program_counter.expr() + num_bytes_needed.clone() - idx.expr();

            cb.require_boolean(
                "Constrain is_pushed can only transit from 1 to 0",
                is_pushed_cell_prev - is_pushed_cell.expr(),
            );
            cb.require_boolean(
                "Constrain is_padding can only transit from 1 to 0",
                is_padding_cell_prev - is_padding_cell.expr(),
            );

            // byte is 0 if it is either not pushed or padding
            cb.condition(
                not::expr(or::expr(&[is_pushed_cell.expr(), is_padding_cell.expr()])),
                |cb| {
                    cb.require_zero(
                        "Constrain byte == 0 when is_pushed == 0 or is_padding == 0",
                        byte.expr(),
                    );
                },
            );
            cb.condition(
                and::expr(&[is_pushed_cell.expr(), not::expr(is_padding_cell.expr())]),
                |cb| {
                    cb.opcode_lookup_at(index, byte.expr(), 0.expr());
                },
            );
            is_pushed_cell_prev = is_pushed_cell.expr();
            is_padding_cell_prev = is_padding_cell.expr();
        }

        // Sum of selectors is_pushed needs to be exactly the number of bytes
        // that needs to be pushed
        cb.require_equal(
            "Constrain sum of is_pushed equal to num_bytes_needed",
            sum::expr(&is_pushed),
            num_bytes_needed.expr(),
        );

        // Sum of selectors is_padding needs to be exactly the number of padded bytes
        cb.require_equal(
            "Constrain sum of is_padding equal to num_padding",
            sum::expr(&is_padding),
            num_bytes_padding.expr(),
        );

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(opcode.expr() - (OpcodeId::PUSH0.as_u64() - 1).expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(select::expr(
                is_push0.expr(),
                -OpcodeId::PUSH0.constant_gas_cost().expr(),
                -OpcodeId::PUSH1.constant_gas_cost().expr(),
            )),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            is_push0,
            value,
            is_pushed,
            is_padding,
            code_length,
            is_out_of_bound,
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
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();
        self.is_push0.assign(
            region,
            offset,
            F::from(opcode.as_u64() - OpcodeId::PUSH0.as_u64()),
        )?;

        let bytecode = block
            .bytecodes
            .get(&call.code_hash)
            .expect("could not find current environment's bytecode");
        let code_length = bytecode.bytes.len() as u64;
        self.code_length
            .assign(region, offset, Value::known(F::from(code_length)))?;

        let value = if opcode.is_push_with_data() {
            block.rws[step.rw_indices[0]].stack_value()
        } else {
            U256::zero()
        };
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        let code_length_left = code_length
            .checked_sub(step.program_counter + 1)
            .expect("unexpected underflow");
        let num_bytes_needed = opcode.postfix().unwrap() as u64;
        let num_padding = num_bytes_needed.saturating_sub(code_length_left);
        self.is_out_of_bound.assign(
            region,
            offset,
            F::from(code_length_left),
            F::from(num_bytes_needed),
        )?;
        for (idx, (is_pushed_cell, is_padding_cell)) in self
            .is_pushed
            .iter()
            .zip(self.is_padding.iter())
            .enumerate()
        {
            is_pushed_cell.assign(
                region,
                offset,
                Value::known(F::from(((idx as u64) < num_bytes_needed) as u64)),
            )?;
            is_padding_cell.assign(
                region,
                offset,
                Value::known(F::from(((idx as u64) < num_padding) as u64)),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, evm_types::OpcodeId};
    use mock::TestContext;

    fn test_ok(opcode: OpcodeId, bytes: &[u8]) {
        let mut bytecode = bytecode! {
            .write_op(opcode)
        };
        for b in bytes {
            bytecode.write(*b, false);
        }
        bytecode.op_stop();

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn push_gadget_simple() {
        #[cfg(feature = "shanghai")]
        test_ok(OpcodeId::PUSH0, &[]);
        test_ok(OpcodeId::PUSH1, &[1]);
        test_ok(OpcodeId::PUSH2, &[1, 2]);
        test_ok(
            OpcodeId::PUSH31,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31,
            ],
        );
        test_ok(
            OpcodeId::PUSH32,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );

        // out of bounds
        test_ok(OpcodeId::PUSH2, &[1]);
        test_ok(OpcodeId::PUSH16, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn push_gadget_rand() {
        for (idx, opcode) in vec![
            OpcodeId::PUSH1,
            OpcodeId::PUSH2,
            OpcodeId::PUSH3,
            OpcodeId::PUSH4,
            OpcodeId::PUSH5,
            OpcodeId::PUSH6,
            OpcodeId::PUSH7,
            OpcodeId::PUSH8,
            OpcodeId::PUSH9,
            OpcodeId::PUSH10,
            OpcodeId::PUSH11,
            OpcodeId::PUSH12,
            OpcodeId::PUSH13,
            OpcodeId::PUSH14,
            OpcodeId::PUSH15,
            OpcodeId::PUSH16,
            OpcodeId::PUSH17,
            OpcodeId::PUSH18,
            OpcodeId::PUSH19,
            OpcodeId::PUSH20,
            OpcodeId::PUSH21,
            OpcodeId::PUSH22,
            OpcodeId::PUSH23,
            OpcodeId::PUSH24,
            OpcodeId::PUSH25,
            OpcodeId::PUSH26,
            OpcodeId::PUSH27,
            OpcodeId::PUSH28,
            OpcodeId::PUSH29,
            OpcodeId::PUSH30,
            OpcodeId::PUSH31,
            OpcodeId::PUSH32,
        ]
        .into_iter()
        .enumerate()
        {
            test_ok(opcode, &rand_bytes(idx + 1));
        }
    }
}
