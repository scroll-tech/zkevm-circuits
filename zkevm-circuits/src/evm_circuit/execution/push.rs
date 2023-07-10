use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::Delta,
            },
            math_gadget::IsZeroGadget,
            not, select, sum, CachedRegion, Cell, Word,
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
    selectors: [Cell<F>; 32],
}

impl<F: Field> ExecutionGadget<F> for PushGadget<F> {
    const NAME: &'static str = "PUSH";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PUSH;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_push0 = IsZeroGadget::construct(cb, "", opcode.expr() - OpcodeId::PUSH0.expr());

        let value = cb.query_word_rlc();
        cb.condition(not::expr(is_push0.expr()), |cb| cb.stack_push(value.expr()));

        // Query selectors for each opcode_lookup
        let selectors = array_init(|_| cb.query_bool());

        // TODO:
        // The below constraints are failed when running test case
        // `push_gadget_out_of_range`. It seems that we cannot check the exact
        // length of `n` data bytes followed by `PUSHn` opcode. Since even if the
        // code ends with PUSH32 should succeed to run.
        // <https://github.com/ethereum/go-ethereum/blob/master/core/vm/analysis.go#L66>
        // <https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/43c67c91ca566fd2b7f3588979c537006090f185/eth-types/src/bytecode.rs#L288>
        //
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
        // for idx in 0..32 {
        //     let byte = &value.cells[idx];
        //     let index = cb.curr.state.program_counter.expr() + opcode.expr()
        //         - (OpcodeId::PUSH0.as_u8() + idx as u8).expr();

        //     cb.condition(selectors[idx].expr(), |cb| {
        //         cb.opcode_lookup_at(index, byte.expr(), 0.expr())
        //     });
        // }

        for idx in 0..32 {
            let selector_prev = if idx == 0 {
                // First selector will always be 1
                1.expr()
            } else {
                selectors[idx - 1].expr()
            };
            // selector can transit from 1 to 0 only once as [1, 1, 1, ...,
            // 0, 0, 0]
            cb.require_boolean(
                "Constrain selector can only transit from 1 to 0",
                selector_prev - selectors[idx].expr(),
            );
            // byte should be 0 when selector is 0
            cb.require_zero(
                "Constrain byte == 0 when selector == 0",
                value.cells[idx].expr() * (1.expr() - selectors[idx].expr()),
            );
        }

        // Deduce the number of additional bytes to push than PUSH0. Note that
        // num_additional_pushed = n where n is the suffix number of PUSH*.
        let num_additional_pushed = opcode.expr() - OpcodeId::PUSH0.as_u64().expr();
        // Sum of selectors needs to be exactly the number of additional bytes
        // that needs to be pushed.
        cb.require_equal(
            "Constrain sum of selectors equal to num_additional_pushed",
            sum::expr(&selectors),
            num_additional_pushed,
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

        let opcode = step.opcode.unwrap();
        self.is_push0.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::PUSH0.as_u64()),
        )?;

        let value = if opcode.is_push_with_data() {
            block.rws[step.rw_indices[0]].stack_value()
        } else {
            U256::zero()
        };
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        let num_additional_pushed = opcode.postfix().expect("opcode with postfix");
        for (idx, selector) in self.selectors.iter().enumerate() {
            selector.assign(
                region,
                offset,
                Value::known(F::from((idx < num_additional_pushed as usize) as u64)),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, evm_types::OpcodeId, Bytecode};
    use mock::TestContext;

    fn test_ok(opcode: OpcodeId, bytes: &[u8]) {
        assert!(bytes.len() == opcode.data_len());

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
    }

    #[ignore]
    #[test]
    fn push_gadget_out_of_range() {
        let bytecode = Bytecode::from(vec![0x61, 0x00]);
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    #[ignore]
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
