use crate::{
    evm_circuit::{
        execution::{bus_mapping_tmp::ExecTrace, ExecutionGadget},
        step::ExecutionResult,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            sum, Cell, Word,
        },
    },
    util::Expr,
};
use array_init::array_init;
use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone)]
pub(crate) struct PushGadget<F> {
    same_context: SameContextGadget<F>,
    value: Word<F>,
    selectors: [Cell<F>; 31],
}

impl<F: FieldExt> ExecutionGadget<F> for PushGadget<F> {
    const NAME: &'static str = "PUSH";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::PUSH;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Query selectors for each opcode_lookup
        let selectors = array_init(|_| cb.query_bool());

        // Lookup opcode from the LSB to MSB
        let bytes = array_init(|idx| {
            let index = cb.curr.state.program_counter.expr() + opcode.expr()
                - (OpcodeId::PUSH1.as_u8() - 1 + idx as u8).expr();
            let byte = cb.query_cell();
            if idx == 0 {
                cb.opcode_lookup_at(index, byte.expr())
            } else {
                cb.condition(selectors[idx - 1].expr(), |cb| {
                    cb.opcode_lookup_at(index, byte.expr())
                });
            }
            byte
        });

        for idx in 0..31 {
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
                bytes[idx + 1].expr() * (1.expr() - selectors[idx].expr()),
            );
        }

        // Deduce the number of additional bytes to push than PUSH1
        let num_additional_pushed =
            opcode.expr() - OpcodeId::PUSH1.as_u64().expr();
        // Sum of selectors needs to be exactly the number of additional bytes
        // that needs to be pushed.
        cb.require_equal(
            "Constrain sum of selectors equal to num_additional_pushed",
            sum::expr(&selectors),
            num_additional_pushed,
        );

        // Push the value on the stack
        let value = Word::new(bytes, cb.randomness());
        cb.stack_push(value.expr());

        // State transition
        // `program_counter` needs to be increased by number of bytes pushed + 1
        let state_transition = StateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(
                opcode.expr() - (OpcodeId::PUSH1.as_u64() - 2).expr(),
            ),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

        Self {
            same_context,
            value,
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

        self.same_context
            .assign_exec_step(region, offset, exec_trace, step_idx)?;

        let opcode = step.opcode.unwrap();

        let value = exec_trace.rws[step.rw_indices[0]].stack_value();
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        let num_additional_pushed =
            (opcode.as_u8() - OpcodeId::PUSH1.as_u8()) as usize;
        for (idx, selector) in self.selectors.iter().enumerate() {
            selector.assign(
                region,
                offset,
                Some(F::from_u64((idx < num_additional_pushed) as u64)),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::bus_mapping_tmp::{Bytecode, Call, ExecStep, ExecTrace, Rw},
        step::ExecutionResult,
        test::{rand_bytes, try_test_circuit},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok(opcode: OpcodeId, bytes: &[u8]) {
        assert!(
            bytes.len() as u8 == opcode.as_u8() - OpcodeId::PUSH1.as_u8() + 1,
        );

        let randomness = Base::rand();
        let bytecode = Bytecode::new(
            [
                vec![opcode.as_u8()],
                bytes.to_vec(),
                vec![OpcodeId::STOP.as_u8()],
            ]
            .concat(),
        );
        let exec_trace = ExecTrace {
            randomness,
            steps: vec![
                ExecStep {
                    rw_indices: vec![0],
                    execution_result: ExecutionResult::PUSH,
                    rw_counter: 1,
                    program_counter: 0,
                    stack_pointer: 1024,
                    gas_left: 3,
                    gas_cost: 3,
                    opcode: Some(opcode),
                    ..Default::default()
                },
                ExecStep {
                    execution_result: ExecutionResult::STOP,
                    rw_counter: 2,
                    program_counter: (bytes.len() + 1) as u64,
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
            rws: vec![Rw::Stack {
                rw_counter: 1,
                is_write: true,
                call_id: 1,
                stack_pointer: 1023,
                value: Word::from_big_endian(bytes),
            }],
            bytecodes: vec![bytecode],
        };
        try_test_circuit(exec_trace, Ok(()));
    }

    #[test]
    fn push_gadget_simple() {
        test_ok(OpcodeId::PUSH1, &[1]);
        test_ok(OpcodeId::PUSH2, &[1, 2]);
        test_ok(
            OpcodeId::PUSH31,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
        );
        test_ok(
            OpcodeId::PUSH32,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );
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
