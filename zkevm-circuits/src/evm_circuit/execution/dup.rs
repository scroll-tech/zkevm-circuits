use crate::{
    evm_circuit::{
        execution::{bus_mapping_tmp::ExecTrace, ExecutionGadget},
        step::ExecutionResult,
        util::{
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            math_gadget::RangeCheckGadget,
            Cell, Word,
        },
    },
    util::Expr,
};
use bus_mapping::{
    eth_types::ToLittleEndian,
    evm::{GasCost, OpcodeId},
};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone)]
pub(crate) struct DupGadget<F> {
    opcode: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, 8>,
    value: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for DupGadget<F> {
    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::DUP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr());

        let sufficient_gas_left =
            cb.require_sufficient_gas_left(GasCost::FASTEST.expr());

        let value = cb.query_cell();

        // The stack index we have to peek, deduced from the 'x' value of 'dupx'
        // The offset starts at 0 for DUP1
        let dup_offset = opcode.expr() - OpcodeId::DUP1.expr();

        // Peek the value at `dup_offset` and push the value on the stack
        cb.stack_lookup(false.expr(), dup_offset, value.expr());
        cb.stack_push(value.expr());

        // State transitions
        let state_transition = StateTransition {
            rw_counter: Delta(cb.rw_counter_offset().expr()),
            program_counter: Delta(cb.program_counter_offset().expr()),
            stack_pointer: Delta(cb.stack_pointer_offset().expr()),
            gas_left: Delta(-GasCost::FASTEST.expr()),
            ..Default::default()
        };
        cb.require_state_transition(state_transition);

        Self {
            opcode,
            sufficient_gas_left,
            value,
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

        let value = exec_trace.rws[step.rw_indices[0]].stack_value();
        self.value.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                value.to_le_bytes(),
                exec_trace.randomness,
            )),
        )?;

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

    fn test_ok(opcode: OpcodeId, value: Word) {
        let n = (opcode.as_u8() - OpcodeId::DUP1.as_u8() + 1) as usize;
        let randomness = Base::rand();
        let bytecode = Bytecode::new(
            [
                vec![0x7f],
                value.to_be_bytes().to_vec(),
                vec![OpcodeId::DUP1.as_u8(); n - 1],
                vec![opcode.as_u8(), 0x00],
            ]
            .concat(),
        );
        let exec_trace = ExecTrace {
            randomness,
            steps: vec![
                ExecStep {
                    rw_indices: vec![0, 1],
                    execution_result: ExecutionResult::DUP,
                    rw_counter: 1,
                    program_counter: (33 + n - 1) as u64,
                    stack_pointer: 1024 - n,
                    gas_left: 3,
                    gas_cost: 3,
                    opcode: Some(opcode),
                    ..Default::default()
                },
                ExecStep {
                    execution_result: ExecutionResult::STOP,
                    rw_counter: 3,
                    program_counter: (33 + n) as u64,
                    stack_pointer: 1023 - n,
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
                    counter: 1,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1023,
                    value,
                },
                Rw::Stack {
                    counter: 2,
                    is_write: true,
                    call_id: 1,
                    stack_pointer: 1023 - n,
                    value,
                },
            ],
            bytecodes: vec![bytecode],
        };
        try_test_circuit(exec_trace, Ok(()));
    }

    #[test]
    fn dup_gadget_simple() {
        test_ok(OpcodeId::DUP1, Word::max_value());
        test_ok(OpcodeId::DUP2, Word::max_value());
        test_ok(OpcodeId::DUP15, Word::max_value());
        test_ok(OpcodeId::DUP16, Word::max_value());
    }

    #[test]
    #[ignore]
    fn dup_gadget_rand() {
        for opcode in vec![
            OpcodeId::DUP1,
            OpcodeId::DUP2,
            OpcodeId::DUP3,
            OpcodeId::DUP4,
            OpcodeId::DUP5,
            OpcodeId::DUP6,
            OpcodeId::DUP7,
            OpcodeId::DUP8,
            OpcodeId::DUP9,
            OpcodeId::DUP10,
            OpcodeId::DUP11,
            OpcodeId::DUP12,
            OpcodeId::DUP13,
            OpcodeId::DUP14,
            OpcodeId::DUP15,
            OpcodeId::DUP16,
        ]
        .into_iter()
        {
            test_ok(opcode, rand_word());
        }
    }
}
