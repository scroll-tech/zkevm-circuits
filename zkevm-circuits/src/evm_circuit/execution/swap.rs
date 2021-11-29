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
pub(crate) struct SwapGadget<F> {
    opcode: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, 8>,
    values: [Cell<F>; 2],
}

impl<F: FieldExt> ExecutionGadget<F> for SwapGadget<F> {
    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::SWAP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr());

        let sufficient_gas_left =
            cb.require_sufficient_gas_left(GasCost::FASTEST.expr());

        let values = [cb.query_cell(), cb.query_cell()];

        // The stack index we have to peek, deduced from the 'x' value of 'swapx'
        // The offset starts at 1 for SWAP1
        let swap_offset = opcode.expr() - (OpcodeId::SWAP1.as_u64() - 1).expr();

        // Peek the value at `swap_offset`
        cb.stack_lookup(false.expr(), swap_offset.clone(), values[0].expr());
        // Peek the value at the top of the stack
        cb.stack_lookup(false.expr(), 0.expr(), values[1].expr());
        // Write the value previously at the top of the stack to `swap_offset`
        cb.stack_lookup(true.expr(), swap_offset, values[1].expr());
        // Write the value previously at `swap_offset` to the top of the stack
        cb.stack_lookup(true.expr(), 0.expr(), values[0].expr());

        // State transitions
        let state_transition = StateTransition {
            rw_counter: Delta(cb.rw_counter_offset().expr()),
            program_counter: Delta(cb.program_counter_offset().expr()),
            gas_left: Delta(-GasCost::FASTEST.expr()),
            ..Default::default()
        };
        cb.require_state_transition(state_transition);

        Self {
            opcode,
            sufficient_gas_left,
            values,
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

        for (cell, value) in self.values.iter().zip(
            [step.rw_indices[0], step.rw_indices[1]]
                .map(|idx| exec_trace.rws[idx].stack_value())
                .iter(),
        ) {
            cell.assign(
                region,
                offset,
                Some(Word::random_linear_combine(
                    value.to_le_bytes(),
                    exec_trace.randomness,
                )),
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
        test::{rand_word, try_test_circuit},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok(opcode: OpcodeId, lhs: Word, rhs: Word) {
        let n = (opcode.as_u8() - OpcodeId::SWAP1.as_u8() + 1) as usize;
        let randomness = Base::rand();
        let bytecode = Bytecode::new(
            [
                vec![0x7f],
                lhs.to_be_bytes().to_vec(),
                vec![OpcodeId::DUP1.as_u8(); n - 1],
                vec![0x7f],
                rhs.to_be_bytes().to_vec(),
                vec![opcode.as_u8(), 0x00],
            ]
            .concat(),
        );
        let exec_trace = ExecTrace {
            randomness,
            steps: vec![
                ExecStep {
                    rw_indices: vec![0, 1],
                    execution_result: ExecutionResult::SWAP,
                    rw_counter: 1,
                    program_counter: (65 + n) as u64,
                    stack_pointer: 1024 - n - 1,
                    gas_left: 3,
                    gas_cost: 3,
                    opcode: Some(opcode),
                    ..Default::default()
                },
                ExecStep {
                    execution_result: ExecutionResult::STOP,
                    rw_counter: 5,
                    program_counter: (66 + n) as u64,
                    stack_pointer: 1024 - n - 1,
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
                    value: lhs,
                },
                Rw::Stack {
                    counter: 2,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1023 - n,
                    value: rhs,
                },
                Rw::Stack {
                    counter: 3,
                    is_write: true,
                    call_id: 1,
                    stack_pointer: 1023,
                    value: rhs,
                },
                Rw::Stack {
                    counter: 4,
                    is_write: true,
                    call_id: 1,
                    stack_pointer: 1023 - n,
                    value: lhs,
                },
            ],
            bytecodes: vec![bytecode],
        };
        try_test_circuit(exec_trace, Ok(()));
    }

    #[test]
    fn swap_gadget_simple() {
        test_ok(OpcodeId::SWAP1, Word::from(0x030201), Word::from(0x040506));
        test_ok(OpcodeId::SWAP2, Word::from(0x030201), Word::from(0x040506));
        test_ok(OpcodeId::SWAP15, Word::from(0x030201), Word::from(0x040506));
        test_ok(OpcodeId::SWAP16, Word::from(0x030201), Word::from(0x040506));
    }

    #[test]
    #[ignore]
    fn swap_gadget_rand() {
        for opcode in vec![
            OpcodeId::SWAP1,
            OpcodeId::SWAP2,
            OpcodeId::SWAP3,
            OpcodeId::SWAP4,
            OpcodeId::SWAP5,
            OpcodeId::SWAP6,
            OpcodeId::SWAP7,
            OpcodeId::SWAP8,
            OpcodeId::SWAP9,
            OpcodeId::SWAP10,
            OpcodeId::SWAP11,
            OpcodeId::SWAP12,
            OpcodeId::SWAP13,
            OpcodeId::SWAP14,
            OpcodeId::SWAP15,
            OpcodeId::SWAP16,
        ]
        .into_iter()
        {
            test_ok(opcode, rand_word(), rand_word());
        }
    }
}
