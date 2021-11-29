use crate::{
    evm_circuit::{
        execution::{bus_mapping_tmp::ExecTrace, ExecutionGadget},
        step::ExecutionResult,
        util::{
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            from_bytes,
            math_gadget::RangeCheckGadget,
            Cell, RandomLinearCombination,
        },
    },
    util::Expr,
};
use array_init::array_init;
use bus_mapping::evm::GasCost;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone)]
pub(crate) struct PcGadget<F> {
    opcode: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, 8>,
    value: RandomLinearCombination<F, 8>,
}

impl<F: FieldExt> ExecutionGadget<F> for PcGadget<F> {
    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::PC;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr());

        let sufficient_gas_left =
            cb.require_sufficient_gas_left(GasCost::QUICK.expr());

        // program_counter is limited to 64 bits so we only consider 8 bytes
        let bytes = array_init(|_| cb.query_cell());
        cb.require_equal(
            from_bytes::expr(bytes.to_vec()),
            cb.curr.state.program_counter.expr(),
        );

        // Push the value on the stack
        let value = RandomLinearCombination::new(bytes, cb.randomness());
        cb.stack_push(value.expr());

        // State transitions
        // `program_counter` needs to be increased by number of bytes pushed + 1
        let state_transition = StateTransition {
            rw_counter: Delta(cb.rw_counter_offset().expr()),
            program_counter: Delta(cb.program_counter_offset().expr()),
            stack_pointer: Delta(cb.stack_pointer_offset().expr()),
            gas_left: Delta(-GasCost::QUICK.expr()),
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

        self.sufficient_gas_left.assign(
            region,
            offset,
            F::from_u64((step.gas_left - step.gas_cost) as u64),
        )?;

        self.value.assign(
            region,
            offset,
            Some(step.program_counter.to_le_bytes()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::bus_mapping_tmp::{Bytecode, Call, ExecStep, ExecTrace, Rw},
        step::ExecutionResult,
        test::try_test_circuit,
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok() {
        let opcode = OpcodeId::PC;
        let randomness = Base::rand();
        let bytecode = Bytecode::new(
            [
                vec![OpcodeId::PUSH32.as_u8()],
                vec![0; 32],
                vec![opcode.as_u8(), 0x00],
            ]
            .concat(),
        );
        let exec_trace = ExecTrace {
            randomness,
            steps: vec![
                ExecStep {
                    rw_indices: vec![0],
                    execution_result: ExecutionResult::PC,
                    rw_counter: 1,
                    program_counter: 33,
                    stack_pointer: 1023,
                    gas_left: 3,
                    gas_cost: 2,
                    opcode: Some(opcode),
                    ..Default::default()
                },
                ExecStep {
                    execution_result: ExecutionResult::STOP,
                    rw_counter: 2,
                    program_counter: 34,
                    stack_pointer: 1022,
                    gas_left: 1,
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
                counter: 1,
                is_write: true,
                call_id: 1,
                stack_pointer: 1022,
                value: Word::from(33),
            }],
            bytecodes: vec![bytecode],
        };
        try_test_circuit(exec_trace, Ok(()));
    }

    #[test]
    fn pc_gadget_simple() {
        test_ok();
    }
}
