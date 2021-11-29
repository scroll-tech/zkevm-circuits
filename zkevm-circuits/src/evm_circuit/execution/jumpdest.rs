use crate::{
    evm_circuit::{
        execution::{bus_mapping_tmp::ExecTrace, ExecutionGadget},
        step::ExecutionResult,
        util::{
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            math_gadget::RangeCheckGadget,
            Cell,
        },
    },
    util::Expr,
};
use bus_mapping::evm::GasCost;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone)]
pub(crate) struct JumpdestGadget<F> {
    opcode: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, 8>,
}

impl<F: FieldExt> ExecutionGadget<F> for JumpdestGadget<F> {
    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::JUMPDEST;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr());

        let sufficient_gas_left =
            cb.require_sufficient_gas_left(GasCost::ONE.expr());

        // State transitions
        let state_transition = StateTransition {
            program_counter: Delta(cb.program_counter_offset().expr()),
            gas_left: Delta(-GasCost::ONE.expr()),
            ..Default::default()
        };
        cb.require_state_transition(state_transition);

        Self {
            opcode,
            sufficient_gas_left,
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

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::bus_mapping_tmp::{Bytecode, Call, ExecStep, ExecTrace},
        step::ExecutionResult,
        test::try_test_circuit,
        util::RandomLinearCombination,
    };
    use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok() {
        let opcode = OpcodeId::JUMPDEST;
        let randomness = Base::rand();
        let bytecode = Bytecode::new(vec![opcode.as_u8(), 0x00]);
        let exec_trace = ExecTrace {
            randomness,
            steps: vec![
                ExecStep {
                    rw_indices: vec![],
                    execution_result: ExecutionResult::JUMPDEST,
                    rw_counter: 1,
                    program_counter: 0,
                    stack_pointer: 1024,
                    gas_left: 3,
                    gas_cost: 1,
                    opcode: Some(opcode),
                    ..Default::default()
                },
                ExecStep {
                    execution_result: ExecutionResult::STOP,
                    rw_counter: 1,
                    program_counter: 1,
                    stack_pointer: 1024,
                    gas_left: 2,
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
            rws: vec![],
            bytecodes: vec![bytecode],
        };
        try_test_circuit(exec_trace, Ok(()));
    }

    #[test]
    fn jumpdest_gadget_simple() {
        test_ok();
    }
}
