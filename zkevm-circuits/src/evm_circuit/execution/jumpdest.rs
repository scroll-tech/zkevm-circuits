use crate::{
    evm_circuit::{
        execution::{bus_mapping_tmp::ExecTrace, ExecutionGadget},
        step::ExecutionResult,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
        },
    },
    util::Expr,
};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone)]
pub(crate) struct JumpdestGadget<F> {
    same_context: SameContextGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for JumpdestGadget<F> {
    const NAME: &'static str = "JUMPDEST";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::JUMPDEST;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // State transition
        let state_transition = StateTransition {
            program_counter: Delta(1.expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

        Self { same_context }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        exec_trace: &ExecTrace<F>,
        step_idx: usize,
    ) -> Result<(), Error> {
        self.same_context
            .assign_exec_step(region, offset, exec_trace, step_idx)
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
        let bytecode =
            Bytecode::new(vec![opcode.as_u8(), OpcodeId::STOP.as_u8()]);
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
