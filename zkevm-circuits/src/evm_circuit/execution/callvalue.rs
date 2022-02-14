use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::CallContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct CallvalueGadget<F> {
    same_context: SameContextGadget<F>,
    call_value: Word<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for CallvalueGadget<F> {
    const NAME: &'static str = "CALLVALUE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLVALUE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let call_value = cb.query_rlc();

        cb.call_context_lookup(None, CallContextFieldTag::Value, call_value.expr());
        cb.stack_push(call_value.expr());

        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition, None);

        Self {
            same_context,
            call_value,
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

        let call_value = block.rws[step.rw_indices[1]].stack_value();
        self.call_value
            .assign(region, offset, Some(call_value.to_le_bytes()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        step::ExecutionState,
        table::CallContextFieldTag,
        test::run_test_circuit_incomplete_fixed_table,
        util::RandomLinearCombination,
        witness::{Block, Bytecode, Call, ExecStep, Rw, Transaction},
    };
    use bus_mapping::evm::OpcodeId;
    use eth_types::{bytecode, ToLittleEndian, Word, U256};
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr;

    #[test]
    fn callvalue_gadget_test() {
        let bytecode = Bytecode::new(
            bytecode! {
                #[start]
                CALLVALUE
                STOP
            }
            .to_vec(),
        );

        let call_value = 888999046u64;

        let tx_id = 1;
        let call_id = 1;

        let call_value_gas_cost = OpcodeId::CALLVALUE.constant_gas_cost().as_u64();

        let randomness = Fr::rand();
        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: tx_id,
                steps: vec![
                    ExecStep {
                        execution_state: ExecutionState::CALLVALUE,
                        rw_indices: vec![0, 1],
                        rw_counter: 1,
                        program_counter: 0,
                        stack_pointer: 1024,
                        gas_left: call_value_gas_cost,
                        gas_cost: call_value_gas_cost,
                        opcode: Some(OpcodeId::CALLVALUE),
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::STOP,
                        rw_counter: 3,
                        program_counter: 1,
                        stack_pointer: 1023,
                        opcode: Some(OpcodeId::STOP),
                        ..Default::default()
                    },
                ],
                calls: vec![Call {
                    id: 1,
                    is_root: true,
                    is_create: false,
                    opcode_source: RandomLinearCombination::random_linear_combine(
                        bytecode.hash.to_le_bytes(),
                        randomness,
                    ),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            rws: vec![
                Rw::CallContext {
                    call_id,
                    rw_counter: 1,
                    is_write: false,
                    field_tag: CallContextFieldTag::Value,
                    value: U256::from(call_value),
                },
                Rw::Stack {
                    call_id,
                    rw_counter: 2,
                    is_write: true,
                    stack_pointer: 1023,
                    value: Word::from(call_value),
                },
            ],
            bytecodes: vec![bytecode],
            ..Default::default()
        };

        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }
}
