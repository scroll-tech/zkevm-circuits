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
            from_bytes, RandomLinearCombination,
        },
    },
    util::Expr,
};
use array_init::array_init;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct PcGadget<F> {
    same_context: SameContextGadget<F>,
    value: RandomLinearCombination<F, 8>,
}

impl<F: FieldExt> ExecutionGadget<F> for PcGadget<F> {
    const NAME: &'static str = "PC";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::PC;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // program_counter is limited to 64 bits so we only consider 8 bytes
        let bytes = array_init(|_| cb.query_cell());
        cb.require_equal(
            "Constrain program_counter equal to stack value",
            from_bytes::expr(bytes.to_vec()),
            cb.curr.state.program_counter.expr(),
        );

        // Push the value on the stack
        let value = RandomLinearCombination::new(bytes, cb.randomness());
        cb.stack_push(value.expr());

        // State transition
        let state_transition = StateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

        Self {
            same_context,
            value,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        _: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

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
        execution::bus_mapping_tmp::{
            Block, Bytecode, Call, ExecStep, Rw, Transaction,
        },
        step::ExecutionResult,
        test::run_test_circuit_incomplete_fixed_table,
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
                vec![opcode.as_u8(), OpcodeId::STOP.as_u8()],
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
                ..Default::default()
            }],
            rws: vec![Rw::Stack {
                rw_counter: 1,
                is_write: true,
                call_id: 1,
                stack_pointer: 1022,
                value: Word::from(33),
            }],
            bytecodes: vec![bytecode],
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn pc_gadget_simple() {
        test_ok();
    }
}
