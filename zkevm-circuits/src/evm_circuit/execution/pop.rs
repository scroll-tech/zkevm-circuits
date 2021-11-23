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
            Cell, Word,
        },
    },
    util::Expr,
};
use bus_mapping::eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone)]
pub(crate) struct PopGadget<F> {
    same_context: SameContextGadget<F>,
    value: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for PopGadget<F> {
    const NAME: &'static str = "POP";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::POP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let value = cb.query_cell();

        // Pop the value from the stack
        cb.stack_pop(value.expr());

        // State transition
        let state_transition = StateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
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
        block: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let value = block.rws[step.rw_indices[0]].stack_value();
        self.value.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                value.to_le_bytes(),
                block.randomness,
            )),
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
        test::{rand_word, try_test_circuit},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok(value: Word) {
        let opcode = OpcodeId::POP;
        let randomness = Base::rand();
        let bytecode = Bytecode::new(
            [
                vec![OpcodeId::PUSH32.as_u8()],
                value.to_be_bytes().to_vec(),
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
                        execution_result: ExecutionResult::POP,
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
                        stack_pointer: 1024,
                        gas_left: 1,
                        opcode: Some(OpcodeId::STOP),
                        ..Default::default()
                    },
                ],
            }],
            rws: vec![Rw::Stack {
                rw_counter: 1,
                is_write: false,
                call_id: 1,
                stack_pointer: 1023,
                value,
            }],
            bytecodes: vec![bytecode],
        };
        try_test_circuit(block, Ok(()));
    }

    #[test]
    fn pop_gadget_simple() {
        test_ok(Word::from(0x030201));
    }

    #[test]
    fn pop_gadget_rand() {
        test_ok(rand_word());
    }
}
