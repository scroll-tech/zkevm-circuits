use crate::{
    evm_circuit::{
        execution::{
            bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
            ExecutionGadget,
        },
        step::ExecutionResult,
        table::{FixedTableTag, Lookup},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            Word,
        },
    },
    util::Expr,
};
use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct AndGadget<F> {
    same_context: SameContextGadget<F>,
    a: Word<F>,
    b: Word<F>,
    c: Word<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for AndGadget<F> {
    const NAME: &'static str = "AND";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::AND;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word();
        let b = cb.query_word();
        let c = cb.query_word();

        cb.stack_pop(a.expr());
        cb.stack_pop(b.expr());
        cb.stack_push(c.expr());

        // Because opcode AND, OR, and XOR are continuous, so we can make the
        // FixedTableTag of them also continuous, and use the opcode delta from
        // OpcodeId::AND as the delta to FixedTableTag::BitwiseAnd.
        let tag = FixedTableTag::BitwiseAnd.expr()
            + (opcode.expr() - OpcodeId::AND.as_u64().expr());
        for idx in 0..32 {
            cb.add_lookup(Lookup::Fixed {
                tag: tag.clone(),
                values: [
                    a.cells[idx].expr(),
                    b.cells[idx].expr(),
                    c.cells[idx].expr(),
                ],
            });
        }

        // State transition
        let state_transition = StateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            ..Default::default()
        };
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

        Self {
            same_context,
            a,
            b,
            c,
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

        let [a, b, c] =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
                .map(|idx| block.rws[idx].stack_value());
        self.a.assign(region, offset, Some(a.to_le_bytes()))?;
        self.b.assign(region, offset, Some(b.to_le_bytes()))?;
        self.c.assign(region, offset, Some(c.to_le_bytes()))?;

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
        test::{rand_word, run_test_circuit_complete_fixed_table},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok(a: Word, b: Word, c_and: Word, c_or: Word, c_xor: Word) {
        let randomness = Base::rand();
        let bytecode = Bytecode::new(
            [
                vec![OpcodeId::PUSH32.as_u8()],
                b.to_be_bytes().to_vec(),
                vec![OpcodeId::PUSH32.as_u8()],
                a.to_be_bytes().to_vec(),
                vec![OpcodeId::PUSH32.as_u8()],
                b.to_be_bytes().to_vec(),
                vec![OpcodeId::PUSH32.as_u8()],
                a.to_be_bytes().to_vec(),
                vec![OpcodeId::PUSH32.as_u8()],
                b.to_be_bytes().to_vec(),
                vec![OpcodeId::PUSH32.as_u8()],
                a.to_be_bytes().to_vec(),
                vec![
                    OpcodeId::AND.as_u8(),
                    OpcodeId::POP.as_u8(),
                    OpcodeId::OR.as_u8(),
                    OpcodeId::POP.as_u8(),
                    OpcodeId::XOR.as_u8(),
                    OpcodeId::STOP.as_u8(),
                ],
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
                        rw_indices: vec![0, 1, 2],
                        execution_result: ExecutionResult::AND,
                        rw_counter: 1,
                        program_counter: 198,
                        stack_pointer: 1018,
                        gas_left: 13,
                        gas_cost: 3,
                        opcode: Some(OpcodeId::AND),
                        ..Default::default()
                    },
                    ExecStep {
                        rw_indices: vec![3],
                        execution_result: ExecutionResult::POP,
                        rw_counter: 4,
                        program_counter: 199,
                        stack_pointer: 1019,
                        gas_left: 10,
                        gas_cost: 2,
                        opcode: Some(OpcodeId::POP),
                        ..Default::default()
                    },
                    ExecStep {
                        rw_indices: vec![4, 5, 6],
                        execution_result: ExecutionResult::AND,
                        rw_counter: 5,
                        program_counter: 200,
                        stack_pointer: 1020,
                        gas_left: 8,
                        gas_cost: 3,
                        opcode: Some(OpcodeId::OR),
                        ..Default::default()
                    },
                    ExecStep {
                        rw_indices: vec![7],
                        execution_result: ExecutionResult::POP,
                        rw_counter: 8,
                        program_counter: 201,
                        stack_pointer: 1021,
                        gas_left: 5,
                        gas_cost: 2,
                        opcode: Some(OpcodeId::POP),
                        ..Default::default()
                    },
                    ExecStep {
                        rw_indices: vec![8, 9, 10],
                        execution_result: ExecutionResult::AND,
                        rw_counter: 9,
                        program_counter: 202,
                        stack_pointer: 1022,
                        gas_left: 3,
                        gas_cost: 3,
                        opcode: Some(OpcodeId::XOR),
                        ..Default::default()
                    },
                    ExecStep {
                        execution_result: ExecutionResult::STOP,
                        rw_counter: 12,
                        program_counter: 203,
                        stack_pointer: 1023,
                        gas_left: 0,
                        opcode: Some(OpcodeId::STOP),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            rws: vec![
                Rw::Stack {
                    rw_counter: 1,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1018,
                    value: a,
                },
                Rw::Stack {
                    rw_counter: 2,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1019,
                    value: b,
                },
                Rw::Stack {
                    rw_counter: 3,
                    is_write: true,
                    call_id: 1,
                    stack_pointer: 1019,
                    value: c_and,
                },
                Rw::Stack {
                    rw_counter: 4,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1019,
                    value: c_and,
                },
                Rw::Stack {
                    rw_counter: 5,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1020,
                    value: a,
                },
                Rw::Stack {
                    rw_counter: 6,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1021,
                    value: b,
                },
                Rw::Stack {
                    rw_counter: 7,
                    is_write: true,
                    call_id: 1,
                    stack_pointer: 1021,
                    value: c_or,
                },
                Rw::Stack {
                    rw_counter: 8,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1021,
                    value: c_or,
                },
                Rw::Stack {
                    rw_counter: 9,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1022,
                    value: a,
                },
                Rw::Stack {
                    rw_counter: 10,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1023,
                    value: b,
                },
                Rw::Stack {
                    rw_counter: 11,
                    is_write: true,
                    call_id: 1,
                    stack_pointer: 1023,
                    value: c_xor,
                },
            ],
            bytecodes: vec![bytecode],
        };
        assert_eq!(run_test_circuit_complete_fixed_table(block), Ok(()));
    }

    #[test]
    fn and_gadget_simple() {
        test_ok(
            0x12_34_56.into(),
            0x78_9A_BC.into(),
            0x10_10_14.into(),
            0x7A_BE_FE.into(),
            0x6A_AE_EA.into(),
        );
    }

    #[test]
    fn and_gadget_rand() {
        let a = rand_word();
        let b = rand_word();
        test_ok(a, b, a & b, a | b, a ^ b);
    }
}
