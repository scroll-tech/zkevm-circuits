use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::MAX_CODE_SIZE_IN_BYTES,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes,
            math_gadget::IsZeroGadget,
            select, sum, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct JumpiGadget<F> {
    same_context: SameContextGadget<F>,
    destination: RandomLinearCombination<F, MAX_CODE_SIZE_IN_BYTES>,
    condition: Word<F>,
    is_condition_zero: IsZeroGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for JumpiGadget<F> {
    const NAME: &'static str = "JUMPI";

    const EXECUTION_STATE: ExecutionState = ExecutionState::JUMPI;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let destination =
            RandomLinearCombination::new(cb.query_bytes(), cb.randomness());
        let condition = cb.query_word();

        // Pop the value from the stack
        cb.stack_pop(destination.expr());
        cb.stack_pop(condition.expr());

        // Determine if the jump condition is met
        let is_condition_zero =
            IsZeroGadget::construct(cb, sum::expr(&condition.cells));
        let should_jump = 1.expr() - is_condition_zero.expr();

        // Lookup opcode at destination when should_jump
        cb.condition(should_jump.clone(), |cb| {
            cb.opcode_lookup_at(
                from_bytes::expr(&destination.cells),
                OpcodeId::JUMPDEST.expr(),
                1.expr(),
            );
        });

        // Transit program_counter to destination when should_jump, otherwise by
        // delta 1.
        let next_program_counter = select::expr(
            should_jump,
            from_bytes::expr(&destination.cells),
            cb.curr.state.program_counter.expr() + 1.expr(),
        );

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: To(next_program_counter),
            stack_pointer: Delta(2.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            None,
        );

        Self {
            same_context,
            destination,
            condition,
            is_condition_zero,
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

        let [destination, condition] = [step.rw_indices[0], step.rw_indices[1]]
            .map(|idx| block.rws[idx].stack_value());

        self.destination.assign(
            region,
            offset,
            Some(destination.to_le_bytes()[..3].try_into().unwrap()),
        )?;
        self.condition
            .assign(region, offset, Some(condition.to_le_bytes()))?;
        self.is_condition_zero.assign(
            region,
            offset,
            sum::value(&condition.to_le_bytes()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        step::ExecutionState,
        test::{
            rand_range, rand_word, run_test_circuit_incomplete_fixed_table,
        },
        util::RandomLinearCombination,
        witness::{Block, Bytecode, Call, ExecStep, Rw, Transaction},
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr as Fp;

    fn test_ok(destination: usize, condition: Word) {
        assert!((68..(1 << 24) - 1).contains(&destination));
        let should_jump = !condition.is_zero();

        let randomness = Fp::rand();
        let bytecode = Bytecode::new(
            [
                vec![OpcodeId::PUSH32.as_u8()],
                condition.to_be_bytes().to_vec(),
                vec![OpcodeId::PUSH32.as_u8()],
                vec![0; 32 - destination.to_be_bytes().len()],
                destination.to_be_bytes().to_vec(),
                vec![OpcodeId::JUMPI.as_u8(), OpcodeId::STOP.as_u8()],
                vec![0; destination - 68],
                vec![OpcodeId::JUMPDEST.as_u8(), OpcodeId::STOP.as_u8()],
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
                steps: [
                    vec![ExecStep {
                        rw_indices: vec![0, 1],
                        execution_state: ExecutionState::JUMPI,
                        rw_counter: 1,
                        program_counter: 66,
                        stack_pointer: 1022,
                        gas_left: 11,
                        gas_cost: 10,
                        opcode: Some(OpcodeId::JUMPI),
                        ..Default::default()
                    }],
                    if should_jump {
                        vec![
                            ExecStep {
                                execution_state: ExecutionState::JUMPDEST,
                                rw_counter: 3,
                                program_counter: destination as u64,
                                stack_pointer: 1024,
                                gas_left: 1,
                                gas_cost: 1,
                                opcode: Some(OpcodeId::JUMPDEST),
                                ..Default::default()
                            },
                            ExecStep {
                                execution_state: ExecutionState::STOP,
                                rw_counter: 3,
                                program_counter: destination as u64 + 1,
                                stack_pointer: 1024,
                                gas_left: 0,
                                opcode: Some(OpcodeId::STOP),
                                ..Default::default()
                            },
                        ]
                    } else {
                        vec![ExecStep {
                            execution_state: ExecutionState::STOP,
                            rw_counter: 3,
                            program_counter: 67,
                            stack_pointer: 1024,
                            gas_left: 1,
                            opcode: Some(OpcodeId::STOP),
                            ..Default::default()
                        }]
                    },
                ]
                .concat(),
                ..Default::default()
            }],
            rws: vec![
                Rw::Stack {
                    rw_counter: 1,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1022,
                    value: Word::from(destination),
                },
                Rw::Stack {
                    rw_counter: 2,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1023,
                    value: condition,
                },
            ],
            bytecodes: vec![bytecode],
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn jumpi_gadget_simple() {
        test_ok(68, 1.into());
        test_ok(100, 1.into());
        test_ok(1 << 11, 1.into());
        test_ok(68, 0.into());
        test_ok(100, 0.into());
        test_ok(1 << 11, 0.into());
    }

    #[test]
    #[ignore]
    fn jumpi_gadget_huge_bytecode() {
        test_ok(0x5ffe, 1.into());
        test_ok(0x5ffe, 0.into());
    }

    #[test]
    fn jumpi_gadget_rand() {
        test_ok(rand_range(68..1 << 11), 0.into());
        test_ok(rand_range(68..1 << 11), rand_word());
    }

    #[test]
    #[ignore]
    fn jumpi_gadget_rand_huge_bytecode() {
        test_ok(rand_range(1 << 11..0x5fff), 0.into());
        test_ok(rand_range(1 << 11..0x5fff), rand_word());
    }
}
