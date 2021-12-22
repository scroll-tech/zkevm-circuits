use crate::{
    evm_circuit::{
        table::{Lookup, BlockContextFieldTag},
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct CoinbaseGadget<F> {
    same_context: SameContextGadget<F>,
    // TODO: make 20 bytes length as predefined params.rs
    coinbase_address: RandomLinearCombination<F, 20>,
    // For now we only consider one block for evm circuit target, if in future support multi add block number
    // block_number: RandomLinearCombination<F, 31>, 
}

impl<F: FieldExt> ExecutionGadget<F> for CoinbaseGadget<F> {
    const NAME: &'static str = "COINBASE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::COINBASE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let coinbase_address =
            RandomLinearCombination::new(cb.query_bytes(), cb.randomness());

        // Push the value to the stack
        cb.stack_push(coinbase_address.expr());

        // Lookup block table with coinbase address
        cb.block_lookup(
            BlockContextFieldTag::Coinbase.expr(),
            0.expr(),
            coinbase_address.expr(),
        );

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
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
            coinbase_address,
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

        let coinbase = block.rws[step.rw_indices[0]].stack_value();
        
        self.coinbase_address.assign(
            region,
            offset,
            Some(coinbase.to_le_bytes()[..20].try_into().unwrap()), // TODO: parametrize 20
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        step::ExecutionState,
        test::{rand_range, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
        witness::{Block, Bytecode, Call, ExecStep, Rw, Transaction},
    };
    use bus_mapping::{
        eth_types::{ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr as Fp;

    fn test_ok(address: usize) {
        let randomness = Fp::rand();
        let bytecode = Bytecode::new(
            [
                vec![OpcodeId::COINBASE.as_u8()],
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
                        rw_indices: vec![0, 1],
                        execution_state: ExecutionState::JUMP,
                        rw_counter: 1,
                        program_counter: 33,
                        stack_pointer: 1022,
                        gas_left: 9,
                        gas_cost: 8,
                        opcode: Some(OpcodeId::JUMP),
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::JUMPDEST,
                        rw_counter: 2,
                        program_counter: destination as u64,
                        stack_pointer: 1023,
                        gas_left: 1,
                        gas_cost: 1,
                        opcode: Some(OpcodeId::JUMPDEST),
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::STOP,
                        rw_counter: 2,
                        program_counter: destination as u64 + 1,
                        stack_pointer: 1023,
                        gas_left: 0,
                        opcode: Some(OpcodeId::STOP),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            rws: vec![Rw::Stack {
                rw_counter: 1,
                is_write: false,
                call_id: 1,
                stack_pointer: 1022,
                value: Word::from(destination),
            }],
            bytecodes: vec![bytecode],
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn jump_gadget_simple() {
        test_ok(34);
        test_ok(100);
    }

    #[test]
    #[ignore]
    fn jump_gadget_huge_bytecode() {
        test_ok(0x5ffe);
    }

    #[test]
    fn jump_gadget_rand() {
        test_ok(rand_range(34..1 << 11));
    }

    #[test]
    #[ignore]
    fn jump_gadget_rand_huge_bytecode() {
        test_ok(rand_range(1 << 11..0x5fff));
    }
}
