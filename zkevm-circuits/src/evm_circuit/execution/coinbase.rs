use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::BlockContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct CoinbaseGadget<F> {
    same_context: SameContextGadget<F>,
    coinbase_address: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for CoinbaseGadget<F> {
    const NAME: &'static str = "COINBASE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::COINBASE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let coinbase_address = cb.query_cell();

        // Pop the value from the stack
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
            stack_pointer: Delta(-1.expr()),
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
            Some(Word::random_linear_combine(
                coinbase.to_le_bytes(),
                block.randomness,
            )),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        step::ExecutionState,
        test::run_test_circuit_incomplete_fixed_table,
        util::RandomLinearCombination,
        witness::{
            Block, BlockContext, Bytecode, Call, ExecStep, Rw, Transaction,
        },
    };
    use bus_mapping::{
        eth_types::{Address, ToLittleEndian, ToWord},
        evm::OpcodeId,
    };
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr as Fp;
    use std::str::FromStr;

    fn test_ok(address: &str) {
        let randomness = Fp::rand();
        let coinbase_addr = Address::from_str(address).unwrap(); // u160
        let bytecode = Bytecode::new(
            [vec![OpcodeId::COINBASE.as_u8(), OpcodeId::STOP.as_u8()]].concat(),
        );
        let block_context = BlockContext {
            coinbase: coinbase_addr,
            gas_limit: 0,
            ..Default::default()
        };
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
                        execution_state: ExecutionState::COINBASE,
                        rw_counter: 1,
                        program_counter: 0,
                        stack_pointer: 1024,
                        gas_left: 3,
                        gas_cost: 2,
                        opcode: Some(OpcodeId::COINBASE),
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::STOP,
                        rw_counter: 2,
                        program_counter: 1,
                        stack_pointer: 1023,
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
                stack_pointer: 1023,
                value: coinbase_addr.to_word(),
            }],
            bytecodes: vec![bytecode],
            context: block_context,
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn coinbase_gadget_test() {
        test_ok("0x9a0C63EBb78B35D7c209aFbD299B056098b5439b");
    }
}
