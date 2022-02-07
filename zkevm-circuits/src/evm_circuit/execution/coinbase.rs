use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::BlockContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::ToLittleEndian;
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

        // Push the value to the stack
        cb.stack_push(coinbase_address.expr());

        // Lookup block table with coinbase address
        cb.block_lookup(
            BlockContextFieldTag::Coinbase.expr(),
            None,
            coinbase_address.expr(),
        );

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition, None);

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
    use crate::test_util::run_test_circuits;
    use eth_types::bytecode;

    fn test_ok() {
        let bytecode = bytecode! {
            #[start]
            COINBASE
            STOP
        };
        assert_eq!(run_test_circuits(bytecode), Ok(()));
    }
    #[test]
    fn coinbase_gadget_test() {
        test_ok();
    }
}
