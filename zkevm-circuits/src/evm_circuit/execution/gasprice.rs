use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::{CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct GasPriceGadget<F> {
    tx_id: Cell<F>,
    gas_price: Cell<F>,
    same_context: SameContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for GasPriceGadget<F> {
    const NAME: &'static str = "GASPRICE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::GASPRICE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Query gasprice value
        let gas_price = cb.query_cell();

        // Lookup in call_ctx the TxId
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        // Lookup the gas_price in tx table
        cb.tx_context_lookup(
            tx_id.expr(),
            TxContextFieldTag::GasPrice,
            None,
            gas_price.expr(),
        );

        // Push the value to the stack
        cb.stack_push(gas_price.expr());

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2u64.expr()),
            program_counter: Delta(1u64.expr()),
            stack_pointer: Delta((-1i32).expr()),
            gas_left: Delta(-OpcodeId::GASPRICE.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            tx_id,
            gas_price,
            same_context,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let gas_price = block.rws.sorted_stack_rw()[0].stack_value();

        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;

        self.gas_price.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                gas_price.to_le_bytes(),
                block.randomness,
            )),
        )?;

        self.same_context.assign_exec_step(region, offset, step)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::run_test_circuits;
    use eth_types::{bytecode, Word};
    use mock::test_ctx::{helpers::*, TestContext};

    #[test]
    fn gasprice_gadget_test() {
        let bytecode = bytecode! {
            #[start]
            GASPRICE
            STOP
        };

        let two_gwei = Word::from(2_000_000_000u64);

        // Get the execution steps from the external tracer
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(bytecode),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas_price(two_gwei);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }
}
