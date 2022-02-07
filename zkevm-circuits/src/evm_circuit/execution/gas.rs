use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use bus_mapping::evm::OpcodeId;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct GasGadget<F> {
    same_context: SameContextGadget<F>,
    gas_left: RandomLinearCombination<F, N_BYTES_GAS>,
}

impl<F: FieldExt> ExecutionGadget<F> for GasGadget<F> {
    const NAME: &'static str = "GAS";

    const EXECUTION_STATE: ExecutionState = ExecutionState::GAS;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // The gas passed to a transaction is a 64-bit number.
        let gas_left = cb.query_rlc();

        // The `gas_left` in the current state has to be deducted by the gas
        // used by the `GAS` opcode itself.
        cb.require_equal(
            "Constraint: gas left equal to stack value",
            from_bytes::expr(&gas_left.cells),
            cb.curr.state.gas_left.expr() - OpcodeId::GAS.constant_gas_cost().expr(),
        );

        // Construct the value and push it to stack.
        cb.stack_push(gas_left.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition, None);

        Self {
            same_context,
            gas_left,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        _block: &Block<F>,
        _transaction: &Transaction<F>,
        _call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // The GAS opcode takes into account the reduction of gas available due
        // to the instruction itself.
        self.gas_left.assign(
            region,
            offset,
            Some(
                step.gas_left
                    .saturating_sub(OpcodeId::GAS.constant_gas_cost().as_u64())
                    .to_le_bytes(),
            ),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        evm_circuit::{test::run_test_circuit, witness::block_convert},
        test_util::{run_test_circuits, BytecodeTestConfig},
    };
    use bus_mapping::mock::BlockData;
    use eth_types::{bytecode, evm_types::Gas};
    use mock::new_single_tx_trace_code_gas;

    fn test_ok() {
        let bytecode = bytecode! {
            #[start]
            GAS
            STOP
        };
        assert_eq!(run_test_circuits(bytecode), Ok(()));
    }

    #[test]
    fn gas_gadget_simple() {
        test_ok();
    }

    #[test]
    fn gas_gadget_incorrect_deduction() {
        let bytecode = bytecode! {
            #[start]
            GAS
            STOP
        };
        let config = BytecodeTestConfig::default();
        let block_trace = BlockData::new_from_geth_data(
            new_single_tx_trace_code_gas(&bytecode, Gas(config.gas_limit))
                .expect("could not build block trace"),
        );
        let mut builder = block_trace.new_circuit_input_builder();
        builder
            .handle_tx(&block_trace.eth_tx, &block_trace.geth_trace)
            .expect("could not handle block tx");
        let mut block = block_convert(config.randomness, bytecode.code(), &builder.block);

        // The above block has 2 steps (GAS and STOP). We forcefully assign a
        // wrong `gas_left` value for the second step, to assert that
        // the circuit verification fails for this scenario.
        assert_eq!(block.txs.len(), 1);
        assert_eq!(block.txs[0].steps.len(), 2);
        block.txs[0].steps[1].gas_left -= 1;

        assert!(run_test_circuit(block, config.evm_circuit_lookup_tags).is_err());
    }
}
