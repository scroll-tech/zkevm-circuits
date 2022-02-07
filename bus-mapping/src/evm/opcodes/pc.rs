use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::{operation::RW, Error};
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::PC`](crate::evm::OpcodeId::PC) `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Pc;

impl Opcode for Pc {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];
        // Get value result from next step and do stack write
        let value = steps[1].stack.last()?;
        state.push_stack_op(RW::WRITE, step.stack.last_filled().map(|a| a - 1), value);

        Ok(())
    }
}

#[cfg(test)]
mod pc_tests {
    use super::*;
    use crate::circuit_input_builder::{ExecStep, TransactionContext};
    use eth_types::evm_types::StackAddress;
    use eth_types::{bytecode, Word};
    use pretty_assertions::assert_eq;

    #[test]
    fn pc_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            PUSH1(0x1)
            PUSH1(0x2)
            #[start]
            PC
            STOP
        };

        // Get the execution steps from the external tracer
        let block = crate::mock::BlockData::new_from_geth_data(
            mock::new_single_tx_trace_code_at_start(&code).unwrap(),
        );

        let mut builder = block.new_circuit_input_builder();
        builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

        let mut test_builder = block.new_circuit_input_builder();
        let mut tx = test_builder.new_tx(&block.eth_tx).unwrap();
        let mut tx_ctx = TransactionContext::new(&block.eth_tx);

        // Generate step corresponding to MLOAD
        let mut step = ExecStep::new(
            &block.geth_trace.struct_logs[0],
            0,
            test_builder.block_ctx.rwc,
            0,
        );
        let mut state_ref = test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

        // Add the last Stack write
        state_ref.push_stack_op(RW::WRITE, StackAddress::from(1024 - 3), Word::from(0x4));

        tx.steps_mut().push(step);
        test_builder.block.txs_mut().push(tx);

        // Compare first step bus mapping instance
        assert_eq!(
            builder.block.txs()[0].steps()[0].bus_mapping_instance,
            test_builder.block.txs()[0].steps()[0].bus_mapping_instance,
        );

        // Compare containers
        assert_eq!(builder.block.container, test_builder.block.container);

        Ok(())
    }
}
