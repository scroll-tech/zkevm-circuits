use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::eth_types::GethExecStep;
use crate::{
    operation::{StackOp, RW},
    Error,
};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the `OpcodeId::PUSH*` `OpcodeId`.
/// This is responsible of generating all of the associated [`StackOp`]s and
/// place them inside the trace's
/// [`OperationContainer`](crate::operation::OperationContainer).
#[derive(Debug, Copy, Clone)]
pub(crate) struct Push<const N: usize>;

impl<const N: usize> Opcode for Push<N> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];
        state.push_op(StackOp::new(
            RW::WRITE,
            // Get the value and addr from the next step. Being the last
            // position filled with an element in the stack
            step.stack.last_filled().map(|a| a - 1),
            steps[1].stack.last()?,
        ));

        Ok(())
    }
}

#[cfg(test)]
mod push_tests {
    use super::*;
    use crate::{
        bytecode,
        circuit_input_builder::{
            CircuitInputBuilder, ExecStep, Transaction, TransactionContext,
        },
        evm::StackAddress,
        mock, word,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn push_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            #[start]
            PUSH1(0x80)
            PUSH2(0x1234)
            PUSH16(word!("0x00112233445566778899aabbccddeeff"))
            STOP
        };

        // Get the execution steps from the external tracer
        let block =
            mock::BlockData::new_single_tx_trace_code_at_start(&code).unwrap();

        let mut builder = CircuitInputBuilder::new(
            block.eth_block.clone(),
            block.block_ctants.clone(),
        );
        builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

        let mut test_builder = CircuitInputBuilder::new(
            block.eth_block,
            block.block_ctants.clone(),
        );
        let mut tx = Transaction::new(&block.eth_tx);
        let mut tx_ctx = TransactionContext::new(&block.eth_tx);

        // Generate steps corresponding to PUSH1 80, PUSH2 1234,
        // PUSH16 0x00112233445566778899aabbccddeeff
        for (i, word) in [
            word!("0x80"),
            word!("0x1234"),
            word!("0x00112233445566778899aabbccddeeff"),
        ]
        .iter()
        .enumerate()
        {
            let mut step = ExecStep::new(
                &block.geth_trace.struct_logs[i],
                0,
                test_builder.block_ctx.gc,
                0,
            );
            let mut state_ref =
                test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

            // Add StackOp associated to the push at the latest Stack pos.
            state_ref.push_op(StackOp::new(
                RW::WRITE,
                StackAddress::from(1023 - i),
                *word,
            ));
            tx.steps_mut().push(step);
        }

        test_builder.block.txs_mut().push(tx);

        // Compare first 3 steps bus mapping instance
        for i in 0..3 {
            assert_eq!(
                builder.block.txs()[0].steps()[i].bus_mapping_instance,
                test_builder.block.txs()[0].steps()[i].bus_mapping_instance
            );
        }
        // Compare containers
        assert_eq!(builder.block.container, test_builder.block.container);

        Ok(())
    }
}
