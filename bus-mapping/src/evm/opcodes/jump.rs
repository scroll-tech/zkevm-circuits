use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::eth_types::GethExecStep;
use crate::{
    operation::{StackOp, RW},
    Error,
};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::JUMP`](crate::evm::OpcodeId::JUMP)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Jump;

impl Opcode for Jump {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];

        // `JUMP` needs only one read operation
        let op = StackOp::new(
            RW::READ,
            step.stack.nth_last_filled(0),
            step.stack.nth_last(0)?,
        );
        state.push_op(op);

        Ok(())
    }
}

#[cfg(test)]
mod jump_tests {
    use super::*;
    use crate::{
        bytecode,
        circuit_input_builder::{
            CircuitInputBuilder, ExecStep, Transaction, TransactionContext,
        },
        eth_types::Word,
        evm::StackAddress,
        mock,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn jump_opcode_impl() -> Result<(), Error> {
        let destination = 35;

        let mut code = bytecode! {
            PUSH32(destination)
            #[start]
            JUMP
        };
        for _ in 0..(destination - 34) {
            code.write(0);
        }
        code.append(&bytecode! {
            JUMPDEST
            STOP
        });

        // Get the execution steps from the external tracer
        let block =
            mock::BlockData::new_single_tx_trace_code_at_start(&code).unwrap();

        let mut builder = CircuitInputBuilder::new(
            &block.eth_block.clone(),
            block.ctants.clone(),
        );
        builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

        let mut test_builder =
            CircuitInputBuilder::new(&block.eth_block, block.ctants.clone());
        let mut tx = Transaction::new(&block.eth_tx);
        let mut tx_ctx = TransactionContext::new(&block.eth_tx);

        // Generate step corresponding to JUMP
        let mut step = ExecStep::new(
            &block.geth_trace.struct_logs[0],
            0,
            test_builder.block_ctx.gc,
            0,
        );
        let mut state_ref =
            test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

        // Add the last Stack read
        state_ref.push_op(StackOp::new(
            RW::READ,
            StackAddress::from(1023),
            Word::from(destination),
        ));

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
