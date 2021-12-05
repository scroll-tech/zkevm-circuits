use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::eth_types::GethExecStep;
use crate::{
    operation::{StackOp, RW},
    Error,
};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to all the Stack only operations: take N words and return one.
/// The following cases exist in the EVM:
/// - N = 1: UnaryOpcode
/// - N = 2: BinaryOpcode
/// - N = 3: TernaryOpcode
#[derive(Debug, Copy, Clone)]
pub(crate) struct StackOnlyOpcode<const N: usize>;

impl<const N: usize> Opcode for StackOnlyOpcode<N> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];
        // N stack reads
        for i in 0..N {
            let op = StackOp::new(
                RW::READ,
                step.stack.nth_last_filled(i),
                step.stack.nth_last(i)?,
            );
            state.push_op(op);
        }

        // Get operator result from next step and do stack write
        let result_value = steps[1].stack.last()?;
        state.push_op(StackOp::new(
            RW::WRITE,
            step.stack.nth_last_filled(N - 1),
            result_value,
        ));

        Ok(())
    }
}

#[cfg(test)]
mod stackonlyop_tests {
    use super::*;
    use crate::{
        bytecode,
        circuit_input_builder::{
            CircuitInputBuilder, ExecStep, Transaction, TransactionContext,
        },
        eth_types::Word,
        evm::StackAddress,
        mock, word,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn not_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            PUSH32(word!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
            #[start]
            NOT
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

        // Generate step corresponding to NOT
        let mut step = ExecStep::new(
            &block.geth_trace.struct_logs[0],
            0,
            test_builder.block_ctx.gc,
            0,
        );
        let mut state_ref =
            test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

        // Read a
        state_ref.push_op(StackOp::new(
            RW::READ,
            StackAddress(1024 - 1),
            word!("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        ));

        // Write ~a
        state_ref.push_op(StackOp::new(
            RW::WRITE,
            StackAddress(1024 - 1),
            word!("0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"),
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

    #[test]
    fn add_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            PUSH1(0x80u64)
            PUSH1(0x80u64)
            #[start]
            ADD
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

        // Generate step corresponding to ADD
        let mut step = ExecStep::new(
            &block.geth_trace.struct_logs[0],
            0,
            test_builder.block_ctx.gc,
            0,
        );
        let mut state_ref =
            test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

        let last_stack_pointer = StackAddress(1022);
        let second_last_stack_pointer = StackAddress(1023);
        let stack_value_a = Word::from(0x80);
        let stack_value_b = Word::from(0x80);
        let sum = Word::from(0x100);

        // Manage first stack read at latest stack position
        state_ref.push_op(StackOp::new(
            RW::READ,
            last_stack_pointer,
            stack_value_a,
        ));

        // Manage second stack read at second latest stack position
        state_ref.push_op(StackOp::new(
            RW::READ,
            second_last_stack_pointer,
            stack_value_b,
        ));

        // Add StackOp associated to the 0x80 push at the latest Stack pos.
        state_ref.push_op(StackOp::new(
            RW::WRITE,
            second_last_stack_pointer,
            sum,
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

    #[test]
    fn addmod_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            PUSH3(0xbcdef)
            PUSH3(0x6789a)
            PUSH3(0x12345)
            #[start]
            ADDMOD
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

        // Generate step corresponding to ADDMOD
        let mut step = ExecStep::new(
            &block.geth_trace.struct_logs[0],
            0,
            test_builder.block_ctx.gc,
            0,
        );
        let mut state_ref =
            test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

        // Read a, b, n
        state_ref.push_op(StackOp::new(
            RW::READ,
            StackAddress(1024 - 3),
            Word::from(0x12345),
        ));
        state_ref.push_op(StackOp::new(
            RW::READ,
            StackAddress(1024 - 2),
            Word::from(0x6789a),
        ));
        state_ref.push_op(StackOp::new(
            RW::READ,
            StackAddress(1024 - 1),
            Word::from(0xbcdef),
        ));

        // Write a + b % n
        state_ref.push_op(StackOp::new(
            RW::WRITE,
            StackAddress(1024 - 1),
            Word::from(0x79bdf),
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
