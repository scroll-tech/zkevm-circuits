use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::eth_types::GethExecStep;
use crate::{
    operation::{StackOp, StorageOp, RW},
    Error,
};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::SSTORE`](crate::evm::OpcodeId::SSTORE)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Sstore;

impl Opcode for Sstore {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];
        // First stack read (key)
        let key = step.stack.nth_last(0)?;
        let key_pos = step.stack.nth_last_filled(0);
        state.push_op(StackOp::new(RW::READ, key_pos, key));

        // Second stack read (value)
        let value = step.stack.nth_last(1)?;
        let value_pos = step.stack.nth_last_filled(1);
        state.push_op(StackOp::new(RW::READ, value_pos, value));

        // Storage write
        let value_prev = step.storage.get_or_err(&key)?;
        state.push_op(StorageOp::new(
            RW::WRITE,
            state.call().address,
            key,
            value,
            value_prev,
        ));

        Ok(())
    }
}

#[cfg(test)]
mod sstore_tests {
    use super::*;
    use crate::{
        bytecode,
        circuit_input_builder::{
            CircuitInputBuilder, ExecStep, Transaction, TransactionContext,
        },
        eth_types::{Address, Word},
        evm::StackAddress,
        mock,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn sstore_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            // Write 0x6f to storage slot 1
            PUSH1(0x6fu64)
            PUSH1(0x01u64)
            SSTORE
            // Write 0x7f to storage slot 1
            PUSH1(0x7fu64)
            PUSH1(0x01u64)
            #[start]
            SSTORE
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

        // Generate step corresponding to SLOAD
        let mut step = ExecStep::new(
            &block.geth_trace.struct_logs[0],
            0,
            test_builder.block_ctx.gc,
            0,
        );
        let mut state_ref =
            test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);
        // Add StackOp associated to the stack pop.
        state_ref.push_op(StackOp::new(
            RW::READ,
            StackAddress::from(1022),
            Word::from(0x01u32),
        ));
        state_ref.push_op(StackOp::new(
            RW::READ,
            StackAddress::from(1023),
            Word::from(0x7fu32),
        ));
        // Add StorageOp associated to the storage read.
        state_ref.push_op(StorageOp::new(
            RW::WRITE,
            Address::from([0u8; 20]),
            Word::from(0x01u32),
            Word::from(0x7fu32),
            Word::from(0x7fu32), // TODO: 6f?
        ));
        tx.steps_mut().push(step);
        test_builder.block.txs_mut().push(tx);

        assert_eq!(
            builder.block.txs()[0].steps()[0].bus_mapping_instance,
            test_builder.block.txs()[0].steps()[0].bus_mapping_instance
        );
        assert_eq!(builder.block.container, test_builder.block.container);

        Ok(())
    }
}
