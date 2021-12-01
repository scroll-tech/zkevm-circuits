use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::eth_types::{GethExecStep, ToBigEndian, ToLittleEndian};
use crate::{
    evm::MemoryAddress,
    operation::{MemoryOp, StackOp, RW},
    Error,
};
use core::convert::TryInto;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::MSTORE`](crate::evm::OpcodeId::MSTORE)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Mstore<const WHOLEWORD: bool>;

impl<const WHOLEWORD: bool> Opcode for Mstore<WHOLEWORD> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];
        // First stack read (offset)
        let offset = step.stack.nth_last(0)?;
        let offset_pos = step.stack.nth_last_filled(0);
        state.push_op(StackOp::new(RW::READ, offset_pos, offset));

        // Second stack read (value)
        let value = step.stack.nth_last(1)?;
        let value_pos = step.stack.nth_last_filled(1);
        state.push_op(StackOp::new(RW::READ, value_pos, value));

        // First mem write -> 32 MemoryOp generated.
        let offset_addr: MemoryAddress = offset.try_into()?;
        if WHOLEWORD {
            let bytes = value.to_be_bytes();
            for (i, byte) in bytes.iter().enumerate() {
                state.push_op(MemoryOp::new(
                    RW::WRITE,
                    offset_addr.map(|a| a + i),
                    *byte,
                ));
            }
        } else {
            // stack write operation for mstore8
            state.push_op(MemoryOp::new(
                RW::WRITE,
                offset_addr,
                value.to_le_bytes().first().unwrap() & 0xff,
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod mstore_tests {
    use super::*;
    use crate::{
        bytecode,
        circuit_input_builder::{
            CircuitInputBuilder, ExecStep, Transaction, TransactionContext,
        },
        eth_types::Word,
        evm::{MemoryAddress, StackAddress},
        mock,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn mstore_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            .setup_state()
            PUSH2(0x1234)
            PUSH2(0x100)
            #[start]
            MSTORE
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

        // Generate step corresponding to MSTORE
        let mut step = ExecStep::new(
            &block.geth_trace.struct_logs[0],
            0,
            test_builder.block_ctx.gc,
            0,
        );
        let mut state_ref =
            test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

        // Add StackOps associated to the 0x100, 0x1234 reads starting from last
        // stack position.
        state_ref.push_op(StackOp::new(
            RW::READ,
            StackAddress::from(1022),
            Word::from(0x100),
        ));
        state_ref.push_op(StackOp::new(
            RW::READ,
            StackAddress::from(1023),
            Word::from(0x1234),
        ));

        // Add the 32 MemoryOp generated from the Memory write at addr
        // 0x100..0x120 for each byte.
        for (i, byte) in Word::from(0x1234).to_be_bytes().iter().enumerate() {
            state_ref.push_op(MemoryOp::new(
                RW::WRITE,
                MemoryAddress(0x100 + i),
                *byte,
            ));
        }

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
