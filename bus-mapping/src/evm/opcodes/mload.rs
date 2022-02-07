use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::{operation::RW, Error};
use core::convert::TryInto;
use eth_types::evm_types::MemoryAddress;
use eth_types::{GethExecStep, ToBigEndian, Word};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::MLOAD`](crate::evm::OpcodeId::MLOAD)
/// `OpcodeId`. This is responsible of generating all of the associated
/// [`crate::operation::StackOp`]s and [`crate::operation::MemoryOp`]s and place
/// them inside the trace's [`crate::operation::OperationContainer`].
#[derive(Debug, Copy, Clone)]
pub(crate) struct Mload;

impl Opcode for Mload {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];
        //
        // First stack read
        //
        let stack_value_read = step.stack.last()?;
        let stack_position = step.stack.last_filled();

        // Manage first stack read at latest stack position
        state.push_stack_op(RW::READ, stack_position, stack_value_read);

        // Read the memory
        let mut mem_read_addr: MemoryAddress = stack_value_read.try_into()?;
        // Accesses to memory that hasn't been initialized are valid, and return
        // 0.
        let mem_read_value = steps[1]
            .memory
            .read_word(mem_read_addr)
            .unwrap_or_else(|_| Word::zero());

        //
        // First stack write
        //
        state.push_stack_op(RW::WRITE, stack_position, mem_read_value);

        //
        // First mem read -> 32 MemoryOp generated.
        //
        let bytes = mem_read_value.to_be_bytes();
        bytes.iter().for_each(|value_byte| {
            state.push_memory_op(RW::READ, mem_read_addr, *value_byte);

            // Update mem_read_addr to next byte's one
            mem_read_addr += MemoryAddress::from(1);
        });

        Ok(())
    }
}

#[cfg(test)]
mod mload_tests {
    use super::*;
    use crate::circuit_input_builder::{ExecStep, TransactionContext};
    use eth_types::evm_types::StackAddress;
    use eth_types::{bytecode, Word};
    use pretty_assertions::assert_eq;

    #[test]
    fn mload_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            .setup_state()

            PUSH1(0x40u64)
            #[start]
            MLOAD
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

        // Add StackOp associated to the 0x40 read from the latest Stack pos.
        state_ref.push_stack_op(RW::READ, StackAddress::from(1023), Word::from(0x40));

        // Add the last Stack write
        state_ref.push_stack_op(RW::WRITE, StackAddress::from(1023), Word::from(0x80));

        // Add the 32 MemoryOp generated from the Memory read at addr
        // 0x40<->0x80 for each byte.
        Word::from(0x80)
            .to_be_bytes()
            .iter()
            .enumerate()
            .map(|(idx, byte)| (idx + 0x40, byte))
            .for_each(|(idx, byte)| {
                state_ref.push_memory_op(RW::READ, idx.into(), *byte);
            });

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
