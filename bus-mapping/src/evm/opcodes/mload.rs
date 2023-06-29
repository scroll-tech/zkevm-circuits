use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::{GethExecStep, Word};
use log::trace;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::MLOAD`](crate::evm::OpcodeId::MLOAD)
/// `OpcodeId`. This is responsible of generating all of the associated
/// [`crate::operation::StackOp`]s and [`crate::operation::MemoryWordOp`]s and place
/// them inside the trace's [`crate::operation::OperationContainer`].
#[derive(Debug, Copy, Clone)]
pub(crate) struct Mload;

impl Opcode for Mload {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        // First stack read
        //
        let stack_value_read = geth_step.stack.last()?;
        let stack_position = geth_step.stack.last_filled();

        // Manage first stack read at latest stack position
        state.stack_read(&mut exec_step, stack_position, stack_value_read)?;

        // Read the memory value from the next step of the trace.
        let mem_read_value = geth_steps[1].stack.last()?;

        let offset = stack_value_read.as_u64();
        let shift = offset % 32;
        let slot = offset - shift;
        trace!("shift {shift}, slot {slot}");

        let (left_word, right_word) = {
            // Get the memory chunk that contains the word, starting at an aligned slot address.
            let slots_content = state.call_ctx()?.memory.read_chunk(slot.into(), 64.into());

            (
                Word::from_big_endian(&slots_content[..32]),
                Word::from_big_endian(&slots_content[32..64]),
            )
        };

        // First stack write
        state.stack_write(&mut exec_step, stack_position, mem_read_value)?;

        state.memory_read_word(&mut exec_step, slot.into(), left_word)?;
        state.memory_read_word(&mut exec_step, (slot + 32).into(), right_word)?;

        // Expand memory if needed.
        state
            .call_ctx_mut()?
            .memory
            .extend_at_least((offset + 32) as usize);

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod mload_tests {
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{MemoryWordOp, StackOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{MemoryAddress, OpcodeId, StackAddress},
        geth_types::GethData,
        Word,
    };
    use itertools::Itertools;
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn mload_opcode_impl() {
        let code = bytecode! {
            .setup_state()

            PUSH1(0x40u64)
            MLOAD
            STOP
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::MLOAD))
            .unwrap();

        assert_eq!(
            [0, 1]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x40))
                ),
                (
                    RW::WRITE,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x80))
                )
            ]
        );

        let shift = 0x40 % 32;
        let slot = 0x40 - shift;
        assert_eq!(
            (2..4)
                .map(|idx| &builder.block.container.memory_word
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op().clone()))
                .collect_vec(),
            vec![
                (
                    RW::READ,
                    MemoryWordOp::new(1, MemoryAddress(slot), Word::from(0x80u64))
                ),
                (
                    RW::READ,
                    MemoryWordOp::new(1, MemoryAddress(slot + 32), Word::from(0x00))
                ),
            ]
        )
    }
}
