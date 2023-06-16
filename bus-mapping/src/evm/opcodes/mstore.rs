use std::mem;

use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::{evm_types::MemoryAddress, GethExecStep, ToBigEndian, ToLittleEndian, Word};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::MSTORE`](crate::evm::OpcodeId::MSTORE)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Mstore<const IS_MSTORE8: bool>;

impl<const IS_MSTORE8: bool> Opcode for Mstore<IS_MSTORE8> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        // First stack read (offset)
        let offset = geth_step.stack.nth_last(0)?;
        let offset_pos = geth_step.stack.nth_last_filled(0);
        state.stack_read(&mut exec_step, offset_pos, offset)?;

        // Second stack read (value)
        let value = geth_step.stack.nth_last(1)?;
        let value_pos = geth_step.stack.nth_last_filled(1);
        state.stack_read(&mut exec_step, value_pos, value)?;

        let offset_u64 = offset.as_u64() as usize;
        let shift = offset_u64 % 32;
        let slot = offset_u64 - shift;
        println!("shift {}, slot {}", shift, slot);

        let (left_word, right_word) = {
            // Get the memory chunk that contains the word, starting at an aligned slot address.
            let mut slots_content = state.call_ctx()?.memory.read_chunk(slot.into(), 64.into());

            // reconstruct memory with value
            match IS_MSTORE8 {
                true => {
                    let val = *value.to_le_bytes().first().unwrap();
                    slots_content[shift] = val;
                }
                false => {
                    let bytes = value.to_be_bytes();
                    slots_content[shift..shift + 32].copy_from_slice(&bytes);
                }
            }

            // after memory construction, we can get the left and right words to fill bus mapping.
            (
                Word::from_big_endian(&slots_content[..32]),
                Word::from_big_endian(&slots_content[32..64]),
            )
        };

        // memory write left word for mstore8 and mstore.
        state.memory_write_word(&mut exec_step, slot.into(), left_word)?;

        if !IS_MSTORE8 {
            // memory write right word for mstore
            state.memory_write_word(&mut exec_step, (slot + 32).into(), right_word)?;

            // TODO: edge case: if shift = 0, we could skip the right word?
        }

        // reconstruction

        let minimal_length = offset_u64 + if IS_MSTORE8 { 1 } else { 32 };
        state.call_ctx_mut()?.memory.extend_at_least(minimal_length);

        match IS_MSTORE8 {
            true => {
                let val = *value.to_le_bytes().first().unwrap();
                state.call_ctx_mut()?.memory.0[offset_u64] = val;
            }
            false => {
                let bytes = value.to_be_bytes();
                state.call_ctx_mut()?.memory[offset_u64..offset_u64 + 32].copy_from_slice(&bytes);
            }
        }

        println!(
            "after mstore memory length {}",
            state.call_ctx_mut()?.memory.0.len()
        );
        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod mstore_tests {
    use super::*;
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{MemoryOp, MemoryWordOp, StackOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{MemoryAddress, OpcodeId, StackAddress},
        geth_types::GethData,
        Word, U256,
    };
    use itertools::Itertools;
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn mstore_opcode_impl() {
        let code = bytecode! {
            .setup_state()
            PUSH2(0x1234)
            PUSH2(0x100)
            MSTORE
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
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::MSTORE))
            .nth(1)
            .unwrap();

        assert_eq!(
            [0, 1]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1022u32), Word::from(0x100u64))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023u32), Word::from(0x1234u64))
                )
            ]
        );

        let shift = 0x100 % 32;
        let slot = 0x100 - shift;
        assert_eq!(
            (2..4)
                .map(|idx| &builder.block.container.memory_word
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op().clone()))
                .collect_vec(),
            vec![
                (
                    RW::WRITE,
                    MemoryWordOp::new(1, MemoryAddress(slot), Word::from(0x1234u64))
                ),
                (
                    RW::WRITE,
                    MemoryWordOp::new(1, MemoryAddress(slot + 32), Word::from(0x00))
                ),
            ]
        )
    }

    #[test]
    fn mstore8_opcode_impl() {
        let code = bytecode! {
            .setup_state()
            PUSH2(0x1234)
            PUSH2(0x100)
            MSTORE8
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::MSTORE8))
            .unwrap();

        assert_eq!(
            [0, 1]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1022u32), Word::from(0x100u64))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023u32), Word::from(0x1234))
                )
            ]
        );

        let shift = 0x100 % 32;
        let slot = 0x100 - shift;
        let memory_word_op =
            &builder.block.container.memory_word[step.bus_mapping_instance[2].as_usize()];
        assert_eq!(
            (memory_word_op.rw(), memory_word_op.op()),
            (
                RW::WRITE,
                &MemoryWordOp::new(1, MemoryAddress(slot), Word::from(0x34))
            )
        )
    }
}
