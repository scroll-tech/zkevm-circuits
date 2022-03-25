use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::{operation::RW, Error};
use core::convert::TryInto;
use eth_types::evm_types::MemoryAddress;
use eth_types::{GethExecStep, ToBigEndian, ToLittleEndian};

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
        state.push_stack_op(&mut exec_step, RW::READ, offset_pos, offset)?;

        // Second stack read (value)
        let value = geth_step.stack.nth_last(1)?;
        let value_pos = geth_step.stack.nth_last_filled(1);
        state.push_stack_op(&mut exec_step, RW::READ, value_pos, value)?;

        // First mem write -> 32 MemoryOp generated.
        let offset_addr: MemoryAddress = offset.try_into()?;

        match IS_MSTORE8 {
            true => {
                // stack write operation for mstore8
                state.push_memory_op(
                    &mut exec_step,
                    RW::WRITE,
                    offset_addr,
                    *value.to_le_bytes().first().unwrap(),
                )?;
            }
            false => {
                // stack write each byte for mstore
                let bytes = value.to_be_bytes();
                for (i, byte) in bytes.iter().enumerate() {
                    state.push_memory_op(
                        &mut exec_step,
                        RW::WRITE,
                        offset_addr.map(|a| a + i),
                        *byte,
                    )?;
                }
            }
        }

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod mstore_tests {
    use super::*;
    use crate::circuit_input_builder::ExecState;
    use crate::operation::{MemoryOp, StackOp};
    use eth_types::bytecode;
    use eth_types::evm_types::{MemoryAddress, OpcodeId, StackAddress};
    use eth_types::Word;
    use itertools::Itertools;
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
        let block = crate::mock::BlockData::new_from_geth_data(
            mock::new_single_tx_trace_code(&code).unwrap(),
        );

        let mut builder = block.new_circuit_input_builder();
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
                    &StackOp::new(1, StackAddress::from(1022), Word::from(0x100))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x1234))
                )
            ]
        );

        assert_eq!(
            (2..34)
                .map(|idx| &builder.block.container.memory
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op().clone()))
                .collect_vec(),
            Word::from(0x1234)
                .to_be_bytes()
                .into_iter()
                .enumerate()
                .map(|(idx, byte)| (
                    RW::WRITE,
                    MemoryOp::new(1, MemoryAddress(idx + 0x100), byte)
                ))
                .collect_vec()
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
        let block = crate::mock::BlockData::new_from_geth_data(
            mock::new_single_tx_trace_code(&code).unwrap(),
        );

        let mut builder = block.new_circuit_input_builder();
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
                    &StackOp::new(1, StackAddress::from(1022), Word::from(0x100))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x1234))
                )
            ]
        );

        let memory_op = &builder.block.container.memory[step.bus_mapping_instance[2].as_usize()];
        assert_eq!(
            (memory_op.rw(), memory_op.op()),
            (RW::WRITE, &MemoryOp::new(1, MemoryAddress(0x100), 0x34))
        )
    }
}
