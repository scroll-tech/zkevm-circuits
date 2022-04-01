use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
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
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        //
        // First stack read
        //
        let stack_value_read = geth_step.stack.last()?;
        let stack_position = geth_step.stack.last_filled();

        // Manage first stack read at latest stack position
        state.push_stack_op(&mut exec_step, RW::READ, stack_position, stack_value_read)?;

        // Read the memory
        let mut mem_read_addr: MemoryAddress = stack_value_read.try_into()?;
        // Accesses to memory that hasn't been initialized are valid, and return
        // 0.
        let mem_read_value = geth_steps[1]
            .memory
            .read_word(mem_read_addr)
            .unwrap_or_else(|_| Word::zero());

        //
        // First stack write
        //
        state.push_stack_op(&mut exec_step, RW::WRITE, stack_position, mem_read_value)?;

        //
        // First mem read -> 32 MemoryOp generated.
        //
        for byte in mem_read_value.to_be_bytes() {
            state.push_memory_op(&mut exec_step, RW::READ, mem_read_addr, byte)?;

            // Update mem_read_addr to next byte's one
            mem_read_addr += MemoryAddress::from(1);
        }

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod mload_tests {
    use super::*;
    use crate::{
        evm::opcodes::test_util::step_witness_for_bytecode,
        operation::{MemoryOp, StackOp},
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
    };
    use itertools::Itertools;

    use pretty_assertions::assert_eq;

    #[test]
    fn mload_opcode_impl() {
        let code = bytecode! {
            .setup_state()

            PUSH1(0x40u64)
            MLOAD
            STOP
        };
        let step = step_witness_for_bytecode(code, OpcodeId::MLOAD);

        assert_eq!(
            [0, 1]
                .map(|idx| &step.rws.stack[idx])
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

        assert_eq!(
            (0..32)
                .map(|idx| &step.rws.memory[idx])
                .map(|operation| (operation.rw(), operation.op().clone()))
                .collect_vec(),
            Word::from(0x80)
                .to_be_bytes()
                .into_iter()
                .enumerate()
                .map(|(idx, byte)| (RW::READ, MemoryOp::new(1, MemoryAddress(idx + 0x40), byte)))
                .collect_vec()
        )
    }
}
