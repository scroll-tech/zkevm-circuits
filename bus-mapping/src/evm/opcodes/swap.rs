use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use crate::{operation::RW, Error};
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the `OpcodeId::SWAP*` `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Swap<const N: usize>;

impl<const N: usize> Opcode for Swap<N> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];

        // Peek b and a
        let stack_b_value_read = step.stack.nth_last(N)?;
        let stack_b_position = step.stack.nth_last_filled(N);
        state.push_stack_op(RW::READ, stack_b_position, stack_b_value_read);
        let stack_a_value_read = step.stack.last()?;
        let stack_a_position = step.stack.last_filled();
        state.push_stack_op(RW::READ, stack_a_position, stack_a_value_read);

        // Write a into b_position, write b into a_position
        state.push_stack_op(RW::WRITE, stack_b_position, stack_a_value_read);
        state.push_stack_op(RW::WRITE, stack_a_position, stack_b_value_read);

        Ok(())
    }
}

#[cfg(test)]
mod swap_tests {
    use super::*;
    use crate::{
        bytecode,
        circuit_input_builder::{ExecStep, TransactionContext},
        mock,
    };
    use eth_types::evm_types::StackAddress;
    use eth_types::Word;
    use pretty_assertions::assert_eq;

    #[test]
    fn swap_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            PUSH1(0x1)
            PUSH1(0x2)
            PUSH1(0x3)
            PUSH1(0x4)
            PUSH1(0x5)
            PUSH1(0x6)
            #[start] // [1,2,3,4,5,6]
            SWAP1    // [1,2,3,4,6,5]
            SWAP3    // [1,2,5,4,6,3]
            SWAP5    // [3,2,5,4,6,1]
            STOP
        };

        // Get the execution steps from the external tracer
        let block =
            mock::BlockData::new_single_tx_trace_code_at_start(&code).unwrap();

        let mut builder = block.new_circuit_input_builder();
        builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

        let mut test_builder = block.new_circuit_input_builder();
        let mut tx = test_builder.new_tx(&block.eth_tx).unwrap();
        let mut tx_ctx = TransactionContext::new(&block.eth_tx);

        // Generate steps corresponding to DUP1, DUP3, DUP5
        for (i, (a, b)) in [(6, 5), (5, 3), (3, 1)].iter().enumerate() {
            let mut step = ExecStep::new(
                &block.geth_trace.struct_logs[i],
                0,
                test_builder.block_ctx.rwc,
                0,
            );
            let mut state_ref =
                test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

            let a_pos = StackAddress(1024 - 6);
            let b_pos = StackAddress(1024 - 5 + i * 2);
            let a_val = Word::from(*a);
            let b_val = Word::from(*b);

            state_ref.push_stack_op(RW::READ, b_pos, b_val);
            state_ref.push_stack_op(RW::READ, a_pos, a_val);
            state_ref.push_stack_op(RW::WRITE, b_pos, a_val);
            state_ref.push_stack_op(RW::WRITE, a_pos, b_val);

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
