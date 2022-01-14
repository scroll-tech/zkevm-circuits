use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use types::eth_types::GethExecStep;
use crate::{operation::RW, Error};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the `OpcodeId::DUP*` `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Dup<const N: usize>;

impl<const N: usize> Opcode for Dup<N> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];

        let stack_value_read = step.stack.nth_last(N - 1)?;
        let stack_position = step.stack.nth_last_filled(N - 1);
        state.push_stack_op(RW::READ, stack_position, stack_value_read);

        state.push_stack_op(
            RW::WRITE,
            step.stack.last_filled().map(|a| a - 1),
            stack_value_read,
        );

        Ok(())
    }
}

#[cfg(test)]
mod dup_tests {
    use super::*;
    use crate::{
        bytecode,
        circuit_input_builder::{ExecStep, TransactionContext},
        evm_types::StackAddress,
        mock,
    };
    use types::word;
    use pretty_assertions::assert_eq;

    #[test]
    fn dup_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            PUSH1(0x1)
            PUSH1(0x2)
            PUSH1(0x3)
            #[start] // [1,2,3]
            DUP1     // [1,2,3,3]
            DUP3     // [1,2,3,3,2]
            DUP5     // [1,2,3,3,2,1]
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
        for (i, word) in [word!("0x3"), word!("0x2"), word!("0x1")]
            .iter()
            .enumerate()
        {
            let mut step = ExecStep::new(
                &block.geth_trace.struct_logs[i],
                0,
                test_builder.block_ctx.rwc,
                0,
            );
            let mut state_ref =
                test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

            state_ref.push_stack_op(
                RW::READ,
                StackAddress(1024 - 3 + i),
                *word,
            );

            state_ref.push_stack_op(
                RW::WRITE,
                StackAddress(1024 - 4 - i),
                *word,
            );

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
