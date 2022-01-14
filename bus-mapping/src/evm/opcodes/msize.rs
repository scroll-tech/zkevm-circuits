use super::Opcode;
use crate::circuit_input_builder::CircuitInputStateRef;
use types::eth_types::{GethExecStep, Word};
use crate::{operation::RW, Error};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::MSIZE`](crate::evm_types::OpcodeId::MSIZE)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Msize;

impl Opcode for Msize {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &steps[0];

        // Get value result from next step's memory and do stack write
        let mem_size_value = Word::from(steps[1].memory.size() as u32);
        state.push_stack_op(
            RW::WRITE,
            step.stack.last_filled().map(|a| a - 1),
            mem_size_value,
        );

        Ok(())
    }
}

#[cfg(test)]
mod msize_tests {
    use super::*;
    use crate::{
        bytecode,
        circuit_input_builder::{ExecStep, TransactionContext},
        eth_types::Word,
        evm_types::StackAddress,
        mock,
    };

    #[test]
    fn msize_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            .setup_state()

            #[start]
            MSIZE
            STOP
        };

        let block =
            mock::BlockData::new_single_tx_trace_code_at_start(&code).unwrap();

        let mut builder = block.new_circuit_input_builder();
        builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

        let mut test_builder = block.new_circuit_input_builder();
        let mut tx = test_builder.new_tx(&block.eth_tx).unwrap();
        let mut tx_ctx = TransactionContext::new(&block.eth_tx);

        let mut step = ExecStep::new(
            &block.geth_trace.struct_logs[0],
            0,
            test_builder.block_ctx.rwc,
            0,
        );
        let mut state_ref =
            test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

        // Add StackOp WRITE to the latest Stack pos.
        state_ref.push_stack_op(
            RW::WRITE,
            StackAddress::from(1023),
            Word::from(0x3_u64),
        );

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
