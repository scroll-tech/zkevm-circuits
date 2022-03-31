#[cfg(test)]
mod number_tests {
    use crate::{
        circuit_input_builder::{ExecStep, TransactionContext},
        operation::RW,
        Error,
    };
    use eth_types::{bytecode, evm_types::StackAddress};
    use mock::new_single_tx_trace_code_at_start;
    use mock::TestContext;
    use pretty_assertions::assert_eq;

    #[test]
    fn number_opcode_impl() -> Result<(), Error> {
        let code = bytecode! {
            #[start]
            NUMBER
            STOP
        };

        // Get the execution steps from the external tracer
        let block =
            TestContext::new_from_geth_data(new_single_tx_trace_code_at_start(&code).unwrap());

        let mut builder = block.new_circuit_input_builder();
        builder
            .handle_tx(&block.eth_tx, &block.geth_trace)
            .unwrap();

        let mut test_builder = block.new_circuit_input_builder();
        let mut tx = test_builder
            .new_tx(&block.eth_tx, !block.geth_trace.failed)
            .unwrap();
        let mut tx_ctx = TransactionContext::new(&block.eth_tx, &block.geth_trace).unwrap();

        // Generate step corresponding to NUMBER
        let mut step = ExecStep::new(
            &block.geth_trace.struct_logs[0],
            0,
            test_builder.block_ctx.rwc,
            0,
        );
        let mut state_ref = test_builder.state_ref(&mut tx, &mut tx_ctx);

        // Add the last Stack write
        let number = block.eth_block.number.unwrap().as_u64();
        state_ref.push_stack_op(
            &mut step,
            RW::WRITE,
            StackAddress::from(1024 - 1),
            eth_types::U256::from(number),
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
