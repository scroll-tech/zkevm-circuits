use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::{CallContextField, TransientStorageOp, RW},
    Error,
};
use eth_types::{GethExecStep, ToWord, Word};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::TLOAD`](crate::evm::OpcodeId::TLOAD)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Tload;

impl Opcode for Tload {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let call_id = state.call()?.call_id;
        let contract_addr = state.call()?.address;

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::TxId,
            Word::from(state.tx_ctx.id()),
        )?;

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::CalleeAddress,
            contract_addr.to_word(),
        )?;

        // First stack read
        let key = state.stack_pop(&mut exec_step)?;
        #[cfg(feature = "enable-stack")]
        assert_eq!(key, geth_step.stack.last()?);

        // Transient Storage read
        let (_, &value) = state.sdb.get_transient_storage(&contract_addr, &key);
        #[cfg(feature = "enable-stack")]
        assert_eq!(
            value,
            geth_steps[1].stack.last()?,
            "inconsistent tload: step proof {value:?}, result {:?} in contract {contract_addr:?}, key {key:?}", geth_steps[1].stack.last()?,
        );

        state.push_op(
            &mut exec_step,
            RW::READ,
            TransientStorageOp::new(contract_addr, key, value, value, state.tx_ctx.id()),
        )?;

        // First stack write
        state.stack_push(&mut exec_step, value)?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod tload_tests {
    use super::*;
    use crate::{circuit_input_builder::ExecState, mock::BlockData, operation::StackOp};
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
    };
    use mock::{
        test_ctx::{helpers::*, TestContext},
        MOCK_ACCOUNTS,
    };
    use pretty_assertions::assert_eq;

    #[test]
    fn tload_opcode() {
        let code = bytecode! {
            // Load transient storage slot 0
            PUSH1(0x00u64)
            TLOAD
            STOP
        };
        let expected_loaded_value = 0;

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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::TLOAD))
            .unwrap();

        println!("{:?}", step.bus_mapping_instance);

        assert_eq!(
            [&builder.block.container.stack[step.bus_mapping_instance[2].as_usize()]]
                .map(|operation| (operation.rw(), operation.op())),
            [(
                RW::READ,
                &StackOp::new(1, StackAddress::from(1023), Word::from(0x0u32))
            )]
        );

        let transient_storage_op =
            &builder.block.container.transient_storage[step.bus_mapping_instance[3].as_usize()];
        assert_eq!(
            (transient_storage_op.rw(), transient_storage_op.op()),
            (
                RW::READ,
                &TransientStorageOp::new(
                    MOCK_ACCOUNTS[0],
                    Word::from(0x0u32),
                    Word::from(expected_loaded_value),
                    Word::from(expected_loaded_value),
                    1,
                )
            )
        );
    }
}
