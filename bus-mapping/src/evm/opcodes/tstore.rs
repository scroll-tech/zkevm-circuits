use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::{CallContextField, TransientStorageOp},
    Error,
};
use eth_types::{GethExecStep, ToWord, Word};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::TSTORE`](crate::evm::OpcodeId::TSTORE)
/// `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Tstore;

impl Opcode for Tstore {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let contract_addr = state.call()?.address;

        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::TxId,
            Word::from(state.tx_ctx.id()),
        )?;
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::IsStatic,
            Word::from(state.call()?.is_static as u8),
        )?;

        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::RwCounterEndOfReversion,
            Word::from(state.call()?.rw_counter_end_of_reversion),
        )?;

        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::IsPersistent,
            Word::from(state.call()?.is_persistent as u8),
        )?;

        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CalleeAddress,
            state.call()?.address.to_word(),
        )?;

        let key = state.stack_pop(&mut exec_step)?;
        let value = state.stack_pop(&mut exec_step)?;
        #[cfg(feature = "enable-stack")]
        {
            assert_eq!(key, geth_step.stack.nth_last(0)?);
            assert_eq!(value, geth_step.stack.nth_last(1)?);
        }

        let (_, value_prev) = state.sdb.get_transient_storage(&contract_addr, &key);
        let value_prev = *value_prev;

        state.push_op_reversible(
            &mut exec_step,
            TransientStorageOp::new(
                state.call()?.address,
                key,
                value,
                value_prev,
                state.tx_ctx.id(),
            ),
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod tstore_tests {
    use super::*;
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{CallContextOp, StackOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        Word,
    };
    use mock::{test_ctx::helpers::tx_from_1_to_0, TestContext, MOCK_ACCOUNTS};
    use pretty_assertions::assert_eq;

    #[test]
    fn tstore_opcode() {
        let code = bytecode! {
            // Write 0x6f to transient storage slot 0
            PUSH1(0x6fu64)
            PUSH1(0x00u64)
            TSTORE
            PUSH1(0x00u64)
            TLOAD
            STOP
        };
        let expected_prev_value = 0x00u64;

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(MOCK_ACCOUNTS[0])
                    .balance(Word::from(10u64.pow(19)))
                    .code(code)
                    .storage(vec![(0x00u64.into(), 0x6fu64.into())].into_iter());
                accs[1]
                    .address(MOCK_ACCOUNTS[1])
                    .balance(Word::from(10u64.pow(19)));
            },
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
            .rev() // find last tstore
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::TSTORE))
            .unwrap();

        assert_eq!(
            [0, 1, 2, 3, 4]
                .map(|idx| &builder.block.container.call_context
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &CallContextOp::new(1, CallContextField::TxId, Word::from(0x01)),
                ),
                (
                    RW::READ,
                    &CallContextOp::new(1, CallContextField::IsStatic, Word::from(0x00)),
                ),
                (
                    RW::READ,
                    &CallContextOp::new(
                        1,
                        CallContextField::RwCounterEndOfReversion,
                        Word::from(0x00)
                    ),
                ),
                (
                    RW::READ,
                    &CallContextOp::new(1, CallContextField::IsPersistent, Word::from(0x01)),
                ),
                (
                    RW::READ,
                    &CallContextOp::new(
                        1,
                        CallContextField::CalleeAddress,
                        MOCK_ACCOUNTS[0].to_word(),
                    ),
                ),
            ]
        );

        assert_eq!(
            [5, 6]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1022), Word::from(0x0u32))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0x6fu32))
                ),
            ]
        );

        let storage_op =
            &builder.block.container.transient_storage[step.bus_mapping_instance[7].as_usize()];
        assert_eq!(
            (storage_op.rw(), storage_op.op()),
            (
                RW::WRITE,
                &TransientStorageOp::new(
                    MOCK_ACCOUNTS[0],
                    Word::from(0x0u32),
                    Word::from(0x6fu32),
                    Word::from(expected_prev_value),
                    1,
                )
            )
        );
    }
}
