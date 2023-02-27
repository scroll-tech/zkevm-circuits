use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::error::ExecError;
use crate::evm::Opcode;
use crate::operation::CallContextField;
use crate::Error;
use eth_types::{GethExecStep, Word};

#[derive(Debug, Copy, Clone)]
pub(crate) struct ErrorReturnDataOutOfBound;

impl Opcode for ErrorReturnDataOutOfBound {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        let next_step = geth_steps.get(1);

        exec_step.error = Some(ExecError::ReturnDataOutOfBounds);
        assert_eq!(
            state.get_step_err(geth_step, next_step).unwrap(),
            Some(ExecError::ReturnDataOutOfBounds)
        );

        let memory_offset = geth_step.stack.nth_last(0)?;
        let data_offset = geth_step.stack.nth_last(1)?;
        let length = geth_step.stack.nth_last(2)?;

        state.stack_read(
            &mut exec_step,
            geth_step.stack.nth_last_filled(0),
            memory_offset,
        )?;
        state.stack_read(
            &mut exec_step,
            geth_step.stack.nth_last_filled(1),
            data_offset,
        )?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(2), length)?;

        let call_id = state.call()?.call_id;
        let call_ctx = state.call_ctx()?;
        let return_data = &call_ctx.return_data;
        let last_callee_return_data_length = state.call()?.last_callee_return_data_length;
        assert_eq!(
            last_callee_return_data_length as usize,
            return_data.len(),
            "callee return data size should be correct"
        );

        let end = data_offset + length;
        // check data_offset or end is u64 overflow, or
        // last_callee_return_data_length < end
        let data_offset_overflow = data_offset > Word::from(u64::MAX);
        let end_overflow = end > Word::from(u64::MAX);
        let end_exceed_length = Word::from(last_callee_return_data_length) < end;
        // one of three must hold at least one.
        assert!(data_offset_overflow | end_overflow | end_exceed_length);
        // read last callee info
        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::LastCalleeReturnDataLength,
            return_data.len().into(),
        );

        // `IsSuccess` call context operation is added in gen_restore_context_ops

        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;
        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_input_builder::ExecState;
    use crate::mock::BlockData;
    use crate::operation::RW;
    use eth_types::evm_types::OpcodeId;
    use eth_types::geth_types::GethData;
    use eth_types::{bytecode, word};
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;

    #[test]
    fn test_returndata_error() {
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000F3600052600C6014F3"))
            PUSH1(0)
            MSTORE

            PUSH1 (0x15) // size
            PUSH1 (0xB) // offset
            PUSH1 (0)   // value
            CREATE

            PUSH1 (0x20)   // retLength
            PUSH1 (0x20)   // retOffset
            PUSH1 (0x20)   // argsLength
            PUSH1 (0)      // argsOffset
            PUSH1 (0)      // value
            DUP6           // addr from above CREATE
            PUSH2 (0xFFFF) // gas
            CALL

            PUSH1 (0x40) // 0x40 > 0x20 (which return from above CALL), result in ReturnDataOutOfBounds
            PUSH1 (0)
            PUSH1 (0x40)
            RETURNDATACOPY

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

        let tx_id = 1;
        let transaction = &builder.block.txs()[tx_id - 1];
        let step = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::RETURNDATACOPY))
            .last()
            .unwrap();

        assert_eq!(step.error, Some(ExecError::ReturnDataOutOfBounds));

        let container = builder.block.container.clone();
        let operation = &container.stack[step.bus_mapping_instance[0].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
    }
}
