use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyBytes, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
    },
    evm::Opcode,
    operation::CallContextField,
    Error,
};
use eth_types::GethExecStep;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Returndatacopy;

impl Opcode for Returndatacopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_steps = vec![gen_returndatacopy_step(state, geth_step)?];

        let copy_event = gen_copy_event(state, geth_step, &mut exec_steps[0])?;
        state.push_copy(&mut exec_steps[0], copy_event);
        Ok(exec_steps)
    }
}

fn gen_returndatacopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;
    let memory_offset = geth_step.stack.last()?;
    let data_offset = geth_step.stack.nth_last(1)?;
    let length = geth_step.stack.nth_last(2)?;

    state.stack_read(&mut exec_step, geth_step.stack.last_filled(), memory_offset)?;
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(1),
        data_offset,
    )?;
    state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(2), length)?;

    let call_id = state.call()?.call_id;
    let call_ctx = state.call_ctx()?;
    let return_data_len = call_ctx.return_data.len();
    let last_callee_id = state.call()?.last_callee_id;
    let last_callee_return_data_offset = state.call()?.last_callee_return_data_offset;
    let last_callee_return_data_length = state.call()?.last_callee_return_data_length;

    assert_eq!(
        last_callee_return_data_length as usize, return_data_len,
        "callee return data size should be correct"
    );

    // read last callee info
    for (field, value) in [
        (CallContextField::LastCalleeId, last_callee_id.into()),
        (
            CallContextField::LastCalleeReturnDataOffset,
            if return_data_len == 0 {
                0.into()
            } else {
                last_callee_return_data_offset.into()
            },
        ),
        (
            CallContextField::LastCalleeReturnDataLength,
            return_data_len.into(),
        ),
    ] {
        state.call_context_read(&mut exec_step, call_id, field, value)?;
    }
    Ok(exec_step)
}

fn gen_copy_event(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
    exec_step: &mut ExecStep,
) -> Result<CopyEvent, Error> {
    let rw_counter_start = state.block_ctx.rwc;

    // Get low Uint64 of offset.
    let dst_addr = geth_step.stack.last()?;
    let data_offset = geth_step.stack.nth_last(1)?;
    let length = geth_step.stack.nth_last(2)?;

    let (dst_addr, data_offset, length) =
        (dst_addr.low_u64(), data_offset.as_u64(), length.as_u64());

    let last_callee_return_data_offset = state.call()?.last_callee_return_data_offset;
    let last_callee_return_data_length = state.call()?.last_callee_return_data_length;
    let (src_addr, src_addr_end) = (
        last_callee_return_data_offset + data_offset,
        last_callee_return_data_offset + last_callee_return_data_length,
    );

    let (read_steps, write_steps, prev_bytes) =
        state.gen_copy_steps_for_return_data(exec_step, src_addr, dst_addr, length)?;

    Ok(CopyEvent {
        src_type: CopyDataType::Memory,
        src_id: NumberOrHash::Number(state.call()?.last_callee_id),
        src_addr,
        src_addr_end,
        dst_type: CopyDataType::Memory,
        dst_id: NumberOrHash::Number(state.call()?.call_id),
        dst_addr,
        log_id: None,
        rw_counter_start,
        copy_bytes: CopyBytes::new(read_steps, Some(write_steps), Some(prev_bytes)),
    })
}

#[cfg(test)]
mod return_tests {
    use crate::mock::BlockData;
    use eth_types::{bytecode, geth_types::GethData};
    use mock::{
        test_ctx::{
            helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
            LoggerConfig,
        },
        TestContext, MOCK_DEPLOYED_CONTRACT_BYTECODE,
    };

    #[test]
    fn test_ok() {
        let code = bytecode! {
            PUSH21(*MOCK_DEPLOYED_CONTRACT_BYTECODE)
            PUSH1(0)
            MSTORE

            PUSH1 (0x15)
            PUSH1 (0xB)
            PUSH1 (0)
            CREATE

            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0)
            DUP6
            PUSH2 (0xFFFF)
            CALL

            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0x40)
            RETURNDATACOPY

            STOP
        };
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new_with_logger_config(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
            LoggerConfig::default(),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }
}
