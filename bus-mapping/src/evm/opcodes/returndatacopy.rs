use crate::circuit_input_builder::{
    CircuitInputStateRef, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
};
use crate::evm::Opcode;
use crate::operation::{CallContextField, MemoryOp, RW};
use crate::Error;
use eth_types::GethExecStep;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Returndatacopy;

impl Opcode for Returndatacopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let exec_steps = vec![gen_returndatacopy_step(state, geth_step)?];

        // reconstruction
        let geth_step = &geth_steps[0];
        let dest_offset = geth_step.stack.nth_last(0)?;
        let offset = geth_step.stack.nth_last(1)?;
        let size = geth_step.stack.nth_last(2)?;

        // can we reduce this clone?
        let return_data = state.call_ctx()?.return_data.clone();

        let call_ctx = state.call_ctx_mut()?;
        let memory = &mut call_ctx.memory;
        let length = size.as_usize();
        if length != 0 {
            let mem_starts = dest_offset.as_usize();
            let mem_ends = mem_starts + length;
            let data_starts = offset.as_usize();
            let data_ends = data_starts + length;
            let minimal_length = dest_offset.as_usize() + length;
            if data_ends <= return_data.len() {
                memory.extend_at_least(minimal_length);
                memory[mem_starts..mem_ends].copy_from_slice(&return_data[data_starts..data_ends]);
            } else {
                // if overflows this opcode would fails current context, so
                // there is no more steps.
                if !(geth_steps.len() == 1 || geth_steps[1].depth != geth_steps[0].depth) {
                    log::warn!("read return data overflow, step {:?}", geth_steps[0]);
                    memory.extend_at_least(minimal_length);
                    let mut return_data = return_data[data_starts..].to_vec();
                    return_data.resize(data_ends - data_starts, 0);
                    memory[mem_starts..mem_ends].copy_from_slice(&return_data);
                }
            }
        }

        let copy_event = gen_copy_event(state, geth_step)?;
        state.push_copy(copy_event);
        Ok(exec_steps)
    }
}

fn gen_returndatacopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;
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
    let return_data = call_ctx.return_data.clone();
    let last_callee_id = state.call()?.last_callee_id;
    let last_callee_return_data_offset = state.call()?.last_callee_return_data_offset;
    let last_callee_return_data_length = state.call()?.last_callee_return_data_length;
    assert_eq!(
        last_callee_return_data_length as usize,
        return_data.len(),
        "callee return data size should be correct"
    );

    // read last callee info
    for (field, value) in [
        (CallContextField::LastCalleeId, last_callee_id.into()),
        (
            CallContextField::LastCalleeReturnDataOffset,
            last_callee_return_data_offset.into(),
        ),
        (
            CallContextField::LastCalleeReturnDataLength,
            return_data.len().into(),
        ),
    ] {
        state.call_context_read(&mut exec_step, call_id, field, value);
    }
    Ok(exec_step)
}

fn gen_copy_steps(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    src_addr: u64,
    dst_addr: u64,
    src_addr_end: u64,
    bytes_left: u64,
) -> Result<Vec<(u8, bool)>, Error> {
    let mut copy_steps = Vec::with_capacity(bytes_left as usize);
    let src_addr_base = state.call()?.last_callee_return_data_offset;
    for idx in 0..bytes_left {
        let addr = src_addr + idx;
        let value = if addr < src_addr_end {
            state.call_ctx()?.return_data[(addr - src_addr_base) as usize]
        } else {
            unreachable!("return data copy out of bound")
        };
        // Read
        state.push_op(
            exec_step,
            RW::READ,
            MemoryOp::new(state.call()?.last_callee_id, addr.into(), value),
        );

        // Write
        copy_steps.push((value, false));
        state.memory_write(exec_step, (dst_addr + idx).into(), value)?;
    }
    Ok(copy_steps)
}

fn gen_copy_event(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<CopyEvent, Error> {
    let dst_addr = geth_step.stack.nth_last(0)?.as_u64();
    let data_offset = geth_step.stack.nth_last(1)?.as_u64();
    let length = geth_step.stack.nth_last(2)?.as_u64();

    let last_callee_return_data_offset = state.call()?.last_callee_return_data_offset;
    let last_callee_return_data_length = state.call()?.last_callee_return_data_length;
    let (src_addr, src_addr_end) = (
        last_callee_return_data_offset + data_offset,
        last_callee_return_data_offset + last_callee_return_data_length,
    );

    let rw_counter_start = state.block_ctx.rwc;
    let mut exec_step = state.new_step(geth_step)?;
    let copy_steps = gen_copy_steps(
        state,
        &mut exec_step,
        src_addr,
        dst_addr,
        src_addr_end,
        length,
    )?;

    let (src_type, dst_type, src_id, dst_id) = (
        CopyDataType::Memory,
        CopyDataType::Memory,
        NumberOrHash::Number(state.call()?.last_callee_id),
        NumberOrHash::Number(state.call()?.call_id),
    );

    Ok(CopyEvent {
        src_type,
        src_id,
        src_addr,
        src_addr_end,
        dst_type,
        dst_id,
        dst_addr,
        log_id: None,
        rw_counter_start,
        bytes: copy_steps,
    })
}

#[cfg(test)]
mod return_tests {
    use crate::mock::BlockData;
    use eth_types::geth_types::GethData;
    use eth_types::{bytecode, word};
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;

    #[test]
    fn test_ok() {
        // // deployed contract
        // PUSH1 0x20
        // PUSH1 0
        // PUSH1 0
        // CALLDATACOPY
        // PUSH1 0x20
        // PUSH1 0
        // RETURN
        //
        // bytecode: 0x6020600060003760206000F3
        //
        // // constructor
        // PUSH12 0x6020600060003760206000F3
        // PUSH1 0
        // MSTORE
        // PUSH1 0xC
        // PUSH1 0x14
        // RETURN
        //
        // bytecode: 0x6B6020600060003760206000F3600052600C6014F3
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000F3600052600C6014F3"))
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
    }
}
