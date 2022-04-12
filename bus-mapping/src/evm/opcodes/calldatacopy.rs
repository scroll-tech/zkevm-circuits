use super::Opcode;
use crate::operation::{CallContextField, CallContextOp, MemoryOp, RW};
use crate::Error;
use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyToMemoryAuxData, ExecState, ExecStep, StepAuxiliaryData,
    },
    constants::MAX_COPY_BYTES,
};
use eth_types::GethExecStep;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Calldatacopy;

impl Opcode for Calldatacopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_steps = vec![gen_calldatacopy_step(state, geth_step)?];
        let memory_copy_steps = gen_memory_copy_steps(state, geth_steps)?;
        exec_steps.extend(memory_copy_steps);
        Ok(exec_steps)
    }
}

fn gen_calldatacopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;
    let memory_offset = geth_step.stack.nth_last(0)?;
    let data_offset = geth_step.stack.nth_last(1)?;
    let length = geth_step.stack.nth_last(2)?;

    state.push_stack_op(
        &mut exec_step,
        RW::READ,
        geth_step.stack.nth_last_filled(0),
        memory_offset,
    )?;
    state.push_stack_op(
        &mut exec_step,
        RW::READ,
        geth_step.stack.nth_last_filled(1),
        data_offset,
    )?;
    state.push_stack_op(
        &mut exec_step,
        RW::READ,
        geth_step.stack.nth_last_filled(2),
        length,
    )?;

    if state.call()?.is_root {
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::TxId,
                value: state.tx_ctx.id().into(),
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::CallDataLength,
                value: state.call()?.call_data_length.into(),
            },
        );
    } else {
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::CallerId,
                value: state.call()?.caller_id.into(),
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::CallDataLength,
                value: state.call()?.call_data_length.into(),
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::CallDataOffset,
                value: state.call()?.call_data_offset.into(),
            },
        );
    };

    Ok(exec_step)
}

fn gen_memory_copy_step(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    src_addr: u64,
    dst_addr: u64,
    src_addr_end: u64,
    bytes_left: usize,
    is_root: bool,
) -> Result<(), Error> {
    for idx in 0..std::cmp::min(bytes_left, MAX_COPY_BYTES) {
        let addr = src_addr + idx as u64;
        let byte = if addr < src_addr_end {
            let byte =
                state.call_ctx()?.call_data[(addr - state.call()?.call_data_offset) as usize];
            if !is_root {
                state.push_op(
                    exec_step,
                    RW::READ,
                    MemoryOp::new(state.call()?.caller_id, (addr as usize).into(), byte),
                );
            }
            byte
        } else {
            0
        };
        state.push_memory_op(exec_step, RW::WRITE, (idx + dst_addr as usize).into(), byte)?;
    }

    exec_step.aux_data = Some(StepAuxiliaryData::CopyToMemory(CopyToMemoryAuxData {
        src_addr,
        dst_addr,
        bytes_left: bytes_left as u64,
        src_addr_end,
        from_tx: is_root,
    }));

    Ok(())
}

fn gen_memory_copy_steps(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let memory_offset = geth_steps[0].stack.nth_last(0)?.as_u64();
    let data_offset = geth_steps[0].stack.nth_last(1)?.as_u64();
    let length = geth_steps[0].stack.nth_last(2)?.as_usize();

    let call_data_offset = state.call()?.call_data_offset;
    let call_data_length = state.call()?.call_data_length;
    let (src_addr, buffer_addr_end) = (
        call_data_offset + data_offset,
        call_data_offset + call_data_length,
    );

    let mut copied = 0;
    let mut steps = vec![];
    while copied < length {
        let mut exec_step = state.new_step(&geth_steps[1])?;
        exec_step.exec_state = ExecState::CopyToMemory;
        gen_memory_copy_step(
            state,
            &mut exec_step,
            src_addr + copied as u64,
            memory_offset + copied as u64,
            buffer_addr_end,
            length - copied,
            state.call()?.is_root,
        )?;
        steps.push(exec_step);
        copied += MAX_COPY_BYTES;
    }

    Ok(steps)
}

#[cfg(test)]
mod calldatacopy_tests {
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{CallContextField, CallContextOp, MemoryOp, StackOp, RW},
    };
    use eth_types::{
        address, bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        Address, ToWord, Word,
    };

    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn calldatacopy_opcode_internal() {
        let addr_a = address!("0x000000000000000000000000000000000cafe00a");
        let addr_b = address!("0x000000000000000000000000000000000cafe00b");

        // code B gets called by code A, so the call is an internal call.
        let dst_offset = 0x00usize;
        let offset = 0x00usize;
        let copy_size = 0x10usize;
        let code_b = bytecode! {
            PUSH32(copy_size)  // size
            PUSH32(offset)     // offset
            PUSH32(dst_offset) // dst_offset
            CALLDATACOPY
            STOP
        };

        // code A calls code B.
        let pushdata = hex::decode("1234567890abcdef").unwrap();
        let memory_a = std::iter::repeat(0)
            .take(24)
            .chain(pushdata.clone())
            .collect::<Vec<u8>>();
        let call_data_length = 0x20usize;
        let call_data_offset = 0x10usize;
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call addr_b.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH1(call_data_length) // argsLength
            PUSH1(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(Address::random())
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[2].address);
            },
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CALLDATACOPY))
            .unwrap();

        let caller_id = builder.block.txs()[0].calls()[step.call_index].caller_id;
        let expected_call_id = builder.block.txs()[0].calls()[step.call_index].call_id;

        // 3 stack reads + 3 call context reads.
        assert_eq!(step.bus_mapping_instance.len(), 6);

        // 3 stack reads.
        assert_eq!(
            [0, 1, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1021), Word::from(dst_offset))
                ),
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1022), Word::from(offset))
                ),
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1023), Word::from(copy_size))
                ),
            ]
        );

        // 3 call context reads.
        assert_eq!(
            [3, 4, 5]
                .map(|idx| &builder.block.container.call_context
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: expected_call_id,
                        field: CallContextField::CallerId,
                        value: Word::from(1),
                    }
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: expected_call_id,
                        field: CallContextField::CallDataLength,
                        value: Word::from(call_data_length),
                    },
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: expected_call_id,
                        field: CallContextField::CallDataOffset,
                        value: Word::from(call_data_offset),
                    },
                ),
            ]
        );

        // memory writes.
        // 1. First `call_data_length` memory ops are RW::WRITE and come from the `CALL`
        // opcode.    (we skip checking those)
        // 2. Following that, we should have tuples of (RW::READ and RW::WRITE) where
        // the caller    memory is read and the current call's memory is written
        // to.
        assert_eq!(
            builder.block.container.memory.len(),
            call_data_length + 2 * copy_size
        );
        assert_eq!(
            (call_data_length..(call_data_length + (2 * copy_size)))
                .map(|idx| &builder.block.container.memory[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryOp)>>(),
            {
                let mut memory_ops = Vec::with_capacity(2 * copy_size);
                (0..copy_size).for_each(|idx| {
                    memory_ops.push((
                        RW::READ,
                        MemoryOp::new(
                            caller_id,
                            (call_data_offset + offset + idx).into(),
                            memory_a[call_data_offset + idx],
                        ),
                    ));
                    memory_ops.push((
                        RW::WRITE,
                        MemoryOp::new(
                            expected_call_id,
                            (dst_offset + idx).into(),
                            memory_a[call_data_offset + idx],
                        ),
                    ));
                });
                memory_ops
            },
        );
    }

    #[test]
    fn calldatacopy_opcode_root() {
        let code = bytecode! {
            PUSH32(0)
            PUSH32(0)
            PUSH32(0x40)
            CALLDATACOPY
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

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CALLDATACOPY))
            .unwrap();

        assert_eq!(step.bus_mapping_instance.len(), 5);

        assert_eq!(
            [0, 1, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1021), Word::from(0x40))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1022), Word::from(0))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0))
                ),
            ]
        );

        assert_eq!(
            [3, 4]
                .map(|idx| &builder.block.container.call_context
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: builder.block.txs()[0].calls()[0].call_id,
                        field: CallContextField::TxId,
                        value: Word::from(1),
                    }
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: builder.block.txs()[0].calls()[0].call_id,
                        field: CallContextField::CallDataLength,
                        value: Word::zero(),
                    },
                ),
            ]
        );
    }
}
