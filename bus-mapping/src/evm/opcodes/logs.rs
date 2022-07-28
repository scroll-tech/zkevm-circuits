use super::Opcode;
use crate::operation::{CallContextField, TxLogField};
use crate::Error;
use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyDetails, ExecState, ExecStep, StepAuxiliaryData,
    },
    constants::MAX_COPY_BYTES,
};
use eth_types::evm_types::{MemoryAddress, OpcodeId};
use eth_types::Word;
use eth_types::{GethExecStep, ToBigEndian, ToWord};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Log;

impl Opcode for Log {
    fn gen_associated_ops(
        &self,
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_steps = vec![gen_log_step(state, geth_step)?];
        let log_copy_steps = gen_log_copy_steps(state, geth_steps)?;
        exec_steps.extend(log_copy_steps);

        // reconstruction
        let offset = geth_step.stack.nth_last(0)?.as_usize();
        let length = geth_step.stack.nth_last(1)?.as_usize();

        if length != 0 {
            state
                .call_ctx_mut()?
                .memory
                .extend_at_least(offset + length);
        }

        Ok(exec_steps)
    }
}

fn gen_log_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;

    let mstart = geth_step.stack.nth_last(0)?;
    let msize = geth_step.stack.nth_last(1)?;

    let call_id = state.call()?.call_id;
    let mut stack_index = 0;
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(stack_index),
        mstart,
    )?;
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(stack_index + 1),
        msize,
    )?;

    stack_index += 1;

    state.call_context_read(
        &mut exec_step,
        call_id,
        CallContextField::TxId,
        state.tx_ctx.id().into(),
    );
    state.call_context_read(
        &mut exec_step,
        call_id,
        CallContextField::IsStatic,
        Word::from(state.call()?.is_static as u8),
    );
    state.call_context_read(
        &mut exec_step,
        call_id,
        CallContextField::CalleeAddress,
        state.call()?.address.to_word(),
    );
    state.call_context_read(
        &mut exec_step,
        call_id,
        CallContextField::IsPersistent,
        Word::from(state.call()?.is_persistent as u8),
    );

    let log_id = exec_step.log_id;
    if state.call()?.is_persistent {
        state.tx_log_write(
            &mut exec_step,
            state.tx_ctx.id(),
            log_id + 1,
            TxLogField::Address,
            0,
            state.call()?.address.to_word(),
        )?;
    }

    // generates topic operation dynamically
    let topic_count = match exec_step.exec_state {
        ExecState::Op(op_id) => (op_id.as_u8() - OpcodeId::LOG0.as_u8()) as usize,
        _ => panic!("currently only handle succeful log state"),
    };

    for i in 0..topic_count {
        let topic = geth_step.stack.nth_last(2 + i)?;
        state.stack_read(
            &mut exec_step,
            geth_step.stack.nth_last_filled(stack_index + 1),
            topic,
        )?;
        stack_index += 1;

        if state.call()?.is_persistent {
            state.tx_log_write(
                &mut exec_step,
                state.tx_ctx.id(),
                log_id + 1,
                TxLogField::Topic,
                i,
                topic,
            )?;
        }
    }

    Ok(exec_step)
}

fn gen_log_copy_step(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    src_addr: u64,
    src_addr_end: u64,
    bytes_left: usize,
    data_start_index: usize,
) -> Result<(), Error> {
    // Get memory data
    let memory_address: MemoryAddress = Word::from(src_addr).try_into()?;
    let mem_read_value = state
        .call_ctx()?
        .memory
        .read_word(memory_address)
        .to_be_bytes();

    let data_end_index = std::cmp::min(bytes_left, MAX_COPY_BYTES);
    for (idx, _) in mem_read_value.iter().enumerate().take(data_end_index) {
        let addr = src_addr + idx as u64;
        let byte = if addr < src_addr_end {
            let byte = mem_read_value[idx];
            state.memory_read(exec_step, (addr as usize).into(), byte)?;
            byte
        } else {
            0
        };
        // write to tx log if persistent
        let log_id = exec_step.log_id;
        if state.call()?.is_persistent {
            state.tx_log_write(
                exec_step,
                state.tx_ctx.id(),
                log_id,
                TxLogField::Data,
                data_start_index + idx,
                Word::from(byte),
            )?;
        }
    }

    exec_step.aux_data = Some(StepAuxiliaryData::new(
        src_addr,
        0u64,
        bytes_left as u64,
        src_addr_end,
        CopyDetails::Log((
            state.call()?.is_persistent,
            state.tx_ctx.id(),
            data_start_index,
        )),
    ));

    Ok(())
}

fn gen_log_copy_steps(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let memory_start = geth_steps[0].stack.nth_last(0)?.as_u64();
    let msize = geth_steps[0].stack.nth_last(1)?.as_usize();

    let (src_addr, buffer_addr_end) = (memory_start, memory_start + msize as u64);

    let mut copied = 0;
    let mut steps = vec![];
    while copied < msize {
        let mut exec_step = state.new_step(&geth_steps[1])?;
        exec_step.log_id += 1;

        exec_step.exec_state = ExecState::CopyToLog;
        gen_log_copy_step(
            state,
            &mut exec_step,
            src_addr + copied as u64,
            buffer_addr_end,
            msize - copied,
            copied,
        )?;
        steps.push(exec_step);
        copied += MAX_COPY_BYTES;
    }

    Ok(steps)
}

#[cfg(test)]
mod log_tests {
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{CallContextField, CallContextOp, MemoryOp, StackOp, TxLogField, TxLogOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        Bytecode, ToWord, Word,
    };

    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn logs_opcode_ok() {
        // zero topics
        test_logs_opcode(&[]);
        // one topics
        test_logs_opcode(&[Word::from(0xA0)]);
        // two topics
        test_logs_opcode(&[Word::from(0xA0), Word::from(0xef)]);
        // three topics
        test_logs_opcode(&[Word::from(0xA0), Word::from(0xef), Word::from(0xb0)]);
        // four topics
        test_logs_opcode(&[
            Word::from(0xA0),
            Word::from(0xef),
            Word::from(0xb0),
            Word::from(0x37),
        ]);
    }

    fn test_logs_opcode(topics: &[Word]) {
        let log_codes = [
            OpcodeId::LOG0,
            OpcodeId::LOG1,
            OpcodeId::LOG2,
            OpcodeId::LOG3,
            OpcodeId::LOG4,
        ];

        let topic_count = topics.len();
        let cur_op_code = log_codes[topic_count];

        let mstart = 0x00usize;
        let msize = 0x40usize;
        let mut code = Bytecode::default();
        // make dynamic topics push operations
        for topic in topics {
            code.push(32, *topic);
        }

        code.push(32, Word::from(msize));
        code.push(32, Word::from(mstart));
        code.write_op(cur_op_code);
        code.write_op(OpcodeId::STOP);

        // prepare memory data
        let pushdata = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let mut memory_data = std::iter::repeat(0)
            .take(16)
            .chain(pushdata.clone())
            .collect::<Vec<u8>>();
        // construct 64 bytes
        memory_data.append(&mut memory_data.clone());

        let mut code_prepare: Bytecode = bytecode! {
            // populate memory.
            PUSH16(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            PUSH16(Word::from_big_endian(&pushdata))
            PUSH1(0x20) // offset
            MSTORE
        };

        code_prepare.append(&code);

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code_prepare),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let is_persistent = builder.block.txs()[0].calls()[0].is_persistent;
        let callee_address = builder.block.txs()[0].to;

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(cur_op_code))
            .unwrap();

        assert_eq!(
            [0, 1]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from((1022 - topic_count) as u32), Word::from(mstart))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from((1023 - topic_count) as u32), Word::from(msize))
                )
            ]
        );

        // assert call context is right
        assert_eq!(
            [2, 3, 4, 5]
                .map(|idx| &builder.block.container.call_context
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: 1,
                        field: CallContextField::TxId,
                        value: Word::from(1),
                    },
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: 1,
                        field: CallContextField::IsStatic,
                        value: Word::from(0),
                    },
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: 1,
                        field: CallContextField::CalleeAddress,
                        value: callee_address.to_word(),
                    },
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id: 1,
                        field: CallContextField::IsPersistent,
                        value: Word::from(1),
                    },
                ),
            ]
        );

        // TODO: handle is_persistent = false conditions
        if is_persistent {
            assert_eq!(
                [6].map(|idx| &builder.block.container.tx_log
                    [step.bus_mapping_instance[idx].as_usize()])
                    .map(|operation| (operation.rw(), operation.op())),
                [(
                    RW::WRITE,
                    &TxLogOp {
                        tx_id: 1,
                        log_id: step.log_id + 1,
                        field: TxLogField::Address,
                        index: 0,
                        value: callee_address.to_word(),
                    }
                ),]
            );
        }
        // memory reads.
        let mut log_data_ops = Vec::with_capacity(msize);
        assert_eq!(
            // skip first 32 writes of MSTORE ops
            (mstart + 64..(mstart + 64 + msize))
                .map(|idx| &builder.block.container.memory[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryOp)>>(),
            {
                let mut memory_ops = Vec::with_capacity(msize);
                (mstart..msize).for_each(|idx| {
                    memory_ops.push((
                        RW::READ,
                        MemoryOp::new(1, (mstart + idx).into(), memory_data[mstart + idx]),
                    ));
                    // tx log addition
                    log_data_ops.push((
                        RW::WRITE,
                        TxLogOp::new(
                            1,
                            step.log_id + 1, // because it is in next CopyToLog step
                            TxLogField::Data,
                            idx - mstart,
                            Word::from(memory_data[mstart + idx]),
                        ),
                    ));
                });

                memory_ops
            },
        );

        // log topic writes
        let mut log_topic_ops = Vec::with_capacity(topic_count);
        for (idx, topic) in topics.iter().rev().enumerate() {
            log_topic_ops.push((
                RW::WRITE,
                TxLogOp::new(1, step.log_id + 1, TxLogField::Topic, idx, *topic),
            ));
        }

        assert_eq!(
            (1..1 + topic_count)
                .map(|idx| &builder.block.container.tx_log[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, TxLogOp)>>(),
            { log_topic_ops },
        );

        // log data writes
        assert_eq!(
            ((1 + topic_count)..msize + 1 + topic_count)
                .map(|idx| &builder.block.container.tx_log[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, TxLogOp)>>(),
            { log_data_ops },
        );
    }
}
