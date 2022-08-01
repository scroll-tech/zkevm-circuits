use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecState, ExecStep};
use crate::circuit_input_builder::{CopyDataType, CopyEvent, CopyStep, NumberOrHash};
use crate::operation::{CallContextField, TxLogField, RW};
use crate::Error;
use eth_types::evm_types::OpcodeId;
use eth_types::Word;
use eth_types::{GethExecStep, ToWord};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Log;

impl Opcode for Log {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = gen_log_step(state, geth_step)?;
        if state.call()?.is_persistent {
            let copy_event = gen_copy_event(state, geth_step, &mut exec_step)?;
            state.push_copy(copy_event);
            state.tx_ctx.log_id += 1;
        }
        // reconstruction
        let offset = geth_step.stack.nth_last(0)?.as_usize();
        let length = geth_step.stack.nth_last(1)?.as_usize();

        if length != 0 {
            state
                .call_ctx_mut()?
                .memory
                .extend_at_least(offset + length);
        }
        Ok(vec![exec_step])
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

    if state.call()?.is_persistent {
        state.tx_log_write(
            &mut exec_step,
            state.tx_ctx.id(),
            state.tx_ctx.log_id + 1,
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
                state.tx_ctx.log_id + 1,
                TxLogField::Topic,
                i,
                topic,
            )?;
        }
    }

    Ok(exec_step)
}

fn gen_copy_steps(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    src_addr: u64,
    src_addr_end: u64,
    bytes_left: usize,
    data_start_index: usize,
) -> Result<Vec<CopyStep>, Error> {
    // Get memory data
    let mem = state
        .call_ctx()?
        .memory
        .read_chunk(src_addr.into(), bytes_left.into());

    let mut copy_steps = Vec::with_capacity(2 * bytes_left);
    for (idx, byte) in mem.iter().enumerate() {
        let addr = src_addr + idx as u64;
        let rwc = state.block_ctx.rwc;
        let (value, is_pad) = if addr < src_addr_end {
            state.memory_read(exec_step, (addr as usize).into(), *byte)?;
            (*byte, false)
        } else {
            (0, true)
        };

        // Read
        copy_steps.push(CopyStep {
            addr,
            tag: CopyDataType::Memory,
            rw: RW::READ,
            value,
            is_code: None,
            is_pad,
            rwc,
            rwc_inc_left: 0,
        });
        // Write
        copy_steps.push(CopyStep {
            addr: (data_start_index + idx) as u64,
            tag: CopyDataType::TxLog,
            rw: RW::WRITE,
            value,
            is_code: None,
            is_pad: false,
            rwc: state.block_ctx.rwc,
            rwc_inc_left: 0,
        });
        state.tx_log_write(
            exec_step,
            state.tx_ctx.id(),
            state.tx_ctx.log_id + 1,
            TxLogField::Data,
            data_start_index + idx,
            Word::from(value),
        )?;
    }

    Ok(copy_steps)
}

fn gen_copy_event(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
    exec_step: &mut ExecStep,
) -> Result<CopyEvent, Error> {
    assert!(state.call()?.is_persistent, "Error: Call is not persistent");
    let memory_start = geth_step.stack.nth_last(0)?.as_u64();
    let msize = geth_step.stack.nth_last(1)?.as_usize();

    let (src_addr, src_addr_end) = (memory_start, memory_start + msize as u64);

    let mut steps = gen_copy_steps(state, exec_step, src_addr, src_addr_end, msize, 0)?;

    for cs in steps.iter_mut() {
        cs.rwc_inc_left = state.block_ctx.rwc.0 as u64 - cs.rwc.0 as u64;
    }

    Ok(CopyEvent {
        src_type: CopyDataType::Memory,
        src_id: NumberOrHash::Number(state.call()?.call_id),
        src_addr,
        src_addr_end,
        dst_type: CopyDataType::TxLog,
        dst_id: NumberOrHash::Number(state.tx_ctx.id()),
        dst_addr: 0,
        log_id: Some(state.tx_ctx.log_id as u64 + 1),
        length: msize as u64,
        steps,
        tx_id: state.tx_ctx.id(),
        call_id: state.call()?.call_id,
        pc: exec_step.pc,
    })
}

#[cfg(test)]
mod log_tests {
    use crate::{
        circuit_input_builder::{CopyDataType, CopyStep, ExecState, NumberOrHash},
        mock::BlockData,
        operation::{
            CallContextField, CallContextOp, MemoryOp, RWCounter, StackOp, TxLogField, TxLogOp, RW,
        },
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

        let expected_call_id = builder.block.txs()[0].calls()[step.call_index].call_id;

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
        assert_eq!(
            ((1 + topic_count)..msize + 1 + topic_count)
                .map(|idx| &builder.block.container.tx_log[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, TxLogOp)>>(),
            { log_data_ops },
        );

        let copy_events = builder.block.copy_events.clone();
        assert_eq!(copy_events.len(), 1);
        assert_eq!(copy_events[0].steps.len(), 2 * msize);
        assert_eq!(copy_events[0].src_type, CopyDataType::Memory);
        assert_eq!(
            copy_events[0].src_id,
            NumberOrHash::Number(expected_call_id)
        );
        assert_eq!(copy_events[0].src_addr as usize, mstart);
        assert_eq!(copy_events[0].src_addr_end as usize, mstart + msize);
        assert_eq!(copy_events[0].dst_type, CopyDataType::TxLog);
        assert_eq!(copy_events[0].dst_id, NumberOrHash::Number(1)); // tx_id
        assert_eq!(copy_events[0].dst_addr as usize, 0);
        assert_eq!(copy_events[0].length as usize, msize);
        assert_eq!(copy_events[0].log_id, Some(step.log_id as u64 + 1));

        let mut rwc = RWCounter(
            step.rwc.0 + // start of rwc
            6 + // 2 stack reads + 4 call context reads
            1 + // TxLogField::Address write
            topic_count + // stack read for topics
            topic_count,
        ); // TxLogField::Topic write
        let mut rwc_inc = copy_events[0].steps.first().unwrap().rwc_inc_left;
        for (idx, copy_rw_pair) in copy_events[0].steps.chunks(2).enumerate() {
            assert_eq!(copy_rw_pair.len(), 2);
            let (value, is_pad) = memory_data
                .get(mstart + idx)
                .cloned()
                .map_or((0, true), |v| (v, false));
            // Read
            let read_step = copy_rw_pair[0].clone();
            assert_eq!(
                read_step,
                CopyStep {
                    addr: (mstart + idx) as u64,
                    rw: RW::READ,
                    tag: CopyDataType::Memory,
                    value,
                    is_code: None,
                    is_pad,
                    rwc: if !is_pad { rwc.inc_pre() } else { rwc },
                    rwc_inc_left: rwc_inc,
                }
            );
            if !is_pad {
                rwc_inc -= 1;
            }
            // Write
            let write_step = copy_rw_pair[1].clone();
            assert_eq!(
                write_step,
                CopyStep {
                    addr: idx as u64,
                    rw: RW::WRITE,
                    tag: CopyDataType::TxLog,
                    value,
                    is_code: None,
                    is_pad: false,
                    rwc: rwc.inc_pre(),
                    rwc_inc_left: rwc_inc,
                }
            );
            rwc_inc -= 1;
        }
    }
}
