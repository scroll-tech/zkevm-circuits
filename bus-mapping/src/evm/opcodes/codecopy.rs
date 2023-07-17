use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyBytes, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
    },
    Error,
};
use eth_types::{Bytecode, GethExecStep};

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Codecopy;

impl Opcode for Codecopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_steps = vec![gen_codecopy_step(state, geth_step)?];

        let copy_event = gen_copy_event(state, geth_step, &mut exec_steps[0])?;
        state.push_copy(&mut exec_steps[0], copy_event);
        Ok(exec_steps)
    }
}

fn gen_codecopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;

    let dest_offset = geth_step.stack.nth_last(0)?;
    let code_offset = geth_step.stack.nth_last(1)?;
    let length = geth_step.stack.nth_last(2)?;

    // stack reads
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(0),
        dest_offset,
    )?;
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(1),
        code_offset,
    )?;
    state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(2), length)?;

    Ok(exec_step)
}

fn gen_copy_event(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
    exec_step: &mut ExecStep,
) -> Result<CopyEvent, Error> {
    let rw_counter_start = state.block_ctx.rwc;

    let dst_offset = geth_step.stack.nth_last(0)?;
    let code_offset = geth_step.stack.nth_last(1)?;
    let length = geth_step.stack.nth_last(2)?.as_u64();

    let code_hash = state.call()?.code_hash;
    let bytecode: Bytecode = state.code(code_hash)?.into();
    let code_size = bytecode.code.len() as u64;

    // Get low Uint64 of offset.
    let dst_addr = dst_offset.low_u64();
    let src_addr_end = code_size;

    // Reset offset to Uint64 maximum value if overflow, and set source start to the
    // minimum value of offset and code size.
    let src_addr = u64::try_from(code_offset)
        .unwrap_or(u64::MAX)
        .min(src_addr_end);

    let (copy_steps, prev_bytes) =
        state.gen_copy_steps_for_bytecode(exec_step, &bytecode, src_addr, dst_addr, length)?;

    Ok(CopyEvent {
        src_type: CopyDataType::Bytecode,
        src_id: NumberOrHash::Hash(code_hash),
        src_addr,
        src_addr_end,
        dst_type: CopyDataType::Memory,
        dst_id: NumberOrHash::Number(state.call()?.call_id),
        dst_addr,
        log_id: None,
        rw_counter_start,
        //fetch pre write bytes of CopyBytes
        copy_bytes: CopyBytes::new(copy_steps, None, Some(prev_bytes)),
    })
}

#[cfg(test)]
mod codecopy_tests {
    use eth_types::{
        bytecode,
        evm_types::{MemoryAddress, OpcodeId, StackAddress},
        geth_types::GethData,
        Word,
    };
    use mock::{
        test_ctx::{
            helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
            LoggerConfig,
        },
        TestContext,
    };

    use crate::{
        circuit_input_builder::{CopyDataType, ExecState, NumberOrHash},
        mock::BlockData,
        operation::{MemoryOp, StackOp, RW},
        state_db::CodeDB,
    };

    #[test]
    fn codecopy_opcode_impl() {
        test_ok(0x00, 0x00, 0x40);
        test_ok(0x20, 0x40, 0xA0);
    }

    fn test_ok(memory_offset: usize, code_offset: usize, copy_size: usize) {
        let code = bytecode! {
            PUSH32(copy_size)
            PUSH32(code_offset)
            PUSH32(memory_offset)
            CODECOPY
            STOP
        };

        let block: GethData = TestContext::<2, 1>::new_with_logger_config(
            None,
            account_0_code_account_1_no_code(code.clone()),
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

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CODECOPY))
            .unwrap();

        let expected_call_id = builder.block.txs()[0].calls()[step.call_index].call_id;

        assert_eq!(
            [0, 1, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|op| (op.rw(), op.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1021), Word::from(memory_offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1022), Word::from(code_offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(copy_size)),
                ),
            ]
        );

        // add RW table memory word writes.
        let length = memory_offset + copy_size;
        let copy_start = memory_offset - memory_offset % 32;
        let copy_end = length - length % 32;
        let word_ops = (copy_end + 32 - copy_start) / 32 - 1;
        let copied_bytes = builder.block.copy_events[0]
            .copy_bytes
            .bytes
            .iter()
            .map(|(b, _, _)| *b)
            .collect::<Vec<_>>();
        let prev_bytes = builder.block.copy_events[0]
            .copy_bytes
            .bytes_write_prev
            .clone()
            .unwrap();

        assert_eq!(builder.block.container.memory.len(), word_ops);
        assert_eq!(
            (0..word_ops)
                .map(|idx| &builder.block.container.memory[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryOp)>>(),
            (0..word_ops)
                .map(|idx| {
                    (
                        RW::WRITE,
                        MemoryOp::new_write(
                            expected_call_id,
                            MemoryAddress(copy_start + idx * 32),
                            Word::from(&copied_bytes[idx * 32..(idx + 1) * 32]),
                            // get previous value
                            Word::from(&prev_bytes[idx * 32..(idx + 1) * 32]),
                        ),
                    )
                })
                .collect::<Vec<(RW, MemoryOp)>>(),
        );

        let copy_events = builder.block.copy_events.clone();
        assert_eq!(copy_events.len(), 1);
        assert_eq!(
            copy_events[0].src_id,
            NumberOrHash::Hash(CodeDB::hash(&code.to_vec()))
        );
        assert_eq!(copy_events[0].src_addr as usize, code_offset);
        assert_eq!(copy_events[0].src_addr_end as usize, code.to_vec().len());
        assert_eq!(copy_events[0].src_type, CopyDataType::Bytecode);
        assert_eq!(
            copy_events[0].dst_id,
            NumberOrHash::Number(expected_call_id)
        );
        assert_eq!(copy_events[0].dst_addr as usize, memory_offset);
        assert_eq!(copy_events[0].dst_type, CopyDataType::Memory);
        assert!(copy_events[0].log_id.is_none());

        for (idx, (value, is_code, is_mask)) in copy_events[0].copy_bytes.bytes.iter().enumerate() {
            let bytecode_element = code.get(code_offset + idx).unwrap_or_default();
            if !is_mask {
                assert_eq!(*value, bytecode_element.value);
                assert_eq!(*is_code, bytecode_element.is_code);
            }
        }
    }
}
