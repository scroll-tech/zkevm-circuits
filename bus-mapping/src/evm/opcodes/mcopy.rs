use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyBytes, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
    },
    Error,
};
use eth_types::{Bytecode, GethExecStep, Word};

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct MCopy;

impl Opcode for MCopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let dest_offset = state.stack_pop(&mut exec_step)?;
        let src_offset = state.stack_pop(&mut exec_step)?;
        let length = state.stack_pop(&mut exec_step)?;

        #[cfg(feature = "enable-stack")]
        {
            assert_eq!(dest_offset, geth_step.stack.nth_last(0)?);
            assert_eq!(src_offset, geth_step.stack.nth_last(1)?);
            assert_eq!(length, geth_step.stack.nth_last(2)?);
        }

        let copy_event = gen_copy_event(
            state,
            dest_offset,
            src_offset,
            length.as_u64(),
            &mut exec_step,
        )?;
        state.push_copy(&mut exec_step, copy_event);
        Ok(vec![exec_step])
    }
}

fn gen_copy_event(
    state: &mut CircuitInputStateRef,
    dest_offset: Word,
    src_offset: Word,
    length: u64,
    exec_step: &mut ExecStep,
) -> Result<CopyEvent, Error> {
    let rw_counter_start = state.block_ctx.rwc;

    let call_id = state.call()?.call_id;

    // Get low Uint64 of offset.
    let dst_addr = dest_offset.low_u64();
    let src_addr_end = src_offset.as_u64() + length;

    // Reset offset to Uint64 maximum value if overflow, and set source start to the
    // minimum value of offset and code size.
    let src_addr = u64::try_from(src_offset)
        .unwrap_or(u64::MAX)
        .min(src_addr_end);

    let (read_steps, write_steps, prev_bytes) =
        state.gen_copy_steps_for_memory_to_memory(exec_step, src_addr, dst_addr, length)?;

    Ok(CopyEvent {
        src_type: CopyDataType::Memory,
        // use call_id as src id for match memory type. 
        src_id: NumberOrHash::Number(call_id),
        src_addr,
        src_addr_end,
        dst_type: CopyDataType::Memory,
        // dst_id is also call_id
        dst_id: NumberOrHash::Number(call_id),
        dst_addr,
        log_id: None,
        rw_counter_start,
        // needs both read/write and prev bytes in CopyBytes
        copy_bytes: CopyBytes::new(read_steps, Some(write_steps), Some(prev_bytes)),
        access_list: vec![],
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
    fn mcopy_opcode_impl() {
        test_ok(0x00, 0x00, 0x40);
        test_ok(0x20, 0x40, 0xA0);
    }

    fn test_ok(src_offset: usize, dest_offset: usize, copy_size: usize) {
        let code = bytecode! {
            PUSH32(copy_size)
            PUSH32(src_offset)
            PUSH32(dest_offset)
            MCOPY
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
                    &StackOp::new(1, StackAddress::from(1021), Word::from(dest_offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1022), Word::from(src_offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(copy_size)),
                ),
            ]
        );

        // add RW table memory word writes.
        let length = src_offset + copy_size;
        let copy_start = src_offset - src_offset % 32;
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

        // read and write ops. 
        assert_eq!(builder.block.container.memory.len(), word_ops * 2);
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
        assert_eq!(copy_events[0].src_addr as usize, dest_offset);
        assert_eq!(copy_events[0].src_addr_end as usize, code.to_vec().len());
        assert_eq!(copy_events[0].src_type, CopyDataType::Memory);
        assert_eq!(
            copy_events[0].dst_id,
            NumberOrHash::Number(expected_call_id)
        );
        assert_eq!(copy_events[0].dst_addr as usize, src_offset);
        assert_eq!(copy_events[0].dst_type, CopyDataType::Memory);
        assert!(copy_events[0].log_id.is_none());

        // TODO: below for loops should be adapted as now it is no longer related to bytecode 
        // for (idx, (value, is_code, is_mask)) in copy_events[0].copy_bytes.bytes.iter().enumerate() {
        //     let bytecode_element = code.get(dest_offset + idx).unwrap_or_default();
        //     if !is_mask {
        //         assert_eq!(*value, bytecode_element.value);
        //         assert_eq!(*is_code, bytecode_element.is_code);
        //     }
        // }
    }
}
