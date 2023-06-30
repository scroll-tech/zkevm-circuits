use super::Opcode;
use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyBytes, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
    },
    operation::{AccountField, CallContextField, TxAccessListAccountOp},
    Error,
};
use eth_types::{Bytecode, GethExecStep, ToAddress, ToWord, H256, U256};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Extcodecopy;

// TODO: Update to treat code_hash == 0 as account not_exists once the circuit
// is implemented https://github.com/privacy-scaling-explorations/zkevm-circuits/pull/720

impl Opcode for Extcodecopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_steps = vec![gen_extcodecopy_step(state, geth_step)?];

        let copy_event = gen_copy_event(state, geth_step, &mut exec_steps[0])?;
        state.push_copy(&mut exec_steps[0], copy_event);
        Ok(exec_steps)
    }
}

fn gen_extcodecopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;

    let external_address_word = geth_step.stack.nth_last(0)?;
    let external_address = external_address_word.to_address();
    let dest_offset = geth_step.stack.nth_last(1)?;
    let offset = geth_step.stack.nth_last(2)?;
    let length = geth_step.stack.nth_last(3)?;

    // stack reads
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(0),
        external_address_word,
    )?;
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(1),
        dest_offset,
    )?;
    state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(2), offset)?;
    state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(3), length)?;

    for (field, value) in [
        (CallContextField::TxId, U256::from(state.tx_ctx.id())),
        (
            CallContextField::RwCounterEndOfReversion,
            U256::from(state.call()?.rw_counter_end_of_reversion as u64),
        ),
        (
            CallContextField::IsPersistent,
            U256::from(state.call()?.is_persistent as u64),
        ),
    ] {
        state.call_context_read(&mut exec_step, state.call()?.call_id, field, value);
    }

    let is_warm = state.sdb.check_account_in_access_list(&external_address);
    state.push_op_reversible(
        &mut exec_step,
        TxAccessListAccountOp {
            tx_id: state.tx_ctx.id(),
            address: external_address,
            is_warm: true,
            is_warm_prev: is_warm,
        },
    )?;

    let account = state.sdb.get_account(&external_address).1;
    let exists = !account.is_empty();
    let code_hash = if exists {
        account.code_hash
    } else {
        H256::zero()
    };

    state.account_read(
        &mut exec_step,
        external_address,
        AccountField::CodeHash,
        code_hash.to_word(),
    );
    Ok(exec_step)
}

fn gen_copy_event(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
    exec_step: &mut ExecStep,
) -> Result<CopyEvent, Error> {
    let rw_counter_start = state.block_ctx.rwc;

    let external_address = geth_step.stack.nth_last(0)?.to_address();
    let dst_offset = geth_step.stack.nth_last(1)?;
    let code_offset = geth_step.stack.nth_last(2)?;
    let length = geth_step.stack.nth_last(3)?.as_u64();

    let account = state.sdb.get_account(&external_address).1;
    let exists = !account.is_empty();
    let code_hash = if exists {
        account.code_hash
    } else {
        H256::zero()
    };

    let bytecode: Bytecode = if exists {
        state.code(code_hash)?.into()
    } else {
        Bytecode::default()
    };
    let code_size = bytecode.code.len() as u64;

    // Get low Uint64 of offset.
    let dst_addr = dst_offset.low_u64();
    let src_addr_end = code_size;

    // Reset offset to Uint64 maximum value if overflow, and set source start to the
    // minimum value of offset and code size.
    let src_addr = u64::try_from(code_offset)
        .unwrap_or(u64::MAX)
        .min(src_addr_end);

    let call_ctx = state.call_ctx_mut()?;
    let memory = &mut call_ctx.memory;
    memory.extend_for_range(dst_offset, length.into());
    let memory_updated = {
        let mut memory_updated = memory.clone();
        memory_updated.copy_from(dst_offset, code_offset, length.into(), &bytecode.to_vec());
        memory_updated
    };

    let (copy_steps, prev_bytes) = state.gen_copy_steps_for_bytecode(
        exec_step,
        &bytecode,
        src_addr,
        dst_addr,
        src_addr_end,
        length,
        memory_updated,
    )?;

    Ok(CopyEvent {
        src_addr,
        src_addr_end,
        src_type: CopyDataType::Bytecode,
        src_id: NumberOrHash::Hash(code_hash),
        dst_addr,
        dst_type: CopyDataType::Memory,
        dst_id: NumberOrHash::Number(state.call()?.call_id),
        log_id: None,
        rw_counter_start,
        copy_bytes: CopyBytes::new(copy_steps, None, Some(prev_bytes)),
    })
}

#[cfg(test)]
mod extcodecopy_tests {
    use crate::{
        circuit_input_builder::{CopyDataType, ExecState, NumberOrHash},
        mock::BlockData,
        operation::{
            AccountField, AccountOp, CallContextField, CallContextOp, MemoryWordOp, StackOp,
            TxAccessListAccountOp, RW,
        },
        state_db::CodeDB,
    };
    use eth_types::{
        address, bytecode,
        evm_types::{MemoryAddress, OpcodeId, StackAddress},
        geth_types::GethData,
        Bytecode, Bytes, ToWord, Word, U256,
    };
    use mock::{test_ctx::LoggerConfig, TestContext};

    fn test_ok(
        code_ext: Bytes,
        is_warm: bool,
        data_offset: usize,
        memory_offset: usize,
        copy_size: usize,
    ) {
        let external_address = address!("0xaabbccddee000000000000000000000000000000");
        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                PUSH20(external_address.to_word())
                EXTCODEHASH
                POP
            })
        }
        code.append(&bytecode! {
            PUSH32 (copy_size)
            PUSH32 (data_offset)
            PUSH32 (memory_offset)
            PUSH20 (external_address.to_word())
            EXTCODECOPY
            STOP
        });

        let bytecode_ext = Bytecode::from(code_ext.to_vec());
        // TODO: bytecode_ext = vec![] is being used to indicate an empty account.
        // Should be an optional vec and we need to add tests for EOA vs. non-EOA.
        let code_hash = if code_ext.is_empty() {
            Default::default()
        } else {
            CodeDB::hash(&code_ext)
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 1>::new_with_logger_config(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .code(code.clone());

                accs[1].address(external_address).code(code_ext.clone());

                accs[2]
                    .address(address!("0x0000000000000000000000000000000000cafe01"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block.number(0xcafeu64),
            LoggerConfig::enable_memory(),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        assert!(builder.sdb.add_account_to_access_list(external_address));

        let tx_id = 1;
        let transaction = &builder.block.txs()[tx_id - 1];
        let call_id = transaction.calls()[0].call_id;

        let indices = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::EXTCODECOPY))
            .last()
            .unwrap()
            .bus_mapping_instance
            .clone();
        let container = &builder.block.container;
        assert_eq!(
            {
                let operation = &container.stack[indices[0].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &StackOp {
                    call_id,
                    address: StackAddress::from(1020u32),
                    value: external_address.to_word()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.stack[indices[1].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &StackOp {
                    call_id,
                    address: StackAddress::from(1021u32),
                    value: memory_offset.into()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.stack[indices[2].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &StackOp {
                    call_id,
                    address: StackAddress::from(1022u32),
                    value: data_offset.into()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.stack[indices[3].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &StackOp {
                    call_id,
                    address: StackAddress::from(1023u32),
                    value: copy_size.into()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.call_context[indices[4].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::TxId,
                    value: tx_id.into()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.call_context[indices[5].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::RwCounterEndOfReversion,
                    value: U256::zero()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.call_context[indices[6].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::IsPersistent,
                    value: U256::one()
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.tx_access_list_account[indices[7].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::WRITE,
                &TxAccessListAccountOp {
                    tx_id,
                    address: external_address,
                    is_warm: true,
                    is_warm_prev: is_warm
                }
            )
        );
        assert_eq!(
            {
                let operation = &container.account[indices[8].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &AccountOp {
                    address: external_address,
                    field: AccountField::CodeHash,
                    value: code_hash.to_word(),
                    value_prev: code_hash.to_word(),
                }
            )
        );

        let step = transaction
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::EXTCODECOPY))
            .unwrap();

        let expected_call_id = transaction.calls()[step.call_index].call_id;

        let length = memory_offset + copy_size;
        let copy_start = memory_offset - memory_offset % 32;
        let copy_end = length - length % 32;
        let word_ops = (copy_end + 32 - copy_start) / 32;
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

        assert_eq!(builder.block.container.memory_word.len(), word_ops);
        assert_eq!(
            (0..word_ops)
                .map(|idx| &builder.block.container.memory_word[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryWordOp)>>(),
            (0..word_ops)
                .map(|idx| {
                    (
                        RW::WRITE,
                        MemoryWordOp::new_write(
                            call_id,
                            MemoryAddress(copy_start + idx * 32),
                            Word::from(&copied_bytes[idx * 32..(idx + 1) * 32]),
                            // get previous value
                            Word::from(&prev_bytes[idx * 32..(idx + 1) * 32]),
                        ),
                    )
                })
                .collect::<Vec<(RW, MemoryWordOp)>>(),
        );

        let copy_events = builder.block.copy_events.clone();
        assert_eq!(copy_events.len(), 1);
        assert_eq!(copy_events[0].src_id, NumberOrHash::Hash(code_hash));
        assert_eq!(copy_events[0].src_addr as usize, data_offset);
        assert_eq!(copy_events[0].src_addr_end as usize, code_ext.len());
        assert_eq!(copy_events[0].src_type, CopyDataType::Bytecode);
        assert_eq!(
            copy_events[0].dst_id,
            NumberOrHash::Number(expected_call_id)
        );
        assert_eq!(copy_events[0].dst_addr as usize, memory_offset);
        assert_eq!(copy_events[0].dst_type, CopyDataType::Memory);
        assert!(copy_events[0].log_id.is_none());

        for (idx, (value, is_code, is_mask)) in copy_events[0].copy_bytes.bytes.iter().enumerate() {
            if !*is_mask {
                let bytecode_element = bytecode_ext.get(idx).unwrap_or_default();
                assert_eq!(*value, bytecode_element.value);
                assert_eq!(*is_code, bytecode_element.is_code);
            }
        }
    }

    #[test]
    fn cold_empty_account() {
        test_ok(Bytes::from([]), false, 0x0usize, 0x0usize, 0x30usize);
    }

    #[test]
    fn warm_empty_account() {
        test_ok(Bytes::from([]), true, 0x0usize, 0x0usize, 0x30usize);
    }

    #[test]
    fn cold_non_empty_account() {
        test_ok(Bytes::from([10, 40]), false, 0x0usize, 0x0usize, 0x30usize);
    }

    #[test]
    fn warm_non_empty_account() {
        test_ok(Bytes::from([10, 40]), true, 0x0usize, 0x0usize, 0x30usize);
    }
}
