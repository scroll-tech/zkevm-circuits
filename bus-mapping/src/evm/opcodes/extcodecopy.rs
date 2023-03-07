use super::Opcode;
use crate::circuit_input_builder::{
    CircuitInputStateRef, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
};
use crate::operation::{AccountField, CallContextField, TxAccessListAccountOp, RW};
use crate::Error;
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
        let exec_steps = vec![gen_extcodecopy_step(state, geth_step)?];

        // reconstruction
        let address = geth_steps[0].stack.nth_last(0)?.to_address();
        let dest_offset = geth_steps[0].stack.nth_last(1)?.as_u64();
        // Reset code offset to the maximum value of Uint64 if overflow.
        let code_offset = u64::try_from(geth_step.stack.nth_last(2)?).unwrap_or(u64::MAX);
        let length = geth_steps[0].stack.nth_last(3)?.as_u64();

        let (_, account) = state.sdb.get_account(&address);
        let code_hash = account.code_hash;
        let code = state.code(code_hash)?;

        let call_ctx = state.call_ctx_mut()?;
        let memory = &mut call_ctx.memory;

        memory.copy_from(dest_offset, &code, code_offset, length as usize);

        let copy_event = gen_copy_event(state, geth_step)?;
        state.push_copy(copy_event);
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
        RW::WRITE,
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
        code_hash.to_word(),
    );
    Ok(exec_step)
}

fn gen_copy_steps(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    src_addr: u64,
    dst_addr: u64,
    src_addr_end: u64,
    bytes_left: u64,
    bytecode: &Bytecode,
) -> Result<Vec<(u8, bool)>, Error> {
    let mut copy_steps = Vec::with_capacity(bytes_left as usize);
    for idx in 0..bytes_left {
        let addr = src_addr.checked_add(idx).unwrap_or(src_addr_end);
        let step = if addr < src_addr_end {
            let code = bytecode.code.get(addr as usize).unwrap();
            (code.value, code.is_code)
        } else {
            (0, false)
        };
        copy_steps.push(step);
        state.memory_write(exec_step, (dst_addr + idx).into(), step.0)?;
    }

    Ok(copy_steps)
}

fn gen_copy_event(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<CopyEvent, Error> {
    let rw_counter_start = state.block_ctx.rwc;
    let external_address = geth_step.stack.nth_last(0)?.to_address();
    let memory_offset = geth_step.stack.nth_last(1)?.as_u64();
    // Reset code offset to the maximum value of Uint64 if overflow.
    let code_offset = u64::try_from(geth_step.stack.nth_last(2)?).unwrap_or(u64::MAX);
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
    // Set source start to the minimum value of code offset and code size for
    // avoiding overflow.
    let src_addr = code_offset.min(code_size);
    let src_addr_end = code_size;

    let mut exec_step = state.new_step(geth_step)?;
    let copy_steps = gen_copy_steps(
        state,
        &mut exec_step,
        src_addr,
        memory_offset,
        src_addr_end,
        length,
        &bytecode,
    )?;
    Ok(CopyEvent {
        src_addr,
        src_addr_end,
        src_type: CopyDataType::Bytecode,
        src_id: NumberOrHash::Hash(code_hash),
        dst_addr: memory_offset,
        dst_type: CopyDataType::Memory,
        dst_id: NumberOrHash::Number(state.call()?.call_id),
        log_id: None,
        rw_counter_start,
        bytes: copy_steps,
    })
}

#[cfg(test)]
mod extcodecopy_tests {
    use crate::{
        circuit_input_builder::{CopyDataType, ExecState, NumberOrHash},
        mock::BlockData,
        operation::{
            AccountField, AccountOp, CallContextField, CallContextOp, MemoryOp, StackOp,
            TxAccessListAccountOp, RW,
        },
    };
    use eth_types::{address, bytecode, Bytecode, Bytes, ToWord, Word};
    use eth_types::{
        evm_types::{MemoryAddress, OpcodeId, StackAddress},
        geth_types::GethData,
        H256, U256,
    };
    use ethers_core::utils::keccak256;
    use mock::TestContext;

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
        let code_hash = if code_ext.is_empty() {
            Default::default()
        } else {
            keccak256(code_ext.clone())
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 1>::new(
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
                    value: Word::from(code_hash),
                    value_prev: Word::from(code_hash),
                }
            )
        );

        let step = transaction
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::EXTCODECOPY))
            .unwrap();

        let expected_call_id = transaction.calls()[step.call_index].call_id;

        assert_eq!(
            (0..copy_size)
                .map(|idx| &builder.block.container.memory[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryOp)>>(),
            (0..copy_size)
                .map(|idx| {
                    (
                        RW::WRITE,
                        MemoryOp::new(
                            expected_call_id,
                            MemoryAddress::from(memory_offset + idx),
                            if data_offset + idx < bytecode_ext.to_vec().len() {
                                bytecode_ext.to_vec()[data_offset + idx]
                            } else {
                                0
                            },
                        ),
                    )
                })
                .collect::<Vec<(RW, MemoryOp)>>(),
        );

        let copy_events = builder.block.copy_events.clone();
        assert_eq!(copy_events.len(), 1);
        assert_eq!(copy_events[0].bytes.len(), copy_size);
        assert_eq!(copy_events[0].src_id, NumberOrHash::Hash(H256(code_hash)));
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

        for (idx, (value, is_code)) in copy_events[0].bytes.iter().enumerate() {
            let bytecode_element = bytecode_ext.get(idx).unwrap_or_default();
            assert_eq!(*value, bytecode_element.value);
            assert_eq!(*is_code, bytecode_element.is_code);
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
