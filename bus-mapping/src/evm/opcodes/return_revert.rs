use super::Opcode;
use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyBytes, CopyDataType, CopyEvent, CopyEventStepsBuilder,
        NumberOrHash,
    },
    evm::opcodes::ExecStep,
    operation::{AccountField, AccountOp, CallContextField},
    state_db::CodeDB,
    Error,
};
use eth_types::{
    bytecode::BytecodeElement,
    evm_types::{memory::MemoryWordRange, OpcodeId},
    Bytecode, GethExecStep, ToWord, Word, H256,
};
use ethers_core::utils::keccak256;

#[derive(Debug, Copy, Clone)]
pub(crate) struct ReturnRevert;

impl Opcode for ReturnRevert {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let step = &steps[0];
        let mut exec_step = state.new_step(step)?;

        let offset = step.stack.nth_last(0)?;
        let length = step.stack.nth_last(1)?;
        assert_eq!(offset, state.stack_pop(&mut exec_step)?);
        assert_eq!(length, state.stack_pop(&mut exec_step)?);

        if !length.is_zero() {
            state
                .call_ctx_mut()?
                .memory
                .extend_at_least((offset.low_u64() + length.low_u64()).try_into().unwrap());
        }

        let call = state.call()?.clone();
        state.call_context_read(
            &mut exec_step,
            call.call_id,
            CallContextField::IsSuccess,
            call.is_success.to_word(),
        )?;

        // Get low Uint64 of offset.
        let offset = offset.low_u64() as usize;
        let length = length.as_usize();

        // Case A in the spec.
        if call.is_create() && call.is_success && length > 0 {
            // Note: handle_return updates state.code_db. All we need to do here is push the
            // copy event.
            let code_info = handle_create(
                state,
                &mut exec_step,
                Source {
                    id: call.call_id,
                    offset,
                    length,
                },
            )?;

            for (field, value) in [
                (CallContextField::CallerId, call.caller_id.to_word()),
                (CallContextField::CalleeAddress, call.address.to_word()),
                (
                    CallContextField::RwCounterEndOfReversion,
                    call.rw_counter_end_of_reversion.to_word(),
                ),
                (CallContextField::IsPersistent, call.is_persistent.to_word()),
            ] {
                state.call_context_read(&mut exec_step, call.call_id, field, value)?;
            }

            // the 'nonce' field has already been set to 1 inside 'create' or 'begin_tx',
            // so here account should not be empty.
            // TODO: optimize this later.
            let account = state.sdb.get_account(&call.address).1.clone();
            let prev_code_hash = if account.is_empty() {
                Word::zero()
            } else {
                CodeDB::empty_code_hash().to_word()
            };
            state.account_read(
                &mut exec_step,
                call.address,
                AccountField::CodeHash,
                prev_code_hash,
            )?;
            state.push_op_reversible(
                &mut exec_step,
                AccountOp {
                    address: call.address,
                    field: AccountField::CodeHash,
                    value: code_info.hash.to_word(),
                    value_prev: prev_code_hash,
                },
            )?;

            #[cfg(feature = "scroll")]
            {
                let prev_keccak_code_hash = if account.is_empty() {
                    Word::zero()
                } else {
                    crate::util::KECCAK_CODE_HASH_EMPTY.to_word()
                };
                state.account_read(
                    &mut exec_step,
                    call.address,
                    AccountField::KeccakCodeHash,
                    prev_keccak_code_hash,
                )?;
                state.push_op_reversible(
                    &mut exec_step,
                    AccountOp {
                        address: call.address,
                        field: AccountField::KeccakCodeHash,
                        value: code_info.keccak_hash.to_word(),
                        value_prev: prev_keccak_code_hash,
                    },
                )?;

                state.push_op_reversible(
                    &mut exec_step,
                    AccountOp {
                        address: call.address,
                        field: AccountField::CodeSize,
                        value: code_info.size.to_word(),
                        value_prev: eth_types::Word::zero(),
                    },
                )?;
            }
        }

        // Case B in the specs.
        if call.is_root {
            state.call_context_read(
                &mut exec_step,
                call.call_id,
                CallContextField::IsPersistent,
                call.is_persistent.to_word(),
            )?;
        }

        // Case C in the specs.
        if !call.is_root {
            state.handle_restore_context(&mut exec_step, steps)?;
        }

        // Case D in the specs.
        // only when successful deployment case we don't need to keep return data.
        // namely, when call.is_create() && opcode is revert (successfully revert, not oog revert),
        // we still need to store return data.
        // Failed RETURN will not handled by here, so we don't need to check call.is_success.
        if !call.is_root {
            let return_data = state
                .call_ctx()?
                .memory
                .0
                .get(offset..offset + length)
                .unwrap_or_default()
                .to_vec();
            if call.is_create() && step.op == OpcodeId::RETURN {
                state.caller_ctx_mut()?.return_data.clear();
            } else {
                state.caller_ctx_mut()?.return_data = return_data;
            }
            if !call.is_create() {
                // store return data to caller memory
                for (field, value) in [
                    (CallContextField::ReturnDataOffset, call.return_data_offset),
                    (CallContextField::ReturnDataLength, call.return_data_length),
                ] {
                    state.call_context_read(&mut exec_step, call.call_id, field, value.into())?;
                }

                let return_data_length = usize::try_from(call.return_data_length).unwrap();
                let copy_length = std::cmp::min(return_data_length, length);
                if copy_length > 0 {
                    // reconstruction
                    let return_offset = call.return_data_offset.try_into().unwrap();

                    handle_copy(
                        state,
                        &mut exec_step,
                        Source {
                            id: call.call_id,
                            offset,
                            length,
                        },
                        Destination {
                            id: call.caller_id,
                            offset: return_offset,
                            length: return_data_length,
                        },
                    )?;
                }
            }
        }

        state.handle_return(&mut [&mut exec_step], steps, false)?;
        Ok(vec![exec_step])
    }
}

struct Source {
    id: usize,
    offset: usize,
    length: usize,
}

struct Destination {
    id: usize,
    offset: usize,
    length: usize,
}

// handle non root & non create case
fn handle_copy(
    state: &mut CircuitInputStateRef,
    step: &mut ExecStep,
    source: Source,
    destination: Destination,
) -> Result<(), Error> {
    let copy_length = std::cmp::min(source.length, destination.length);

    let rw_counter_start = state.block_ctx.rwc;

    let mut src_range = MemoryWordRange::align_range(source.offset, copy_length);
    let mut dst_range = MemoryWordRange::align_range(destination.offset, copy_length);
    src_range.ensure_equal_length(&mut dst_range);

    let src_data = state.call_ctx()?.memory.read_chunk(src_range);
    let dst_data_prev = state.caller_ctx()?.memory.read_chunk(dst_range);
    let dst_data = {
        // Copy src_data into dst_data
        let mut dst_data = dst_data_prev.clone();
        dst_data[dst_range.shift().0..dst_range.shift().0 + copy_length]
            .copy_from_slice(&src_data[src_range.shift().0..src_range.shift().0 + copy_length]);
        dst_data
    };

    let mut src_chunk_index = src_range.start_slot().0;
    let mut dst_chunk_index = dst_range.start_slot().0;

    // memory word read from src
    for write_chunk in dst_data.chunks(32) {
        // read memory
        state.memory_read_word(step, src_chunk_index.into())?;

        // write memory
        let write_word = Word::from_big_endian(write_chunk);
        state.memory_write_caller(step, dst_chunk_index.into(), write_word)?;

        dst_chunk_index += 32;
        src_chunk_index += 32;
    }

    // memory word write to destination
    let read_steps = CopyEventStepsBuilder::memory_range(src_range)
        .source(src_data.as_slice())
        .build();
    let write_steps = CopyEventStepsBuilder::memory_range(dst_range)
        .source(dst_data.as_slice())
        .build();

    state.push_copy(
        step,
        CopyEvent {
            rw_counter_start,
            src_type: CopyDataType::Memory,
            src_id: NumberOrHash::Number(source.id),
            src_addr: source.offset.try_into().unwrap(),
            src_addr_end: (source.offset + source.length).try_into().unwrap(),
            dst_type: CopyDataType::Memory,
            dst_id: NumberOrHash::Number(destination.id),
            dst_addr: destination.offset.try_into().unwrap(),
            log_id: None,
            copy_bytes: CopyBytes::new(read_steps, Some(write_steps), Some(dst_data_prev)),
        },
    );

    Ok(())
}

struct AccountCodeInfo {
    keccak_hash: H256,
    hash: H256,
    size: usize,
}

// handle return in create.
fn handle_create(
    state: &mut CircuitInputStateRef,
    step: &mut ExecStep,
    source: Source,
) -> Result<AccountCodeInfo, Error> {
    let values = state.call_ctx()?.memory.0[source.offset..source.offset + source.length].to_vec();
    let keccak_hash = H256(keccak256(&values));
    let code_hash = CodeDB::hash(&values);
    let size = values.len();
    let dst_id = NumberOrHash::Hash(code_hash);
    let bytes = Bytecode::from(values).code;

    let rw_counter_start = state.block_ctx.rwc;
    let dst_range = MemoryWordRange::align_range(source.offset, source.length);

    let memory = state.call_ctx_mut()?.memory.read_chunk(dst_range);

    // collect all bytecode to memory with padding word
    let create_slot_len = dst_range.full_length().0;

    let mut chunk_index = dst_range.start_slot().0;
    // memory word writes to destination word
    for _ in 0..create_slot_len / 32 {
        // read memory
        state.memory_read_word(step, chunk_index.into())?;
        chunk_index += 32;
    }

    let copy_steps = CopyEventStepsBuilder::new()
        .source(bytes.as_slice())
        .read_offset(0)
        .write_offset(dst_range.shift())
        .step_length(dst_range.full_length())
        .length(source.length)
        .padding_byte_getter(|_: &[BytecodeElement], idx: usize| {
            memory.get(idx).copied().unwrap_or(0)
        })
        .mapper(|v: &BytecodeElement| (v.value, v.is_code))
        .build();

    state.push_copy(
        step,
        CopyEvent {
            rw_counter_start,
            src_type: CopyDataType::Memory,
            src_id: NumberOrHash::Number(source.id),
            src_addr: source.offset.try_into().unwrap(),
            src_addr_end: (source.offset + source.length).try_into().unwrap(),
            dst_type: CopyDataType::Bytecode,
            dst_id,
            dst_addr: 0,
            log_id: None,
            copy_bytes: CopyBytes::new(copy_steps, None, None),
        },
    );

    Ok(AccountCodeInfo {
        keccak_hash,
        hash: code_hash,
        size,
    })
}

#[cfg(test)]
mod return_tests {
    use crate::mock::BlockData;
    use eth_types::{bytecode, geth_types::GethData, word};
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

    #[test]
    fn test_revert() {
        // // deployed contract
        // PUSH1 0x20
        // PUSH1 0
        // PUSH1 0
        // CALLDATACOPY
        // PUSH1 0x20
        // PUSH1 0
        // REVERT
        //
        // bytecode: 0x6020600060003760206000FD
        //
        // // constructor
        // PUSH12 0x6020600060003760206000FD
        // PUSH1 0
        // MSTORE
        // PUSH1 0xC
        // PUSH1 0x14
        // RETURN
        //
        // bytecode: 0x6B6020600060003760206000FD600052600C6014F3
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000FD600052600C6014F3"))
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
