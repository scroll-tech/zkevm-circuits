use super::Opcode;
use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyBytes, CopyDataType, CopyEvent, NumberOrHash,
    },
    evm::opcodes::ExecStep,
    operation::{AccountField, AccountOp, CallContextField, MemoryWordOp, RW},
    state_db::CodeDB,
    Error,
};
use eth_types::{Bytecode, GethExecStep, ToWord, Word, H256};
use ethers_core::utils::keccak256;
use std::cmp::max;

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
        state.stack_read(&mut exec_step, step.stack.nth_last_filled(0), offset)?;
        state.stack_read(&mut exec_step, step.stack.nth_last_filled(1), length)?;

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
        );

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
                state.call_context_read(&mut exec_step, state.call()?.call_id, field, value);
            }

            #[cfg(feature = "scroll")]
            state.push_op_reversible(
                &mut exec_step,
                AccountOp {
                    address: state.call()?.address,
                    field: AccountField::KeccakCodeHash,
                    value: code_info.keccak_hash.to_word(),
                    value_prev: crate::util::KECCAK_CODE_HASH_ZERO.to_word(),
                },
            )?;
            state.push_op_reversible(
                &mut exec_step,
                AccountOp {
                    address: state.call()?.address,
                    field: AccountField::CodeHash,
                    value: code_info.hash.to_word(),
                    value_prev: CodeDB::empty_code_hash().to_word(),
                },
            )?;
            #[cfg(feature = "scroll")]
            state.push_op_reversible(
                &mut exec_step,
                AccountOp {
                    address: state.call()?.address,
                    field: AccountField::CodeSize,
                    value: code_info.size.to_word(),
                    value_prev: eth_types::Word::zero(),
                },
            )?;
        }

        // Case B in the specs.
        if call.is_root {
            state.call_context_read(
                &mut exec_step,
                call.call_id,
                CallContextField::IsPersistent,
                call.is_persistent.to_word(),
            );
        }

        // Case C in the specs.
        if !call.is_root {
            state.handle_restore_context(&mut exec_step, steps)?;
        }

        // Case D in the specs.
        if !call.is_root && !call.is_create() {
            for (field, value) in [
                (CallContextField::ReturnDataOffset, call.return_data_offset),
                (CallContextField::ReturnDataLength, call.return_data_length),
            ] {
                state.call_context_read(&mut exec_step, call.call_id, field, value.into());
            }

            let return_data = state
                .call_ctx()?
                .memory
                .0
                .get(offset..offset + length)
                .unwrap_or_default()
                .to_vec();

            state.caller_ctx_mut()?.return_data = return_data;

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

        state.handle_return(&mut exec_step, steps, false)?;
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

    let (src_shift, src_begin_slot) = state.get_addr_shift_slot(source.offset as u64).unwrap();
    let (_, src_end_slot) = state
        .get_addr_shift_slot((source.offset + copy_length - 1) as u64)
        .unwrap();
    let src_shift = src_shift as usize;

    let (dst_shift, dst_begin_slot) = state
        .get_addr_shift_slot(destination.offset as u64)
        .unwrap();
    let (_, dst_end_slot) = state
        .get_addr_shift_slot((destination.offset + copy_length - 1) as u64)
        .unwrap();
    let dst_shift = dst_shift as usize;

    let full_length =
        max(src_end_slot - src_begin_slot, dst_end_slot - dst_begin_slot) as usize + 32;

    let src_data = state
        .call_ctx()?
        .memory
        .read_chunk(src_begin_slot.into(), full_length.into());

    let dst_data_prev = state
        .caller_ctx()?
        .memory
        .read_chunk(dst_begin_slot.into(), full_length.into());

    let dst_data = {
        // Copy src_data into dst_data
        let mut dst_data = dst_data_prev.clone();
        dst_data[dst_shift..dst_shift + copy_length]
            .copy_from_slice(&src_data[src_shift..src_shift + copy_length]);
        dst_data
    };

    let mut src_chunk_index = src_begin_slot;
    let mut dst_chunk_index = dst_begin_slot;

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
    let mut read_steps = Vec::with_capacity(source.length);
    CircuitInputStateRef::gen_memory_copy_steps(
        &mut read_steps,
        &src_data,
        full_length,
        source.offset,
        src_begin_slot as usize,
        copy_length,
    );

    let mut write_steps = Vec::with_capacity(destination.length);
    CircuitInputStateRef::gen_memory_copy_steps(
        &mut write_steps,
        &dst_data, // TODO: this should be dst_data_prev.
        full_length,
        destination.offset,
        dst_begin_slot as usize,
        copy_length,
    );

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
            copy_bytes: CopyBytes::new(read_steps, Some(write_steps), None),
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
    let bytes: Vec<_> = Bytecode::from(values)
        .code
        .iter()
        .map(|element| (element.value, element.is_code, false))
        .collect();

    let rw_counter_start = state.block_ctx.rwc;
    let (_, dst_begin_slot) = state.get_addr_shift_slot(source.offset as u64).unwrap();
    let (_, dst_end_slot) = state
        .get_addr_shift_slot((source.offset + source.length) as u64)
        .unwrap();

    let mut memory = state.call_ctx_mut()?.memory.clone();
    let minimal_length = dst_end_slot as usize + 32;
    memory.extend_at_least(minimal_length);

    // collect all bytecode to memory with padding word
    let create_slot_len = (dst_end_slot + 32 - dst_begin_slot) as usize;

    let mut copy_start = 0u64;
    let mut first_set = true;
    let mut chunk_index = dst_begin_slot;
    // memory word writes to destination word
    for _ in 0..create_slot_len / 32 {
        // read memory
        state.memory_read_word(step, chunk_index.into())?;
        chunk_index += 32;
    }

    let mut copy_steps = Vec::with_capacity(source.length);
    for idx in 0..create_slot_len {
        let value = memory.0[dst_begin_slot as usize + idx];
        if (idx as u64 + dst_begin_slot < source.offset as u64)
            || (idx as u64 + dst_begin_slot >= (source.offset + source.length) as u64)
        {
            // front and back mask byte
            copy_steps.push((value, false, true));
        } else {
            // real copy byte
            if first_set {
                copy_start = idx as u64;
                first_set = false;
            }

            copy_steps.push(bytes[idx - copy_start as usize]);
        }
    }

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
            LoggerConfig::enable_memory(),
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
            LoggerConfig::enable_memory(),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }
}
