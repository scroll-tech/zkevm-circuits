use super::Opcode;
use crate::circuit_input_builder::{CopyDataType, CopyEvent, NumberOrHash};
use crate::operation::AccountOp;
use crate::operation::MemoryOp;
use crate::{
    circuit_input_builder::CircuitInputStateRef,
    evm::opcodes::ExecStep,
    operation::{AccountField, CallContextField, RW},
    Error,
};
use eth_types::{Bytecode, GethExecStep, ToWord, Word, H256};
use ethers_core::utils::keccak256;
use keccak256::EMPTY_HASH_LE;

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
            let code_hash = handle_create(
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

            state.push_op_reversible(
                &mut exec_step,
                AccountOp {
                    address: state.call()?.address,
                    field: AccountField::CodeHash,
                    value: code_hash.to_word(),
                    value_prev: Word::from_little_endian(&*EMPTY_HASH_LE),
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
            state.handle_restore_context(steps, &mut exec_step)?;
        }

        // Case D in the specs.
        if !call.is_root && !call.is_create() {
            for (field, value) in [
                (CallContextField::ReturnDataOffset, call.return_data_offset),
                (CallContextField::ReturnDataLength, call.return_data_length),
            ] {
                state.call_context_read(&mut exec_step, call.call_id, field, value.into());
            }

            let callee_memory = state.call_ctx()?.memory.clone();
            let caller_ctx = state.caller_ctx_mut()?;
            caller_ctx.return_data = callee_memory
                .0
                .get(offset..offset + length)
                .unwrap_or_default()
                .to_vec();

            let return_data_length = usize::try_from(call.return_data_length).unwrap();
            let copy_length = std::cmp::min(return_data_length, length);
            if copy_length > 0 {
                // reconstruction
                let return_offset = call.return_data_offset.try_into().unwrap();
                caller_ctx.memory.0[return_offset..return_offset + copy_length]
                    .copy_from_slice(&callee_memory.0[offset..offset + copy_length]);

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

        state.handle_return(step)?;
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

fn handle_copy(
    state: &mut CircuitInputStateRef,
    step: &mut ExecStep,
    source: Source,
    destination: Destination,
) -> Result<(), Error> {
    let copy_length = std::cmp::min(source.length, destination.length);
    let bytes: Vec<_> = state.call_ctx()?.memory.0[source.offset..source.offset + copy_length]
        .iter()
        .map(|byte| (*byte, false))
        .collect();

    let rw_counter_start = state.block_ctx.rwc;
    for (i, (byte, _is_code)) in bytes.iter().enumerate() {
        state.push_op(
            step,
            RW::READ,
            MemoryOp::new(source.id, (source.offset + i).into(), *byte),
        );
        state.push_op(
            step,
            RW::WRITE,
            MemoryOp::new(destination.id, (destination.offset + i).into(), *byte),
        );
    }

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
            bytes,
        },
    );

    Ok(())
}

fn handle_create(
    state: &mut CircuitInputStateRef,
    step: &mut ExecStep,
    source: Source,
) -> Result<H256, Error> {
    let values = state.call_ctx()?.memory.0[source.offset..source.offset + source.length].to_vec();
    // FIXME for poseidon code hash
    let code_hash = H256(keccak256(&values));
    let dst_id = NumberOrHash::Hash(code_hash);
    let bytes: Vec<_> = Bytecode::from(values)
        .code
        .iter()
        .map(|element| (element.value, element.is_code))
        .collect();

    let rw_counter_start = state.block_ctx.rwc;
    for (i, (byte, _)) in bytes.iter().enumerate() {
        state.push_op(
            step,
            RW::READ,
            MemoryOp::new(source.id, (source.offset + i).into(), *byte),
        );
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
            bytes,
        },
    );

    Ok(code_hash)
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
