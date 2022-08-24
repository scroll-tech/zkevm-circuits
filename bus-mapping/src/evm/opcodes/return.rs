use super::Opcode;
use crate::circuit_input_builder::CopyEvent;
use crate::circuit_input_builder::CopyStep;
use crate::circuit_input_builder::{CopyDataType, NumberOrHash};
use crate::operation::MemoryOp;
use crate::{
    circuit_input_builder::CircuitInputStateRef,
    evm::opcodes::ExecStep,
    operation::{CallContextField, RW},
    Error,
};
use eth_types::{Bytecode, GethExecStep, ToWord, H256};
use ethers_core::utils::keccak256;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Return;

// rename to ReturnRevertStop?
impl Opcode for Return {
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
            // TODO: handle memory expansion gas cost!!
        }

        let call = state.call()?.clone();
        let is_root = call.is_root;
        for (field, value) in [
            (CallContextField::IsRoot, is_root.to_word()),
            (CallContextField::IsCreate, call.is_create().to_word()),
            (CallContextField::IsSuccess, call.is_success.to_word()),
            (CallContextField::CallerId, call.caller_id.into()),
            (
                CallContextField::ReturnDataOffset,
                call.return_data_offset.into(),
            ),
            (
                CallContextField::ReturnDataLength,
                call.return_data_length.into(),
            ),
        ] {
            state.call_context_read(&mut exec_step, call.call_id, field, value);
        }

        if !is_root {
            state.handle_restore_context(steps, &mut exec_step)?;
        }

        let memory = state.call_ctx()?.memory.clone();
        let offset = offset.as_usize();
        let length = length.as_usize();
        if call.is_create() && call.is_success {
            // is this always the case?
            assert!(offset + length <= memory.0.len());
            let code = memory.0[offset..offset + length].to_vec();
            state.code_db.insert(code);
            if length > 0 {
                handle_create(
                    state,
                    &mut exec_step,
                    Source {
                        id: call.call_id,
                        offset: offset.try_into().unwrap(),
                        length: length.try_into().unwrap(),
                    },
                )?;
            }
        } else if !is_root {
            let caller_ctx = state.caller_ctx_mut()?;
            let return_offset = call.return_data_offset.try_into().unwrap();

            let copy_len = std::cmp::min(call.return_data_length.try_into().unwrap(), length);
            caller_ctx.memory.0[return_offset..return_offset + copy_len]
                .copy_from_slice(&memory.0[offset..offset + copy_len]);
            caller_ctx.return_data = memory.0[offset..offset + length].to_vec();

            if length > 0 {
                handle_copy(
                    state,
                    &mut exec_step,
                    Source {
                        id: call.call_id,
                        offset: offset.try_into().unwrap(),
                        length: length.try_into().unwrap(),
                    },
                    Destination {
                        id: call.caller_id,
                        offset: call.return_data_offset.try_into().unwrap(),
                        length: call.return_data_length.try_into().unwrap(),
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
    let initial_rw_counter = state.block_ctx.rwc.0;
    let rw_counter_increase = copy_length * 2;

    let bytes = state.call_ctx()?.memory.0[source.offset..source.offset + copy_length].to_vec();

    let copy_steps = bytes
        .iter()
        .enumerate()
        .flat_map(|(i, &byte)| {
            [
                CopyStep {
                    addr: (source.offset + i).try_into().unwrap(),
                    tag: CopyDataType::Memory,
                    rw: RW::READ,
                    value: byte,
                    is_code: None,
                    is_pad: false,
                    rwc: (initial_rw_counter + 2 * i).into(),
                    rwc_inc_left: (rw_counter_increase - 2 * i).try_into().unwrap(),
                },
                CopyStep {
                    addr: (destination.offset + i).try_into().unwrap(),
                    tag: CopyDataType::Memory,
                    rw: RW::WRITE,
                    value: byte,
                    is_code: None,
                    is_pad: false,
                    rwc: (initial_rw_counter + 2 * i + 1).into(),
                    rwc_inc_left: (rw_counter_increase - 2 * i - 1).try_into().unwrap(),
                },
            ]
            .into_iter()
        })
        .collect();

    for (i, &byte) in bytes.iter().enumerate() {
        state.push_op(
            step,
            RW::READ,
            MemoryOp::new(source.id, (source.offset + i).into(), byte),
        );
        state.push_op(
            step,
            RW::WRITE,
            MemoryOp::new(destination.id, (destination.offset + i).into(), byte),
        );
    }

    state.push_copy(CopyEvent {
        src_type: CopyDataType::Memory,
        src_id: NumberOrHash::Number(source.id.try_into().unwrap()),
        src_addr: 0, // not used
        src_addr_end: (source.offset + copy_length).try_into().unwrap(),
        dst_type: CopyDataType::Memory,
        dst_id: NumberOrHash::Number(destination.id.try_into().unwrap()),
        dst_addr: 0, // not used
        length: copy_length.try_into().unwrap(),
        log_id: None,
        steps: copy_steps,
    });

    Ok(())
}

fn handle_create(
    state: &mut CircuitInputStateRef,
    step: &mut ExecStep,
    source: Source,
) -> Result<(), Error> {
    let bytes = state.call_ctx()?.memory.0[source.offset..source.offset + source.length].to_vec();
    let bytecode = Bytecode::from(bytes.clone());
    let initial_rw_counter = state.block_ctx.rwc.0;
    let copy_steps = bytes
        .iter()
        .enumerate()
        .flat_map(|(i, &byte)| {
            [
                CopyStep {
                    addr: (source.offset + i).try_into().unwrap(),
                    tag: CopyDataType::Memory,
                    rw: RW::READ,
                    value: byte,
                    is_code: None, // does this matter?
                    is_pad: false,
                    rwc: (initial_rw_counter + i).into(),
                    rwc_inc_left: (source.length - i).try_into().unwrap(),
                },
                CopyStep {
                    addr: i.try_into().unwrap(),
                    tag: CopyDataType::Bytecode,
                    rw: RW::WRITE,
                    value: byte,
                    is_code: Some(bytecode.get(i).unwrap().is_code),
                    is_pad: false,
                    rwc: (initial_rw_counter + i).into(),
                    rwc_inc_left: (source.length - i).try_into().unwrap(),
                },
            ]
            .into_iter()
        })
        .collect();

    state.push_copy(CopyEvent {
        src_type: CopyDataType::Memory,
        src_id: NumberOrHash::Number(source.id.try_into().unwrap()),
        src_addr: 0, // not used
        src_addr_end: (source.offset + source.length).try_into().unwrap(),
        dst_type: CopyDataType::Bytecode,
        dst_id: NumberOrHash::Hash(H256(keccak256(&bytes))),
        dst_addr: 0, // not used
        length: source.length.try_into().unwrap(),
        log_id: None,
        steps: copy_steps,
    });

    for (i, &byte) in bytes.iter().enumerate() {
        state.push_op(
            step,
            RW::READ,
            MemoryOp::new(source.id, (source.offset + i).into(), byte),
        );
    }

    Ok(())
}

#[cfg(test)]
mod return_tests {
    use crate::mock::BlockData;
    use eth_types::geth_types::GethData;
    use eth_types::{bytecode, Word};
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;

    fn test_return(
        callee_return_data_offset: usize,
        callee_return_data_length: usize,
        caller_return_data_offset: usize,
        caller_return_data_length: usize,
    ) {
        let contract = bytecode! {
            PUSH1(0x20)
            PUSH1(0)
            PUSH1(0)
            CALLDATACOPY
            PUSH1(callee_return_data_length)
            PUSH1(callee_return_data_offset)
            RETURN
        };

        let constructor = bytecode! {
            PUSH12(Word::from(contract.to_vec().as_slice()))
            PUSH1(0)
            MSTORE
            PUSH1(0xC)
            PUSH1(0x14)
            RETURN
        };

        let code = bytecode! {
            PUSH21(Word::from(constructor.to_vec().as_slice()))
            PUSH1(0)
            MSTORE

            PUSH1 (0x15)
            PUSH1 (0xB)
            PUSH1 (0)
            CREATE

            PUSH1 (caller_return_data_length)
            PUSH1 (caller_return_data_offset)
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
    fn test_cases() {
        test_return(0, 0, 0, 0);
        test_return(10, 10, 10, 10);
        test_return(0, 0, 0, 0);
        test_return(0, 0, 0, 100);
        test_return(0, 0, 0, 0);
    }
}
