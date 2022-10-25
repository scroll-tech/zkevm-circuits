use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, CodeSource, ExecStep};
use crate::operation::{AccountField, CallContextField, TxAccessListAccountOp, RW};
use crate::Error;
use eth_types::evm_types::gas_utils::{eip150_gas, memory_expansion_gas_cost};
use eth_types::evm_types::GasCost;
use eth_types::{evm_types::OpcodeId, H256};
use eth_types::{GethExecStep, ToWord};
use keccak256::EMPTY_HASH;
use log::warn;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the `OpcodeId::CALL` and `OpcodeId::STATICCALL`.
/// - CALL: N_ARGS = 7
/// - STATICCALL: N_ARGS = 6
/// TODO: Suppose to add bus-mapping of `OpcodeId::CALLCODE` and
/// `OpcodeId::DELEGATECALL` here.
#[derive(Debug, Copy, Clone)]
pub(crate) struct CallOpcode<const N_ARGS: usize>;

impl<const N_ARGS: usize> Opcode for CallOpcode<N_ARGS> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        let args_offset = geth_step.stack.nth_last(N_ARGS - 4)?.as_usize();
        let args_length = geth_step.stack.nth_last(N_ARGS - 3)?.as_usize();
        let ret_offset = geth_step.stack.nth_last(N_ARGS - 2)?.as_usize();
        let ret_length = geth_step.stack.nth_last(N_ARGS - 1)?.as_usize();

        // we need to keep the memory until parse_call complete
        state.call_expand_memory(args_offset, args_length, ret_offset, ret_length)?;

        let tx_id = state.tx_ctx.id();
        let call = state.parse_call(geth_step)?;
        let current_call = state.call()?.clone();

        // NOTE: For `RwCounterEndOfReversion` we use the `0` value as a placeholder,
        // and later set the proper value in
        // `CircuitInputBuilder::set_value_ops_call_context_rwc_eor`
        for (field, value) in [
            (CallContextField::TxId, tx_id.into()),
            (CallContextField::RwCounterEndOfReversion, 0.into()),
            (
                CallContextField::IsPersistent,
                (current_call.is_persistent as u64).into(),
            ),
            (
                CallContextField::CalleeAddress,
                current_call.address.to_word(),
            ),
            (
                CallContextField::IsStatic,
                (current_call.is_static as u64).into(),
            ),
            (CallContextField::Depth, current_call.depth.into()),
        ] {
            state.call_context_read(&mut exec_step, current_call.call_id, field, value);
        }

        for i in 0..N_ARGS {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        state.stack_write(
            &mut exec_step,
            geth_step.stack.nth_last_filled(N_ARGS - 1),
            (call.is_success as u64).into(),
        )?;

        let is_warm = state.sdb.check_account_in_access_list(&call.address);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id,
                address: call.address,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        // Switch to callee's call context
        state.push_call(call.clone());

        for (field, value) in [
            (CallContextField::RwCounterEndOfReversion, 0.into()),
            (
                CallContextField::IsPersistent,
                (call.is_persistent as u64).into(),
            ),
        ] {
            state.call_context_write(&mut exec_step, call.call_id, field, value);
        }

        state.transfer(
            &mut exec_step,
            call.caller_address,
            call.address,
            call.value,
        )?;

        let (_, callee_account) = state.sdb.get_account(&call.address);
        let callee_account = callee_account.clone();

        let is_empty_account = callee_account.is_empty();
        let callee_nonce = callee_account.nonce;
        let mut callee_code_hash = call.code_hash;
        if callee_code_hash.is_zero() {
            callee_code_hash = H256::from(*EMPTY_HASH);
            assert!(callee_code_hash.to_fixed_bytes() == *EMPTY_HASH);
        }
        debug_assert!(!callee_code_hash.is_zero());

        // TODO: remove value_prev argument from account_read
        state.account_read(
            &mut exec_step,
            call.address,
            AccountField::Nonce,
            callee_nonce,
            callee_nonce,
        )?;
        let code_source = match call.code_source {
            CodeSource::Address(address) => address,
            _ => unreachable!(),
        };
        state.account_write(
            &mut exec_step,
            code_source,
            AccountField::CodeHash,
            callee_code_hash.to_word(),
            callee_code_hash.to_word(),
        )?;

        // Calculate next_memory_word_size and callee_gas_left manually in case
        // there isn't next geth_step (e.g. callee doesn't have code).
        debug_assert_eq!(exec_step.memory_size % 32, 0);
        let curr_memory_word_size = (exec_step.memory_size as u64) / 32;
        let next_memory_word_size = [
            curr_memory_word_size,
            (call.call_data_offset + call.call_data_length + 31) / 32,
            (call.return_data_offset + call.return_data_length + 31) / 32,
        ]
        .into_iter()
        .max()
        .unwrap();

        let has_value = !call.value.is_zero();
        let memory_expansion_gas_cost =
            memory_expansion_gas_cost(curr_memory_word_size, next_memory_word_size);
        let gas_cost = if is_warm {
            GasCost::WARM_ACCESS.as_u64()
        } else {
            GasCost::COLD_ACCOUNT_ACCESS.as_u64()
        } + if has_value {
            GasCost::CALL_WITH_VALUE.as_u64()
                + if is_empty_account {
                    GasCost::NEW_ACCOUNT.as_u64()
                } else {
                    0
                }
        } else {
            0
        } + memory_expansion_gas_cost;
        let gas_specified = geth_step.stack.last()?;
        let callee_gas_left = eip150_gas(geth_step.gas.0 - gas_cost, gas_specified);

        if geth_steps[0].op == OpcodeId::CALL
            && geth_steps[1].depth == geth_steps[0].depth + 1
            && geth_steps[1].gas.0 != callee_gas_left + if has_value { 2300 } else { 0 }
        {
            // panic with full info
            let info1 = format!("callee_gas_left {} gas_specified {} gas_cost {} is_warm {} has_value {} is_empty_account {} current_memory_word_size {} next_memory_word_size {}, memory_expansion_gas_cost {}",
                    callee_gas_left, gas_specified, gas_cost, is_warm, has_value, is_empty_account, curr_memory_word_size, next_memory_word_size, memory_expansion_gas_cost);
            let info2 = format!("args gas:{:?} addr:{:?} value:{:?} cd_pos:{:?} cd_len:{:?} rd_pos:{:?} rd_len:{:?}",
                        geth_step.stack.nth_last(0),
                        geth_step.stack.nth_last(1),
                        geth_step.stack.nth_last(2),
                        geth_step.stack.nth_last(3),
                        geth_step.stack.nth_last(4),
                        geth_step.stack.nth_last(5),
                        geth_step.stack.nth_last(6)
                    );
            let full_ctx = format!(
                "step0 {:?} step1 {:?} call {:?}, {} {}",
                geth_steps[0], geth_steps[1], call, info1, info2
            );
            debug_assert_eq!(
                geth_steps[1].gas.0,
                callee_gas_left + if has_value { 2300 } else { 0 },
                "{}",
                full_ctx
            );
        }

        // There are 3 branches from here.
        let code_address = call.code_address();
        match (
            code_address
                .map(|ref addr| state.is_precompiled(addr))
                .unwrap_or(false),
            callee_code_hash.to_fixed_bytes() == *EMPTY_HASH,
        ) {
            // 1. Call to precompiled.
            (true, _) => {
                warn!("Call to precompiled is left unimplemented");

                for (field, value) in [
                    (CallContextField::LastCalleeId, 0.into()),
                    (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                    (CallContextField::LastCalleeReturnDataLength, 0.into()),
                ] {
                    state.call_context_write(&mut exec_step, current_call.call_id, field, value);
                }
                state.handle_return(geth_step)?;
                let real_cost = geth_steps[0].gas.0 - geth_steps[1].gas.0;
                if real_cost != exec_step.gas_cost.0 {
                    log::warn!(
                        "precompile gas fixed from {} to {}, step {:?}",
                        exec_step.gas_cost.0,
                        real_cost,
                        geth_steps[0]
                    );
                }
                exec_step.gas_cost = GasCost(real_cost);
                Ok(vec![exec_step])
            }
            // 2. Call to account with empty code.
            (_, true) => {
                log::warn!("Call to account with empty code is not supported yet.");
                for (field, value) in [
                    (CallContextField::LastCalleeId, 0.into()),
                    (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                    (CallContextField::LastCalleeReturnDataLength, 0.into()),
                ] {
                    state.call_context_write(&mut exec_step, current_call.call_id, field, value);
                }
                state.handle_return(geth_step)?;

                // FIXME
                let real_cost = geth_steps[0].gas.0 - geth_steps[1].gas.0;
                if real_cost != exec_step.gas_cost.0 {
                    log::warn!(
                        "empty call gas fixed from {} to {}, step {:?}",
                        exec_step.gas_cost.0,
                        real_cost,
                        geth_steps[0]
                    );
                }
                exec_step.gas_cost = GasCost(real_cost);

                Ok(vec![exec_step])
            }
            // 3. Call to account with non-empty code.
            (_, false) => {
                for (field, value) in [
                    (
                        CallContextField::ProgramCounter,
                        (geth_step.pc.0 + 1).into(),
                    ),
                    (
                        CallContextField::StackPointer,
                        (geth_step.stack.stack_pointer().0 + N_ARGS - 1).into(),
                    ),
                    (
                        CallContextField::GasLeft,
                        (geth_step.gas.0 - geth_step.gas_cost.0).into(),
                    ),
                    (CallContextField::MemorySize, next_memory_word_size.into()),
                    (
                        CallContextField::ReversibleWriteCounter,
                        (exec_step.reversible_write_counter + 1).into(),
                    ),
                ] {
                    state.call_context_write(&mut exec_step, current_call.call_id, field, value);
                }

                for (field, value) in [
                    (CallContextField::CallerId, current_call.call_id.into()),
                    (CallContextField::TxId, tx_id.into()),
                    (CallContextField::Depth, call.depth.into()),
                    (
                        CallContextField::CallerAddress,
                        call.caller_address.to_word(),
                    ),
                    (CallContextField::CalleeAddress, call.address.to_word()),
                    (
                        CallContextField::CallDataOffset,
                        call.call_data_offset.into(),
                    ),
                    (
                        CallContextField::CallDataLength,
                        call.call_data_length.into(),
                    ),
                    (
                        CallContextField::ReturnDataOffset,
                        call.return_data_offset.into(),
                    ),
                    (
                        CallContextField::ReturnDataLength,
                        call.return_data_length.into(),
                    ),
                    (CallContextField::Value, call.value),
                    (CallContextField::IsSuccess, (call.is_success as u64).into()),
                    (CallContextField::IsStatic, (call.is_static as u64).into()),
                    (CallContextField::LastCalleeId, 0.into()),
                    (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                    (CallContextField::LastCalleeReturnDataLength, 0.into()),
                    (CallContextField::IsRoot, 0.into()),
                    (CallContextField::IsCreate, 0.into()),
                    (CallContextField::CodeHash, call.code_hash.to_word()),
                ] {
                    state.call_context_write(&mut exec_step, call.call_id, field, value);
                }

                Ok(vec![exec_step])
            }
        }
    }
}

#[cfg(feature = "skip")]
mod return_tests {
    use crate::mock::BlockData;
    use eth_types::geth_types::GethData;
    use eth_types::{bytecode, word};
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;

    #[test]
    fn test_precompiled_call() {
        let code = bytecode! {
            PUSH16(word!("0123456789ABCDEF0123456789ABCDEF"))
            PUSH1(0x00)
            MSTORE

            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x00)
            PUSH1(0x00)
            PUSH1(0x04)
            PUSH1(0xFF)
            CALL
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
    fn test_precompiled_callcode() {
        let code = bytecode! {
            PUSH16(word!("0123456789ABCDEF0123456789ABCDEF"))
            PUSH1(0x00)
            MSTORE

            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x00)
            PUSH1(0x00)
            PUSH1(0x04)
            PUSH1(0xFF)
            CALLCODE
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
    fn test_precompiled_static_call() {
        let code = bytecode! {
            PUSH16(word!("0123456789ABCDEF0123456789ABCDEF"))
            PUSH1(0x00)
            MSTORE

            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x00)
            PUSH1(0x04)
            PUSH1(0xFF)
            STATICCALL
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
    fn test_precompiled_delegate_call() {
        let code = bytecode! {
            PUSH16(word!("0123456789ABCDEF0123456789ABCDEF"))
            PUSH1(0x00)
            MSTORE

            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x00)
            PUSH1(0x04)
            PUSH1(0xFF)
            DELEGATECALL
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
