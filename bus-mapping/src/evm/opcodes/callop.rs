use super::Opcode;
use crate::{
    circuit_input_builder::{
        CallKind, CircuitInputStateRef, CodeSource, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
    },
    evm::opcodes::precompiles::gen_associated_ops as precompile_associated_ops,
    operation::{AccountField, CallContextField, MemoryOp, TxAccessListAccountOp, RW},
    precompile::{execute_precompiled, is_precompiled, PrecompileCalls},
    state_db::CodeDB,
    Error,
};
use eth_types::{
    evm_types::{
        gas_utils::{eip150_gas, memory_expansion_gas_cost},
        Gas, GasCost, OpcodeId,
    },
    GethExecStep, ToWord, Word,
};
use std::cmp::min;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the `OpcodeId::CALL`, `OpcodeId::CALLCODE`,
/// `OpcodeId::DELEGATECALL` and `OpcodeId::STATICCALL`.
/// - CALL and CALLCODE: N_ARGS = 7
/// - DELEGATECALL and STATICCALL: N_ARGS = 6
#[derive(Debug, Copy, Clone)]
pub(crate) struct CallOpcode<const N_ARGS: usize>;

impl<const N_ARGS: usize> Opcode for CallOpcode<N_ARGS> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let args_offset = geth_step.stack.nth_last(N_ARGS - 4)?.low_u64() as usize;
        let args_length = geth_step.stack.nth_last(N_ARGS - 3)?.as_usize();
        let ret_offset = geth_step.stack.nth_last(N_ARGS - 2)?.low_u64() as usize;
        let ret_length = geth_step.stack.nth_last(N_ARGS - 1)?.as_usize();

        // we need to keep the memory until parse_call complete
        state.call_expand_memory(args_offset, args_length, ret_offset, ret_length)?;

        let tx_id = state.tx_ctx.id();
        let call = state.parse_call(geth_step)?;
        let current_call = state.call()?.clone();

        // For both CALLCODE and DELEGATECALL opcodes, `call.address` is caller
        // address which is different from callee_address (code address).
        let callee_address = match call.code_source {
            CodeSource::Address(address) => address,
            _ => call.address,
        };

        let mut field_values = vec![
            (CallContextField::TxId, tx_id.into()),
            // NOTE: For `RwCounterEndOfReversion` we use the `0` value as a
            // placeholder, and later set the proper value in
            // `CircuitInputBuilder::set_value_ops_call_context_rwc_eor`
            (CallContextField::RwCounterEndOfReversion, 0.into()),
            (
                CallContextField::IsPersistent,
                (current_call.is_persistent as u64).into(),
            ),
            (
                CallContextField::IsStatic,
                (current_call.is_static as u64).into(),
            ),
            (CallContextField::Depth, current_call.depth.into()),
            (
                CallContextField::CalleeAddress,
                current_call.address.to_word(),
            ),
        ];
        if call.kind == CallKind::DelegateCall {
            field_values.extend([
                (
                    CallContextField::CallerAddress,
                    current_call.caller_address.to_word(),
                ),
                (CallContextField::Value, current_call.value),
            ]);
        }
        for (field, value) in field_values {
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

        let callee_code_hash = call.code_hash;
        let callee_exists = !state.sdb.get_account(&callee_address).1.is_empty();

        let (callee_code_hash_word, is_empty_code_hash) = if callee_exists {
            (
                callee_code_hash.to_word(),
                callee_code_hash == CodeDB::empty_code_hash(),
            )
        } else {
            (Word::zero(), true)
        };
        state.account_read(
            &mut exec_step,
            callee_address,
            AccountField::CodeHash,
            callee_code_hash_word,
        );

        let is_warm = state.sdb.check_account_in_access_list(&callee_address);
        state.push_op_reversible(
            &mut exec_step,
            TxAccessListAccountOp {
                tx_id,
                address: callee_address,
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

        let (found, sender_account) = state.sdb.get_account(&call.caller_address);
        debug_assert!(found);

        let caller_balance = sender_account.balance;
        let is_call_or_callcode = call.kind == CallKind::Call || call.kind == CallKind::CallCode;

        // Precheck is OK when depth is in range and caller balance is sufficient.
        let is_precheck_ok =
            geth_step.depth < 1025 && (!is_call_or_callcode || caller_balance >= call.value);

        // read balance of caller to compare to value for insufficient_balance checking
        // in circuit, also use for callcode successful case check balance is
        // indeed larger than transfer value. for call opcode, it does in
        // tranfer gadget implicitly.
        state.account_read(
            &mut exec_step,
            call.caller_address,
            AccountField::Balance,
            caller_balance,
        );

        let code_address = call.code_address();
        let is_precompile = code_address
            .map(|ref addr| is_precompiled(addr))
            .unwrap_or(false);
        // TODO: What about transfer for CALLCODE?
        // Transfer value only for CALL opcode, is_precheck_ok = true.
        if call.kind == CallKind::Call && is_precheck_ok {
            state.transfer(
                &mut exec_step,
                call.caller_address,
                call.address,
                callee_exists || is_precompile,
                false,
                call.value,
            )?;
        }

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

        let has_value = !call.value.is_zero() && !call.is_delegatecall();
        let memory_expansion_gas_cost =
            memory_expansion_gas_cost(curr_memory_word_size, next_memory_word_size);
        let gas_cost = if is_warm {
            GasCost::WARM_ACCESS.as_u64()
        } else {
            GasCost::COLD_ACCOUNT_ACCESS.as_u64()
        } + if has_value {
            GasCost::CALL_WITH_VALUE.as_u64()
                + if call.kind == CallKind::Call && !callee_exists {
                    GasCost::NEW_ACCOUNT.as_u64()
                } else {
                    0
                }
        } else {
            0
        } + memory_expansion_gas_cost;
        let gas_specified = geth_step.stack.last()?;
        debug_assert!(
            geth_step.gas.0 >= gas_cost,
            "gas {:?} gas_cost {:?} memory_expansion_gas_cost {:?}",
            geth_step.gas.0,
            gas_cost,
            memory_expansion_gas_cost
        );
        let callee_gas_left = eip150_gas(geth_step.gas.0 - gas_cost, gas_specified);

        // There are 4 branches from here.
        // add failure case for insufficient balance or error depth in the future.
        if geth_steps[0].op == OpcodeId::CALL
            && geth_steps[1].depth == geth_steps[0].depth + 1
            && geth_steps[1].gas.0 != callee_gas_left + if has_value { 2300 } else { 0 }
        {
            // panic with full info
            let info1 = format!("callee_gas_left {} gas_specified {} gas_cost {} is_warm {} has_value {} current_memory_word_size {} next_memory_word_size {}, memory_expansion_gas_cost {}",
                    callee_gas_left, gas_specified, gas_cost, is_warm, has_value, curr_memory_word_size, next_memory_word_size, memory_expansion_gas_cost);
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

        match (!is_precheck_ok, is_precompile, is_empty_code_hash) {
            // 1. Call to precompiled.
            (false, true, _) => {
                let code_address = code_address.unwrap();
                let precompile_call: PrecompileCalls = code_address.0[19].into();

                // get the result of the precompile call.
                let caller_ctx = state.caller_ctx()?;
                let caller_memory = caller_ctx.memory.0.clone();
                let (result, contract_gas_cost) = execute_precompiled(
                    &code_address,
                    if args_length != 0 {
                        &caller_memory[args_offset..args_offset + args_length]
                    } else {
                        &[]
                    },
                    callee_gas_left,
                );

                // mutate the caller memory.
                let caller_ctx_mut = state.caller_ctx_mut()?;
                caller_ctx_mut.return_data = result.clone();
                let length = min(result.len(), ret_length);
                if length > 0 {
                    caller_ctx_mut.memory.extend_at_least(ret_offset + length);
                    caller_ctx_mut.memory.0[ret_offset..ret_offset + length]
                        .copy_from_slice(&result[..length]);
                }

                for (field, value) in [
                    (
                        CallContextField::IsSuccess,
                        Word::from(call.is_success as u64),
                    ),
                    (
                        CallContextField::CalleeAddress,
                        call.code_address().unwrap().to_word(),
                    ),
                    (CallContextField::CallerId, call.caller_id.into()),
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
                ] {
                    state.call_context_write(&mut exec_step, call.call_id, field, value);
                }

                // return while restoring some of caller's context.
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
                        (geth_steps[0].gas.0 - gas_cost - contract_gas_cost).into(),
                    ),
                    (CallContextField::MemorySize, next_memory_word_size.into()),
                    (
                        CallContextField::ReversibleWriteCounter,
                        (exec_step.reversible_write_counter + 1).into(),
                    ),
                    (CallContextField::LastCalleeId, call.call_id.into()),
                    (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                    (
                        CallContextField::LastCalleeReturnDataLength,
                        result.len().into(),
                    ),
                ] {
                    state.call_context_write(&mut exec_step, current_call.call_id, field, value);
                }

                // insert a copy event (input) for this step
                let rw_counter_start = state.block_ctx.rwc;
                let n_input_bytes = if let Some(input_len) = precompile_call.input_len() {
                    std::cmp::min(input_len, call.call_data_length as usize)
                } else {
                    call.call_data_length as usize
                };
                let input_bytes = if call.call_data_length > 0 {
                    let bytes: Vec<(u8, bool)> = caller_memory
                        .iter()
                        .skip(call.call_data_offset as usize)
                        .take(n_input_bytes)
                        .map(|b| (*b, false))
                        .collect();
                    for (i, &(byte, _is_code)) in bytes.iter().enumerate() {
                        // push caller memory read
                        state.push_op(
                            &mut exec_step,
                            RW::READ,
                            MemoryOp::new(
                                call.caller_id,
                                (call.call_data_offset + i as u64).into(),
                                byte,
                            ),
                        );
                    }
                    state.push_copy(
                        &mut exec_step,
                        CopyEvent {
                            src_id: NumberOrHash::Number(call.caller_id),
                            src_type: CopyDataType::Memory,
                            src_addr: call.call_data_offset,
                            src_addr_end: call.call_data_offset + n_input_bytes as u64,
                            dst_id: NumberOrHash::Number(call.call_id),
                            dst_type: CopyDataType::Precompile(precompile_call),
                            dst_addr: 0,
                            log_id: None,
                            rw_counter_start,
                            bytes: bytes.clone(),
                        },
                    );
                    Some(bytes.iter().map(|t| t.0).collect())
                } else {
                    None
                };

                // write the result in the callee's memory.
                let rw_counter_start = state.block_ctx.rwc;
                let output_bytes =
                    if call.is_success() && call.call_data_length > 0 && !result.is_empty() {
                        let bytes: Vec<(u8, bool)> = result.iter().map(|b| (*b, false)).collect();
                        for (i, &(byte, _is_code)) in bytes.iter().enumerate() {
                            // push callee memory write
                            state.push_op(
                                &mut exec_step,
                                RW::WRITE,
                                MemoryOp::new(call.call_id, i.into(), byte),
                            );
                        }
                        state.push_copy(
                            &mut exec_step,
                            CopyEvent {
                                src_id: NumberOrHash::Number(call.call_id),
                                src_type: CopyDataType::Precompile(precompile_call),
                                src_addr: 0,
                                src_addr_end: result.len() as u64,
                                dst_id: NumberOrHash::Number(call.call_id),
                                dst_type: CopyDataType::Memory,
                                dst_addr: 0,
                                log_id: None,
                                rw_counter_start,
                                bytes: bytes.clone(),
                            },
                        );
                        Some(bytes.iter().map(|t| t.0).collect())
                    } else {
                        None
                    };

                // insert another copy event (output) for this step.
                let rw_counter_start = state.block_ctx.rwc;
                let returned_bytes = if call.is_success() && call.call_data_length > 0 && length > 0
                {
                    let bytes: Vec<(u8, bool)> =
                        result.iter().take(length).map(|b| (*b, false)).collect();
                    for (i, &(byte, _is_code)) in bytes.iter().enumerate() {
                        // push caller memory write
                        state.push_op(
                            &mut exec_step,
                            RW::WRITE,
                            MemoryOp::new(
                                call.caller_id,
                                (call.return_data_offset + i as u64).into(),
                                byte,
                            ),
                        );
                    }
                    state.push_copy(
                        &mut exec_step,
                        CopyEvent {
                            src_id: NumberOrHash::Number(call.call_id),
                            src_type: CopyDataType::Precompile(precompile_call),
                            src_addr: 0,
                            src_addr_end: length as u64,
                            dst_id: NumberOrHash::Number(call.caller_id),
                            dst_type: CopyDataType::Memory,
                            dst_addr: call.return_data_offset,
                            log_id: None,
                            rw_counter_start,
                            bytes: bytes.clone(),
                        },
                    );
                    Some(bytes.iter().map(|t| t.0).collect())
                } else {
                    None
                };

                let mut precompile_step = precompile_associated_ops(
                    state,
                    geth_steps[1].clone(),
                    call.clone(),
                    precompile_call,
                    (input_bytes, output_bytes, returned_bytes),
                )?;

                // Make the Precompile execution step to handle return logic and restore to caller
                // context (similar as STOP and RETURN).
                state.handle_return(&mut precompile_step, geth_steps, true)?;

                let real_cost = geth_steps[0].gas.0 - geth_steps[1].gas.0;
                debug_assert_eq!(real_cost, gas_cost + contract_gas_cost);
                exec_step.gas_cost = GasCost(gas_cost + contract_gas_cost);
                if real_cost != exec_step.gas_cost.0 {
                    log::warn!(
                        "precompile gas fixed from {} to {}, step {:?}",
                        exec_step.gas_cost.0,
                        real_cost,
                        geth_steps[0]
                    );
                }

                // Set gas left and gas cost for precompile step.
                precompile_step.gas_left = Gas(callee_gas_left);
                precompile_step.gas_cost = GasCost(contract_gas_cost);

                Ok(vec![exec_step, precompile_step])
            }
            // 2. Call to account with empty code.
            (false, _, true) => {
                for (field, value) in [
                    (CallContextField::LastCalleeId, 0.into()),
                    (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                    (CallContextField::LastCalleeReturnDataLength, 0.into()),
                ] {
                    state.call_context_write(&mut exec_step, current_call.call_id, field, value);
                }
                state.handle_return(&mut exec_step, geth_steps, false)?;

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
            (false, _, false) => {
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
                    (
                        CallContextField::Value,
                        // Should set to value of current call for DELEGATECALL.
                        if call.kind == CallKind::DelegateCall {
                            current_call.value
                        } else {
                            call.value
                        },
                    ),
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

            // 4. insufficient balance or error depth cases.
            (true, _, _) => {
                for (field, value) in [
                    (CallContextField::LastCalleeId, 0.into()),
                    (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                    (CallContextField::LastCalleeReturnDataLength, 0.into()),
                ] {
                    state.call_context_write(&mut exec_step, current_call.call_id, field, value);
                }
                state.handle_return(&mut exec_step, geth_steps, false)?;
                Ok(vec![exec_step])
            } //
        }
    }
}

#[cfg(any(test, feature = "test"))]
pub mod tests {
    use eth_types::{evm_types::OpcodeId, Bytecode, Word};

    /// Precompile call args
    pub struct PrecompileCallArgs {
        /// description for the instance of a precompile call.
        pub name: &'static str,
        /// the bytecode that when call can produce the desired precompile call.
        pub setup_code: Bytecode,
        /// the call's return data size.
        pub ret_size: Word,
        /// the call's return data offset.
        pub ret_offset: Word,
        /// the call's calldata offset.
        pub call_data_offset: Word,
        /// the call's calldata length.
        pub call_data_length: Word,
        /// the address to which the call is made, i.e. callee address.
        pub address: Word,
        /// the optional value sent along with the call.
        pub value: Word,
        /// the gas limit for the call.
        pub gas: Word,
        /// stack values during the call.
        pub stack_value: Vec<(Word, Word)>,
        /// maximum number of RW entries for the call.
        pub max_rws: usize,
    }

    impl Default for PrecompileCallArgs {
        fn default() -> Self {
            PrecompileCallArgs {
                name: "precompiled call",
                setup_code: Bytecode::default(),
                ret_size: Word::zero(),
                ret_offset: Word::zero(),
                call_data_offset: Word::zero(),
                call_data_length: Word::zero(),
                address: Word::zero(),
                value: Word::zero(),
                gas: Word::from(0xFFFFFFF),
                stack_value: vec![],
                max_rws: 1000,
            }
        }
    }

    impl PrecompileCallArgs {
        /// Get the setup bytecode for call to a precompiled contract.
        pub fn with_call_op(&self, call_op: OpcodeId) -> Bytecode {
            assert!(
                call_op.is_call(),
                "invalid setup, {:?} is not a call op",
                call_op
            );
            let mut code = self.setup_code.clone();
            code.push(32, self.ret_size)
                .push(32, self.ret_offset)
                .push(32, self.call_data_length)
                .push(32, self.call_data_offset);
            if call_op == OpcodeId::CALL || call_op == OpcodeId::CALLCODE {
                code.push(32, self.value);
            }
            code.push(32, self.address)
                .push(32, self.gas)
                .write_op(call_op)
                .write_op(OpcodeId::POP);
            for (offset, _) in self.stack_value.iter().rev() {
                code.push(32, *offset).write_op(OpcodeId::MLOAD);
            }

            code
        }
    }

    // move this to circuit after circuit part is complete
    #[test]
    fn test_precompiled_call() {
        use crate::{circuit_input_builder::CircuitsParams, mock::BlockData};
        use eth_types::{bytecode, evm_types::OpcodeId, geth_types::GethData, word, Word};
        use mock::{
            test_ctx::{
                helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
                LoggerConfig,
            },
            TestContext,
        };

        let test_vector = [
            PrecompileCallArgs {
                name: "ecRecover",
                setup_code: bytecode! {
                    PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3")) // hash
                    PUSH1(0x0)
                    MSTORE
                    PUSH1(28) // v
                    PUSH1(0x20)
                    MSTORE
                    PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608")) // r
                    PUSH1(0x40)
                    MSTORE
                    PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada")) // s
                    PUSH1(0x60)
                    MSTORE
                },
                ret_size: Word::from(0x20),
                ret_offset: Word::from(0x80),
                call_data_length: Word::from(0x80),
                address: Word::from(0x1),
                stack_value: vec![(
                    Word::from(0x80),
                    word!("7156526fbd7a3c72969b54f64e42c10fbb768c8a"),
                )],
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "SHA2-256",
                setup_code: bytecode! {
                    PUSH1(0xFF) // data
                    PUSH1(0)
                    MSTORE
                },
                ret_size: Word::from(0x20),
                ret_offset: Word::from(0x20),
                call_data_length: Word::from(0x1),
                call_data_offset: Word::from(0x1F),
                address: Word::from(0x2),
                stack_value: vec![(
                    Word::from(0x20),
                    word!("a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89"),
                )],
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "RIPEMD-160",
                setup_code: bytecode! {
                    PUSH1(0xFF) // data
                    PUSH1(0)
                    MSTORE
                },
                ret_size: Word::from(0x20),
                ret_offset: Word::from(0x20),
                call_data_length: Word::from(0x1),
                call_data_offset: Word::from(0x1F),
                address: Word::from(0x3),
                stack_value: vec![(
                    Word::from(0x20),
                    word!("2c0c45d3ecab80fe060e5f1d7057cd2f8de5e557"),
                )],
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "identity",
                setup_code: bytecode! {
                    PUSH16(word!("0123456789ABCDEF0123456789ABCDEF"))
                    PUSH1(0x00)
                    MSTORE
                },
                ret_size: Word::from(0x20),
                ret_offset: Word::from(0x20),
                call_data_length: Word::from(0x20),
                address: Word::from(0x4),
                stack_value: vec![(Word::from(0x20), word!("0123456789ABCDEF0123456789ABCDEF"))],
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "modexp",
                setup_code: bytecode! {
                    PUSH1(1) // Bsize
                    PUSH1(0)
                    MSTORE
                    PUSH1(1) // Esize
                    PUSH1(0x20)
                    MSTORE
                    PUSH1(1) // Msize
                    PUSH1(0x40)
                    MSTORE
                    PUSH32(word!("0x08090A0000000000000000000000000000000000000000000000000000000000")) // B, E and M
                    PUSH1(0x60)
                    MSTORE
                },
                ret_size: Word::from(0x01),
                ret_offset: Word::from(0x9F),
                call_data_length: Word::from(0x63),
                address: Word::from(0x5),
                stack_value: vec![(Word::from(0x80), Word::from(8))],
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecAdd",
                setup_code: bytecode! {
                    PUSH1(1) // x1
                    PUSH1(0)
                    MSTORE
                    PUSH1(2) // y1
                    PUSH1(0x20)
                    MSTORE
                    PUSH1(1) // x2
                    PUSH1(0x40)
                    MSTORE
                    PUSH1(2) // y2
                    PUSH1(0x60)
                    MSTORE
                },
                ret_size: Word::from(0x40),
                ret_offset: Word::from(0x80),
                call_data_length: Word::from(0x80),
                address: Word::from(0x6),
                stack_value: vec![
                    (
                        Word::from(0x80),
                        word!("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3"),
                    ),
                    (
                        Word::from(0xA0),
                        word!("15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4"),
                    ),
                ],
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecMul",
                setup_code: bytecode! {
                    PUSH1(1) // x1
                    PUSH1(0)
                    MSTORE
                    PUSH1(2) // y1
                    PUSH1(0x20)
                    MSTORE
                    PUSH1(2) // s
                    PUSH1(0x40)
                    MSTORE
                },
                ret_size: Word::from(0x40),
                ret_offset: Word::from(0x60),
                call_data_length: Word::from(0x60),
                address: Word::from(0x7),
                stack_value: vec![
                    (
                        Word::from(0x60),
                        word!("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3"),
                    ),
                    (
                        Word::from(0x80),
                        word!("15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4"),
                    ),
                ],
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing",
                setup_code: bytecode! {
                    PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                    PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                    PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                    PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                    PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                    PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                    PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                    PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                    PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                    PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
                    PUSH32(word!("0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
                    PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"))

                    PUSH1(12)
                    PUSH2(0x200)
                    MSTORE

                    JUMPDEST

                    PUSH2(0x200)
                    MLOAD
                    PUSH1(12)
                    SUB
                    PUSH1(0x20)
                    MUL
                    MSTORE
                    PUSH1(1)
                    PUSH2(0x200)
                    MLOAD
                    SUB
                    DUP1
                    PUSH2(0x200)
                    MSTORE
                    PUSH2(0x192)
                    JUMPI
                },
                ret_size: Word::from(0x20),
                call_data_length: Word::from(0x180),
                address: Word::from(0x8),
                stack_value: vec![(Word::from(0x0), Word::from(1))],
                max_rws: 3000,
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "blake2f",
                setup_code: bytecode! {
                    PUSH32(word!("0000000003000000000000000000000000000000010000000000000000000000"))
                    PUSH32(word!("0000000000000000000000000000000000000000000000000000000000000000"))
                    PUSH32(word!("0000000000000000000000000000000000000000000000000000000000000000"))
                    PUSH32(word!("0000000000000000000000000000000000000000000000000000000000000000"))
                    PUSH32(word!("19cde05b61626300000000000000000000000000000000000000000000000000"))
                    PUSH32(word!("3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e13"))
                    PUSH32(word!("0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f"))

                    PUSH1(7)
                    PUSH2(0x160)
                    MSTORE

                    JUMPDEST

                    PUSH2(0x160)
                    MLOAD
                    PUSH1(7)
                    SUB
                    PUSH1(0x20)
                    MUL
                    MSTORE
                    PUSH1(1)
                    PUSH2(0x160)
                    MLOAD
                    SUB
                    DUP1
                    PUSH2(0x160)
                    MSTORE
                    PUSH2(0xed)
                    JUMPI
                },
                ret_size: Word::from(0x40),
                ret_offset: Word::from(0x0),
                call_data_length: Word::from(0xd5),
                address: Word::from(0x9),
                stack_value: vec![
                    (
                        Word::from(0x20),
                        word!("d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b"),
                    ),
                    (
                        Word::from(0x0),
                        word!("8c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"),
                    ),
                ],
                max_rws: 3000,
                ..Default::default()
            },
        ];

        let call_ops = [
            OpcodeId::CALL,
            OpcodeId::CALLCODE,
            OpcodeId::DELEGATECALL,
            OpcodeId::STATICCALL,
        ];

        for (test_call, call_op) in itertools::iproduct!(test_vector.iter(), call_ops.iter()) {
            let code = test_call.with_call_op(*call_op);
            let block: GethData = TestContext::<2, 1>::new_with_logger_config(
                None,
                account_0_code_account_1_no_code(code),
                tx_from_1_to_0,
                |block, _tx| block.number(0xcafeu64),
                LoggerConfig {
                    enable_memory: true,
                    ..Default::default()
                },
            )
            .unwrap()
            .into();

            let mut builder = BlockData::new_from_geth_data_with_params(
                block.clone(),
                CircuitsParams {
                    max_rws: test_call.max_rws,
                    ..Default::default()
                },
            )
            .new_circuit_input_builder();
            builder
                .handle_block(&block.eth_block, &block.geth_traces)
                .unwrap();

            let step = block.geth_traces[0]
                .struct_logs
                .last()
                .expect("at least one step");
            log::debug!("{:?}", step.stack);
            for (offset, (_, stack_value)) in test_call.stack_value.iter().enumerate() {
                assert_eq!(
                    *stack_value,
                    step.stack.nth_last(offset).expect("stack value not found"),
                    "stack output mismatch {}",
                    test_call.name
                );
            }
        }
    }
}
