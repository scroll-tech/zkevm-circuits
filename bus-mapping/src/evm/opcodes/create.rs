use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
    },
    error::{ContractAddressCollisionError, ExecError},
    evm::{Opcode, OpcodeId},
    operation::{AccountField, AccountOp, CallContextField, MemoryOp, RW},
    state_db::CodeDB,
    Error,
};
use eth_types::{Bytecode, GethExecStep, ToBigEndian, ToWord, Word, H160, H256};
use ethers_core::utils::{get_create2_address, keccak256, rlp};

#[derive(Debug, Copy, Clone)]
pub struct Create<const IS_CREATE2: bool>;

impl<const IS_CREATE2: bool> Opcode for Create<IS_CREATE2> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        // Get low Uint64 of offset.
        let offset = geth_step.stack.nth_last(1)?.low_u64() as usize;
        let length = geth_step.stack.nth_last(2)?.as_usize();

        if length != 0 {
            state
                .call_ctx_mut()?
                .memory
                .extend_at_least(offset + length);
        }
        let next_memory_word_size = state.call_ctx()?.memory_word_size();

        let callee = state.parse_call(geth_step)?;

        let n_pop = if IS_CREATE2 { 4 } else { 3 };
        for i in 0..n_pop {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        let address = if IS_CREATE2 {
            state.create2_address(&geth_steps[0])?
        } else {
            state.create_address()?
        };

        let callee_account = &state.sdb.get_account(&address).1.clone();
        let callee_exists = !callee_account.is_empty();
        if !callee_exists && callee.value.is_zero() {
            state.sdb.get_account_mut(&address).1.storage.clear();
        }

        state.stack_write(
            &mut exec_step,
            geth_step.stack.nth_last_filled(n_pop - 1),
            if callee.is_success {
                address.to_word()
            } else {
                Word::zero()
            },
        )?;

        let (initialization_code, keccak_code_hash, code_hash) = if length > 0 {
            handle_copy(state, &mut exec_step, state.call()?.call_id, offset, length)?
        } else {
            (vec![], H256(keccak256([])), CodeDB::empty_code_hash())
        };

        let tx_id = state.tx_ctx.id();
        let caller = state.call()?.clone();

        state.call_context_read(
            &mut exec_step,
            caller.call_id,
            CallContextField::TxId,
            tx_id.to_word(),
        );
        state.reversion_info_read(&mut exec_step, &caller);
        state.tx_access_list_write(&mut exec_step, address)?;

        let depth = caller.depth;
        state.call_context_read(
            &mut exec_step,
            caller.call_id,
            CallContextField::Depth,
            depth.to_word(),
        );

        state.call_context_read(
            &mut exec_step,
            caller.call_id,
            CallContextField::CalleeAddress,
            caller.address.to_word(),
        );

        let caller_balance = state.sdb.get_balance(&callee.caller_address);
        state.account_read(
            &mut exec_step,
            callee.caller_address,
            AccountField::Balance,
            caller_balance,
        );

        let caller_nonce = state.sdb.get_nonce(&caller.address);
        state.account_read(
            &mut exec_step,
            callee.caller_address,
            AccountField::Nonce,
            caller_nonce.into(),
        );

        // Check if an error of ErrDepth, ErrInsufficientBalance or
        // ErrNonceUintOverflow occurred.
        let is_precheck_ok =
            depth < 1025 && caller_balance >= callee.value && caller_nonce < u64::MAX;

        if is_precheck_ok {
            // Increase caller's nonce
            state.push_op_reversible(
                &mut exec_step,
                AccountOp {
                    address: caller.address,
                    field: AccountField::Nonce,
                    value: (caller_nonce + 1).into(),
                    value_prev: caller_nonce.into(),
                },
            )?;
        }

        // TODO: look into when this can be pushed. Could it be done in parse call?
        state.push_call(callee.clone());

        for (field, value) in [
            (
                CallContextField::RwCounterEndOfReversion,
                callee.rw_counter_end_of_reversion.to_word(),
            ),
            (
                CallContextField::IsPersistent,
                callee.is_persistent.to_word(),
            ),
        ] {
            state.call_context_write(&mut exec_step, callee.call_id, field, value);
        }

        // if address created before, nonce is not zero

        // this could be good place for checking callee_exists = true, since above
        // operation happens in evm create() method before checking
        // ErrContractAddressCollision
        let code_hash_previous = if callee_exists {
            if is_precheck_ok {
                // CREATE2 may cause address collision error. And for a tricky
                // case of CREATE, it could also cause this error. e.g. the `to`
                // field of transaction is set to the calculated contract
                // address (reference testool case
                // `RevertDepthCreateAddressCollision_d0_g0_v0` for details).
                exec_step.error = Some(ExecError::ContractAddressCollision(match geth_step.op {
                    OpcodeId::CREATE => ContractAddressCollisionError::Create,
                    OpcodeId::CREATE2 => ContractAddressCollisionError::Create2,
                    op => unreachable!(
                        "Contract address collision error is unexpected for opcode: {:?}",
                        op
                    ),
                }));
            }
            callee_account.code_hash
        } else {
            H256::zero()
        };

        // use CodeHash rw not zero to check address already exists
        state.account_read(
            &mut exec_step,
            address,
            AccountField::CodeHash,
            code_hash_previous.to_word(),
        );

        if is_precheck_ok && !callee_exists {
            state.transfer(
                &mut exec_step,
                callee.caller_address,
                callee.address,
                true,
                true,
                callee.value,
            )?;
            state.push_op_reversible(
                &mut exec_step,
                AccountOp {
                    address: callee.address,
                    field: AccountField::Nonce,
                    value: 1.into(),
                    value_prev: 0.into(),
                },
            )?;
        }

        // Per EIP-150, all but one 64th of the caller's gas is sent to the
        // initialization call.
        let caller_gas_left = (geth_step.gas.0 - geth_step.gas_cost.0) / 64;

        for (field, value) in [
            (
                CallContextField::ProgramCounter,
                (geth_step.pc.0 + 1).into(),
            ),
            (
                CallContextField::StackPointer,
                geth_step.stack.nth_last_filled(n_pop - 1).0.into(),
            ),
            (CallContextField::GasLeft, caller_gas_left.into()),
            (CallContextField::MemorySize, next_memory_word_size.into()),
            (
                CallContextField::ReversibleWriteCounter,
                (exec_step.reversible_write_counter + 2).into(),
            ),
        ] {
            state.call_context_write(&mut exec_step, caller.call_id, field, value);
        }

        if !is_precheck_ok {
            for (field, value) in [
                (CallContextField::LastCalleeId, 0.into()),
                (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                (CallContextField::LastCalleeReturnDataLength, 0.into()),
            ] {
                state.call_context_write(&mut exec_step, caller.call_id, field, value);
            }
            state.handle_return(&mut exec_step, geth_steps, false)?;
            return Ok(vec![exec_step]);
        }

        for (field, value) in [
            (CallContextField::CallerId, caller.call_id.into()),
            (CallContextField::IsSuccess, callee.is_success.to_word()),
            (
                CallContextField::IsPersistent,
                callee.is_persistent.to_word(),
            ),
            (CallContextField::TxId, state.tx_ctx.id().into()),
            (
                CallContextField::CallerAddress,
                callee.caller_address.to_word(),
            ),
            (CallContextField::CalleeAddress, callee.address.to_word()),
            (
                CallContextField::RwCounterEndOfReversion,
                callee.rw_counter_end_of_reversion.to_word(),
            ),
            (CallContextField::Depth, callee.depth.to_word()),
            (CallContextField::IsRoot, false.to_word()),
            (CallContextField::IsStatic, false.to_word()),
            (CallContextField::IsCreate, true.to_word()),
            (CallContextField::CodeHash, code_hash.to_word()),
            (CallContextField::Value, callee.value),
        ] {
            state.call_context_write(&mut exec_step, callee.call_id, field, value);
        }

        let keccak_input = if IS_CREATE2 {
            let salt = geth_step.stack.nth_last(3)?;
            assert_eq!(
                address,
                get_create2_address(
                    caller.address,
                    salt.to_be_bytes().to_vec(),
                    initialization_code.clone(),
                )
            );
            std::iter::once(0xffu8)
                .chain(caller.address.to_fixed_bytes())
                .chain(salt.to_be_bytes())
                .chain(keccak_code_hash.to_fixed_bytes())
                .collect::<Vec<_>>()
        } else {
            let mut stream = rlp::RlpStream::new();
            stream.begin_list(2);
            stream.append(&caller.address);
            stream.append(&Word::from(caller_nonce));
            stream.out().to_vec()
        };

        assert_eq!(
            address,
            H160(keccak256(&keccak_input)[12..].try_into().unwrap())
        );

        state.block.sha3_inputs.push(keccak_input);
        state.block.sha3_inputs.push(initialization_code);

        if length == 0 || callee_exists {
            for (field, value) in [
                (CallContextField::LastCalleeId, 0.into()),
                (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                (CallContextField::LastCalleeReturnDataLength, 0.into()),
            ] {
                state.call_context_write(&mut exec_step, caller.call_id, field, value);
            }
            state.handle_return(&mut exec_step, geth_steps, false)?;
        }

        Ok(vec![exec_step])
    }
}

fn handle_copy(
    state: &mut CircuitInputStateRef,
    step: &mut ExecStep,
    callee_id: usize,
    offset: usize,
    length: usize,
) -> Result<(Vec<u8>, H256, H256), Error> {
    let initialization_bytes = state.call_ctx()?.memory.0[offset..offset + length].to_vec();
    let keccak_code_hash = H256(keccak256(&initialization_bytes));
    let code_hash = CodeDB::hash(&initialization_bytes);
    let bytes: Vec<_> = Bytecode::from(initialization_bytes.clone())
        .code
        .iter()
        .map(|element| (element.value, element.is_code))
        .collect();

    let rw_counter_start = state.block_ctx.rwc;
    for (i, (byte, _)) in bytes.iter().enumerate() {
        // this could be a memory read, if this happens before we push the new call?
        state.push_op(
            step,
            RW::READ,
            MemoryOp::new(callee_id, (offset + i).into(), *byte),
        );
    }

    state.push_copy(
        step,
        CopyEvent {
            rw_counter_start,
            src_type: CopyDataType::Memory,
            src_id: NumberOrHash::Number(callee_id),
            src_addr: offset.try_into().unwrap(),
            src_addr_end: (offset + length).try_into().unwrap(),
            dst_type: CopyDataType::Bytecode,
            dst_id: NumberOrHash::Hash(code_hash),
            dst_addr: 0,
            log_id: None,
            bytes,
        },
    );

    Ok((initialization_bytes, keccak_code_hash, code_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuit_input_builder::ExecState, mock::BlockData, operation::RW};
    use eth_types::{bytecode, evm_types::OpcodeId, geth_types::GethData, word};
    use mock::{test_ctx::helpers::account_0_code_account_1_no_code, TestContext};

    #[test]
    fn test_create_address_collision_error() {
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000F3600052600C6014F3"))
            PUSH1(0)
            MSTORE

            PUSH1 (0xef) // salt
            PUSH1 (0x15) // size
            PUSH1 (0xB) // offset
            PUSH1 (0)   // value
            CREATE2

            PUSH1 (0xef) // salt
            PUSH1 (0x15) // size
            PUSH1 (0xB) // offset
            PUSH1 (0)   // value
            CREATE2

            PUSH1 (0x20)   // retLength
            PUSH1 (0x20)   // retOffset
            PUSH1 (0x20)   // argsLength
            PUSH1 (0x00)      // argsOffset
            PUSH1 (0x00)      // value
            DUP6           // addr from above CREATE2
            PUSH2 (0xFFFF) // gas
            CALL
            STOP
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, accs| {
                txs[0].from(accs[1].address).to(accs[0].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let tx_id = 1;
        let transaction = &builder.block.txs()[tx_id - 1];
        let step = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::CREATE2))
            .last()
            .unwrap();

        assert_eq!(
            step.error,
            Some(ExecError::ContractAddressCollision(
                ContractAddressCollisionError::Create2
            ))
        );

        let container = builder.block.container.clone();
        let operation = &container.stack[step.bus_mapping_instance[0].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
    }
}
