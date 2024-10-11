use super::{
    error_oog_precompile::ErrorOOGPrecompile,
    precompiles::gen_ops as precompile_gen_ops_for_begin_tx,
};
use crate::{
    circuit_input_builder::{
        curie::is_curie_enabled, Call, CircuitInputStateRef, CopyAccessList, CopyBytes,
        CopyDataType, CopyEvent, ExecStep, NumberOrHash,
    },
    l2_predeployed::l1_gas_price_oracle,
    operation::{
        AccountField, AccountOp, CallContextField, StorageOp, TxReceiptField, TxRefundOp, RW,
    },
    precompile::{execute_precompiled, PrecompileCalls},
    Error,
};
use eth_types::{
    evm_types::{
        gas_utils::{tx_access_list_gas_cost, tx_data_gas_cost},
        GasCost, MAX_REFUND_QUOTIENT_OF_GAS_USED,
    },
    state_db::CodeDB,
    utils::is_precompiled,
    Bytecode, ToWord, Word,
};
use ethers_core::utils::get_contract_address;

// #[derive(Clone, Copy, Debug)]
// pub(crate) struct BeginEndTx;

// impl TxExecSteps for BeginEndTx {
//     fn gen_associated_steps(
//         state: &mut CircuitInputStateRef,
//         execution_step: ExecState,
//     ) -> Result<ExecStep, Error> {
//         match execution_step {
//             ExecState::BeginTx => gen_begin_tx_steps(state),
//             ExecState::EndTx => gen_end_tx_steps(state),
//             _ => {
//                 unreachable!()
//             }
//         }
//     }
// }

pub fn gen_begin_tx_steps(state: &mut CircuitInputStateRef) -> Result<Vec<ExecStep>, Error> {
    let mut exec_step = state.new_begin_tx_step();
    let call = state.call()?.clone();

    // write tx_id
    begin_tx(state, &mut exec_step, &call)?;

    // Add two copy-events for tx access-list addresses and storage keys for
    // EIP-1559 and EIP-2930.
    gen_tx_access_list_ops(state, &mut exec_step)?;

    let caller_address = call.caller_address;
    if state.tx.tx_type.is_l1_msg() {
        // for l1 message, no need to add rw op, but we must check
        // caller for its existent status

        // notice the caller must existed after a l1msg tx, so we
        // create it here
        let caller_acc = state.sdb.get_account(&caller_address).1.clone();

        state.account_read(
            &mut exec_step,
            caller_address,
            AccountField::CodeHash,
            caller_acc.code_hash_read().to_word(),
        )?;

        if caller_acc.is_empty() {
            log::info!("create account for {:?} inside l1msg tx", caller_address);

            // notice the op is not reversible, since the nonce increasing is
            // inreversible
            state.account_write(
                &mut exec_step,
                caller_address,
                AccountField::CodeHash,
                caller_acc.code_hash.to_word(),
                Word::zero(),
            )?;

            #[cfg(feature = "scroll")]
            {
                state.account_write(
                    &mut exec_step,
                    caller_address,
                    AccountField::KeccakCodeHash,
                    caller_acc.keccak_code_hash.to_word(),
                    Word::zero(),
                )?;
            }
        }
    } else {
        // else, add 6 RW read operations for transaction L1 fee.
        gen_tx_l1_fee_ops(state, &mut exec_step)?;
    }

    log::trace!("write tx l1fee {}", state.tx.l1_fee());
    state.call_context_write(
        &mut exec_step,
        call.call_id,
        CallContextField::L1Fee,
        Word::from(state.tx.l1_fee()),
    )?;

    // the rw delta before is:
    // + for non-l1 msg tx: 3 or 6 (rw for fee oracle contrace)
    // + for scroll l1-msg tx:
    //   * caller existed: 1 (read codehash)
    //   * caller not existed: 3 (read codehash and create account)
    // + for non-scroll l1-msg tx:
    //   * caller existed: 1 (read codehash)
    //   * caller not existed: 2 (read codehash and create account)
    // * write l1fee call context

    for (field, value) in [
        (
            CallContextField::RwCounterEndOfReversion,
            call.rw_counter_end_of_reversion.into(),
        ),
        (
            CallContextField::IsPersistent,
            (call.is_persistent as usize).into(),
        ),
        (CallContextField::IsSuccess, call.is_success.to_word()),
    ] {
        state.call_context_write(&mut exec_step, call.call_id, field, value)?;
    }

    // Increase caller's nonce
    let nonce_prev = state.sdb.get_nonce(&caller_address);
    //debug_assert!(nonce_prev <= state.tx.nonce);
    //while nonce_prev < state.tx.nonce {
    //    state.sdb.increase_nonce(&caller_address);
    //    nonce_prev = state.sdb.get_nonce(&caller_address);
    //    log::warn!("[debug] increase nonce to {}", nonce_prev);
    //}
    state.account_write(
        &mut exec_step,
        caller_address,
        AccountField::Nonce,
        (nonce_prev + 1).into(),
        nonce_prev.into(),
    )?;

    // Add precompile contract address to access list
    for address in 1..=9 {
        let address = eth_types::Address::from_low_u64_be(address);
        let is_warm_prev = !state.sdb.add_account_to_access_list(address);
        state.tx_access_list_account_write(
            &mut exec_step,
            state.tx_ctx.id(),
            address,
            true,
            is_warm_prev,
        )?;
    }

    // Add caller, callee and coinbase (only for Shanghai) to access list.
    let accessed_addresses = [
        call.caller_address,
        call.address,
        state
            .block
            .blocks
            .get(&state.tx.block_num)
            .unwrap()
            .coinbase,
    ];
    for address in accessed_addresses {
        let is_warm_prev = !state.sdb.add_account_to_access_list(address);
        state.tx_access_list_account_write(
            &mut exec_step,
            state.tx_ctx.id(),
            address,
            true,
            is_warm_prev,
        )?;
    }

    // Calculate gas cost of init code only for EIP-3860 of Shanghai.
    let init_code_gas_cost = if state.tx.is_create() {
        (state.tx.input.len() as u64 + 31) / 32 * eth_types::evm_types::INIT_CODE_WORD_GAS
    } else {
        0
    };

    // Calculate intrinsic gas cost
    let call_data_gas_cost = tx_data_gas_cost(&state.tx.input);
    let access_list_gas_cost = tx_access_list_gas_cost(&state.tx.access_list);
    let intrinsic_gas_cost = if state.tx.is_create() {
        GasCost::CREATION_TX.as_u64()
    } else {
        GasCost::TX.as_u64()
    } + call_data_gas_cost
        + access_list_gas_cost
        + init_code_gas_cost;
    log::trace!("intrinsic_gas_cost {intrinsic_gas_cost}, call_data_gas_cost {call_data_gas_cost}, access_list_gas_cost {access_list_gas_cost}, init_code_gas_cost {init_code_gas_cost}, &mut exec_step.gas_cost {:?}", &mut exec_step.gas_cost);
    exec_step.gas_cost = GasCost(intrinsic_gas_cost);

    // Get code_hash of callee account
    let callee_account = &state.sdb.get_account(&call.address).1.clone();
    let is_precompile = is_precompiled(&call.address);
    let callee_exists = !callee_account.is_empty();
    //if !callee_exists && call.value.is_zero() {
    if callee_account.code_hash == CodeDB::empty_code_hash() {
        // The account is empty (codehash and nonce be 0) while storage is non empty.
        // It is an impossible case for any real world scenario.
        // The "clear" helps with testool.
        state.sdb.get_account_mut(&call.address).1.storage.clear();
    }
    let account_code_hash = if callee_exists {
        callee_account.code_hash.to_word()
    } else {
        Word::zero()
    };
    // call_code is code being executed
    let call_code_hash = call.code_hash.to_word();
    if !state.tx.is_create() && !account_code_hash.is_zero() {
        debug_assert_eq!(account_code_hash, call_code_hash);
    }
    let account_code_hash_is_empty_or_zero =
        account_code_hash.is_zero() || account_code_hash == CodeDB::empty_code_hash().to_word();

    state.account_read(
        &mut exec_step,
        call.address,
        AccountField::CodeHash,
        account_code_hash,
    )?;

    if state.tx.is_create()
        && ((!account_code_hash_is_empty_or_zero) || !callee_account.nonce.is_zero())
    {
        // since there is a bug in the prestate
        // tracer: https://github.com/ethereum/go-ethereum/issues/28439
        // which may also act as the data source for our statedb,
        // we have to relax the constraint a bit and fix it silently
        if account_code_hash_is_empty_or_zero && callee_account.nonce == 1.into() {
            log::warn!(
                "fix deployment nonce for {:?} silently for the prestate tracer",
                call.address,
            );
            let mut fixed_account = callee_account.clone();
            fixed_account.nonce = Word::zero();
            state.sdb.set_account(&call.address, fixed_account);
        } else {
            unimplemented!(
                "deployment collision at {:?}, account {:?}",
                call.address,
                callee_account
            );
        }
    }

    // Transfer with fee
    let fee = if state.tx.tx_type.is_l1_msg() {
        0.into()
    } else {
        state.tx.gas_price * state.tx.gas + state.tx_ctx.l1_fee
    };
    state.transfer_with_fee(
        &mut exec_step,
        call.caller_address,
        call.address,
        callee_exists,
        call.is_create(),
        call.value,
        Some(fee),
    )?;

    // In case of contract creation we wish to verify the correctness of the
    // contract's address (callee). This address is defined as:
    //
    // Keccak256(RLP([tx_caller, tx_nonce]))[12:]
    //
    // We feed the RLP-encoded bytes to the block's SHA3 inputs, which gets assigned
    // to the Keccak circuit, so that the BeginTxGadget can do a lookup to the
    // Keccak table and verify the contract address.
    if state.tx.is_create() {
        // 1. add RLP-bytes for contract address to keccak circuit.
        let address_preimage = {
            let mut stream = ethers_core::utils::rlp::RlpStream::new();
            stream.begin_list(2);
            stream.append(&caller_address);
            stream.append(&nonce_prev);
            stream.out().to_vec()
        };
        state.block.sha3_inputs.push(address_preimage);
        // 2. add init code to keccak circuit.
        let initcode = state.tx.input.clone();
        let length = initcode.len();
        state.block.sha3_inputs.push(initcode.clone());
        // 3. add init code to copy circuit.
        let code_hash = state.code_db.insert(initcode.clone());
        let bytes = Bytecode::from(initcode)
            .code
            .iter()
            .map(|element| (element.value, element.is_code, false))
            .collect::<Vec<(u8, bool, bool)>>();

        let rw_counter_start = state.block_ctx.rwc;
        state.push_copy(
            &mut exec_step,
            CopyEvent {
                src_addr: 0,
                src_addr_end: length as u64,
                src_type: CopyDataType::TxCalldata,
                src_id: NumberOrHash::Number(state.tx_ctx.id()),
                dst_addr: 0,
                dst_type: CopyDataType::Bytecode,
                dst_id: NumberOrHash::Hash(code_hash),
                log_id: None,
                rw_counter_start,
                copy_bytes: CopyBytes::new(bytes, None, None),
                access_list: vec![],
            },
        )?;
    }

    let mut precompile_step = None;

    // There are 4 branches from here.
    match (
        call.is_create(),
        is_precompile,
        account_code_hash_is_empty_or_zero,
    ) {
        // 1. Creation transaction.
        (true, _, _) => {
            state.push_op_reversible(
                &mut exec_step,
                AccountOp {
                    address: call.address,
                    field: AccountField::Nonce,
                    value: 1.into(),
                    value_prev: 0.into(),
                },
            )?;
            for (field, value) in [
                (CallContextField::Depth, call.depth.into()),
                (
                    CallContextField::CallerAddress,
                    call.caller_address.to_word(),
                ),
                (
                    CallContextField::CalleeAddress,
                    get_contract_address(caller_address, nonce_prev).to_word(),
                ),
                (
                    CallContextField::CallDataOffset,
                    call.call_data_offset.into(),
                ),
                (CallContextField::CallDataLength, 0.into()),
                (CallContextField::Value, call.value),
                (CallContextField::IsStatic, (call.is_static as usize).into()),
                (CallContextField::LastCalleeId, 0.into()),
                (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                (CallContextField::LastCalleeReturnDataLength, 0.into()),
                (CallContextField::IsRoot, 1.into()),
                (CallContextField::IsCreate, 1.into()),
                (CallContextField::CodeHash, call.code_hash.to_word()),
            ] {
                state.call_context_write(&mut exec_step, call.call_id, field, value)?;
            }
        }
        /*
         2. Call to precompiled.

           + Set up the root call's context like the tx is calling non-empty code
           + Add an additional copy event like we have done in the `CallOp` step.
             It copied the `TxCalldata` into the root calls, with form of `RlcAcc`.
           + Prepare a precompile step to be returned, so in this case `gen_begin_tx_steps`
             would return 2 steps instead of 1
        */
        (_, true, _) => {
            // some *pre-handling* for precompile address, like what we have done in callop
            // the generation of precompile step is in `handle_tx`, right after the generation
            // of begin_tx step

            // add dummy field which precompile call contexts needed
            for (field, value) in [
                (CallContextField::ReturnDataOffset, 0.into()),
                (CallContextField::ReturnDataLength, 0.into()),
            ] {
                state.call_context_write(&mut exec_step, call.call_id, field, value)?;
            }

            // init call context fields like calling normal contract
            for (field, value) in [
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
                (CallContextField::Value, call.value),
                (CallContextField::IsStatic, (call.is_static as usize).into()),
                (CallContextField::LastCalleeId, 0.into()),
                (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                (CallContextField::LastCalleeReturnDataLength, 0.into()),
                (CallContextField::IsRoot, 1.into()),
                (CallContextField::IsCreate, call.is_create().to_word()),
                (CallContextField::CodeHash, account_code_hash),
            ] {
                state.call_context_write(&mut exec_step, call.call_id, field, value)?;
            }

            let precompile_call: PrecompileCalls = call.address.0[19].into();
            let (result, precompile_call_gas_cost, has_oog_err) = execute_precompiled(
                &precompile_call.into(),
                &state.tx.input,
                exec_step.gas_left.0 - exec_step.gas_cost.as_u64(),
            );

            // insert a copy event (input) generate word memory read for input.
            // we do not handle output / return since it is not part of the mined tx
            let n_input_bytes = if let Some(input_len) = precompile_call.input_len() {
                std::cmp::min(input_len as u64, call.call_data_length)
            } else {
                call.call_data_length
            };
            // we copy the truncated part or whole call data
            let src_addr = call.call_data_offset;
            let src_addr_end = call.call_data_offset.checked_add(n_input_bytes).unwrap();

            let copy_steps = state
                .tx
                .input
                .iter()
                .copied()
                .take(n_input_bytes as usize)
                .map(|b| (b, false, false))
                .collect::<Vec<_>>();

            let input_bytes = copy_steps
                .iter()
                .filter(|(_, _, is_mask)| !*is_mask)
                .map(|t| t.0)
                .collect::<Vec<u8>>();
            let rw_counter_start = state.block_ctx.rwc;
            state.push_copy(
                &mut exec_step,
                CopyEvent {
                    src_id: NumberOrHash::Number(state.tx_ctx.id()),
                    src_type: CopyDataType::TxCalldata,
                    src_addr,
                    src_addr_end,
                    dst_id: NumberOrHash::Number(call.call_id),
                    dst_type: CopyDataType::RlcAcc,
                    dst_addr: 0,
                    log_id: None,
                    rw_counter_start,
                    copy_bytes: CopyBytes::new(copy_steps, None, None),
                    access_list: vec![],
                },
            )?;

            let call_success = call.is_success;
            // modexp's oog error is handled in ModExpGadget
            let mut next_step = if has_oog_err && precompile_call != PrecompileCalls::Modexp {
                let next_step = state.new_next_step(&exec_step)?;
                log::debug!(
                    "precompile call ({:?}) runs out of gas: callee_gas_left = {}",
                    precompile_call,
                    next_step.gas_left.0,
                );

                ErrorOOGPrecompile::gen_ops(state, next_step, call)
            } else {
                precompile_gen_ops_for_begin_tx(
                    state,
                    state.new_next_step(&exec_step)?,
                    call,
                    precompile_call,
                    &input_bytes,
                    &result,
                    &[], // notice we suppose return is omitted
                )
            }?;

            // adjust gas cost
            next_step.gas_cost = GasCost(precompile_call_gas_cost);

            // notice we are handling a 'handle_return' process without associated geth step
            // 1.handle reversion if needed
            if !call_success {
                state.handle_reversion(&mut [&mut exec_step, &mut next_step]);
            }
            // 2.pop call ctx
            state.tx_ctx.pop_call_ctx(call_success);
            precompile_step.replace(next_step);
        }
        (_, _, is_empty_code_hash) => {
            // 3. Call to account with empty code (is_empty_code_hash == true).
            // 4. Call to account with non-empty code (is_empty_code_hash == false).
            if !is_empty_code_hash {
                for (field, value) in [
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
                    (CallContextField::Value, call.value),
                    (CallContextField::IsStatic, (call.is_static as usize).into()),
                    (CallContextField::LastCalleeId, 0.into()),
                    (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                    (CallContextField::LastCalleeReturnDataLength, 0.into()),
                    (CallContextField::IsRoot, 1.into()),
                    (CallContextField::IsCreate, call.is_create().to_word()),
                    (CallContextField::CodeHash, call_code_hash),
                ] {
                    state.call_context_write(&mut exec_step, call.call_id, field, value)?;
                }
            }
        }
    }
    log::trace!("begin_tx_step: {:?}, {:?}", exec_step, precompile_step);

    Ok(std::iter::once(exec_step).chain(precompile_step).collect())
}

pub fn gen_end_tx_steps(state: &mut CircuitInputStateRef) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_end_tx_step();
    let call = state.tx.calls()[0].clone();

    state.call_context_read(
        &mut exec_step,
        call.call_id,
        CallContextField::TxId,
        state.tx_ctx.id().into(),
    )?;
    state.call_context_read(
        &mut exec_step,
        call.call_id,
        CallContextField::IsPersistent,
        Word::from(call.is_persistent as u8),
    )?;
    state.call_context_read(
        &mut exec_step,
        call.call_id,
        CallContextField::L1Fee,
        Word::from(state.tx.l1_fee()),
    )?;

    let refund = state.sdb.refund();
    state.push_op(
        &mut exec_step,
        RW::READ,
        TxRefundOp {
            tx_id: state.tx_ctx.id(),
            value: refund,
            value_prev: refund,
        },
    )?;

    let effective_refund =
        refund.min((state.tx.gas - exec_step.gas_left.0) / MAX_REFUND_QUOTIENT_OF_GAS_USED as u64);
    let (found, caller_account) = state.sdb.get_account(&call.caller_address);
    if !found {
        return Err(Error::AccountNotFound(call.caller_address));
    }
    let caller_balance_prev = caller_account.balance;
    let effective_refund_balance = state.tx.gas_price * (exec_step.gas_left.0 + effective_refund);
    let caller_balance = caller_balance_prev + effective_refund_balance;

    if !state.tx.tx_type.is_l1_msg() {
        log::trace!(
            "call balance refund {:?}, now {:?}",
            effective_refund_balance,
            caller_balance
        );
        state.account_write(
            &mut exec_step,
            call.caller_address,
            AccountField::Balance,
            caller_balance,
            caller_balance_prev,
        )?;
    } else {
        log::trace!("l1 tx, no refund");
    }

    let block_info = state.block.blocks.get(&state.tx.block_num).unwrap().clone();
    let effective_tip = if cfg!(feature = "scroll") {
        state.tx.gas_price
    } else {
        state.tx.gas_price - block_info.base_fee
    };
    let gas_cost = state.tx.gas - exec_step.gas_left.0 - effective_refund;
    let coinbase_reward = if state.tx.tx_type.is_l1_msg() {
        Word::zero()
    } else {
        let coinbase_reward = effective_tip * gas_cost + state.tx_ctx.l1_fee;
        log::trace!(
            "coinbase reward = ({} - {}) * ({} - {} - {}) + {} = {}",
            state.tx.gas_price,
            block_info.base_fee,
            state.tx.gas,
            exec_step.gas_left.0,
            effective_refund,
            state.tx_ctx.l1_fee,
            coinbase_reward
        );

        coinbase_reward
    };
    let (found, coinbase_account) = state.sdb.get_account_mut(&block_info.coinbase);
    if !found {
        log::error!("coinbase account not found: {}", block_info.coinbase);
        return Err(Error::AccountNotFound(block_info.coinbase));
    }
    let coinbase_account = coinbase_account.clone();
    state.account_read(
        &mut exec_step,
        block_info.coinbase,
        AccountField::CodeHash,
        if coinbase_account.is_empty() {
            Word::zero()
        } else {
            coinbase_account.code_hash.to_word()
        },
    )?;

    if !state.tx.tx_type.is_l1_msg() {
        state.transfer_to(
            &mut exec_step,
            block_info.coinbase,
            !coinbase_account.is_empty(),
            false,
            coinbase_reward,
            false,
        )?;
    }

    end_tx(state, &mut exec_step, &call)?;

    Ok(exec_step)
}

pub(crate) fn begin_tx(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    call: &Call,
) -> Result<(), Error> {
    // Write the transaction id
    state.call_context_write(
        exec_step,
        call.call_id,
        CallContextField::TxId,
        state.tx_ctx.id().into(),
    )?;
    Ok(())
}

pub(crate) fn end_tx(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    call: &Call,
) -> Result<(), Error> {
    // Write the tx receipt
    write_tx_receipt(state, exec_step, call.is_persistent)?;

    Ok(())
}

fn write_tx_receipt(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    is_persistent: bool,
) -> Result<(), Error> {
    // handle tx receipt tag
    state.tx_receipt_write(
        exec_step,
        state.tx_ctx.id(),
        TxReceiptField::PostStateOrStatus,
        is_persistent as u64,
    )?;

    let log_id = exec_step.log_id;
    state.tx_receipt_write(
        exec_step,
        state.tx_ctx.id(),
        TxReceiptField::LogLength,
        log_id as u64,
    )?;

    if state.tx_ctx.id() > 1 {
        // query pre tx cumulative gas
        state.tx_receipt_read(
            exec_step,
            state.tx_ctx.id() - 1,
            TxReceiptField::CumulativeGasUsed,
            state.block_ctx.cumulative_gas_used,
        )?;
    }

    state.block_ctx.cumulative_gas_used += state.tx.gas - exec_step.gas_left.0;
    state.tx_receipt_write(
        exec_step,
        state.tx_ctx.id(),
        TxReceiptField::CumulativeGasUsed,
        state.block_ctx.cumulative_gas_used,
    )?;

    Ok(())
}

// Add 6 RW read operations for transaction L1 fee.
fn gen_tx_l1_fee_ops(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
) -> Result<(), Error> {
    let tx_id = state.tx_ctx.id();

    let base_fee = Word::from(state.tx.l1_fee.base_fee);
    let fee_overhead = Word::from(state.tx.l1_fee.fee_overhead);
    let fee_scalar = Word::from(state.tx.l1_fee.fee_scalar);
    let l1_blob_basefee = Word::from(state.tx.l1_fee.l1_blob_basefee);
    let commit_scalar = Word::from(state.tx.l1_fee.commit_scalar);
    let blob_scalar = Word::from(state.tx.l1_fee.blob_scalar);

    let base_fee_committed = Word::from(state.tx.l1_fee_committed.base_fee);
    let fee_overhead_committed = Word::from(state.tx.l1_fee_committed.fee_overhead);
    let fee_scalar_committed = Word::from(state.tx.l1_fee_committed.fee_scalar);

    let l1_blob_basefee_committed = Word::from(state.tx.l1_fee_committed.l1_blob_basefee);
    let commit_scalar_committed = Word::from(state.tx.l1_fee_committed.commit_scalar);
    let blob_scalar_committed = Word::from(state.tx.l1_fee_committed.blob_scalar);

    state.push_op(
        exec_step,
        RW::READ,
        StorageOp::new(
            *l1_gas_price_oracle::ADDRESS,
            *l1_gas_price_oracle::BASE_FEE_SLOT,
            base_fee,
            base_fee,
            tx_id,
            base_fee_committed,
        ),
    )?;
    state.push_op(
        exec_step,
        RW::READ,
        StorageOp::new(
            *l1_gas_price_oracle::ADDRESS,
            *l1_gas_price_oracle::OVERHEAD_SLOT,
            fee_overhead,
            fee_overhead,
            tx_id,
            fee_overhead_committed,
        ),
    )?;
    state.push_op(
        exec_step,
        RW::READ,
        StorageOp::new(
            *l1_gas_price_oracle::ADDRESS,
            *l1_gas_price_oracle::SCALAR_SLOT,
            fee_scalar,
            fee_scalar,
            tx_id,
            fee_scalar_committed,
        ),
    )?;

    // Sanity check: we do not support pre-curie blocks as of <https://github.com/scroll-tech/zkevm-circuits/pull/1415>
    //
    // We expect a post-curie block.
    let chain_id = state.block.chain_id;
    let block_number = state.tx.block_num;
    debug_assert!(
        is_curie_enabled(chain_id, block_number),
        "block {block_number} is pre-curie",
    );

    state.push_op(
        exec_step,
        RW::READ,
        StorageOp::new(
            *l1_gas_price_oracle::ADDRESS,
            *l1_gas_price_oracle::L1_BLOB_BASEFEE_SLOT,
            l1_blob_basefee,
            l1_blob_basefee,
            tx_id,
            l1_blob_basefee_committed,
        ),
    )?;
    state.push_op(
        exec_step,
        RW::READ,
        StorageOp::new(
            *l1_gas_price_oracle::ADDRESS,
            *l1_gas_price_oracle::COMMIT_SCALAR_SLOT,
            commit_scalar,
            commit_scalar,
            tx_id,
            commit_scalar_committed,
        ),
    )?;
    state.push_op(
        exec_step,
        RW::READ,
        StorageOp::new(
            *l1_gas_price_oracle::ADDRESS,
            *l1_gas_price_oracle::BLOB_SCALAR_SLOT,
            blob_scalar,
            blob_scalar,
            tx_id,
            blob_scalar_committed,
        ),
    )?;

    Ok(())
}

// Add two copy-events for tx access-list addresses and storage keys for
// EIP-1559 and EIP-2930.
fn gen_tx_access_list_ops(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
) -> Result<(), Error> {
    if !(state.tx.tx_type.is_eip1559() || state.tx.tx_type.is_eip2930()) {
        return Ok(());
    }

    add_access_list_address_copy_event(state, exec_step)?;
    add_access_list_storage_key_copy_event(state, exec_step)?;

    Ok(())
}

fn add_access_list_address_copy_event(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
) -> Result<(), Error> {
    let tx_id = state.tx_ctx.id();
    let rw_counter_start = state.block_ctx.rwc;

    // Build copy access list including addresses.
    let access_list = state.tx.access_list.clone().map_or(Ok(vec![]), |al| {
        al.0.iter()
            .map(|item| {
                // Add RW write operations for access list addresses
                // (will lookup in copy circuit).
                let is_warm_prev = !state.sdb.add_account_to_access_list(item.address);
                state.tx_access_list_account_write(
                    exec_step,
                    tx_id,
                    item.address,
                    true,
                    is_warm_prev,
                )?;

                // Save address, storage_key, storage_key_index and is_warm_prev
                // to column value_word_rlc, value_word_rlc_prev, value and
                // value_prev in copy circuit.
                Ok(CopyAccessList::new(
                    item.address,
                    Word::zero(),
                    0,
                    is_warm_prev,
                ))
            })
            .collect::<Result<Vec<_>, Error>>()
    })?;

    // Unnecessary to add copy event if no access-list address.
    if access_list.is_empty() {
        return Ok(());
    }

    let tx_id = NumberOrHash::Number(tx_id);

    // Use placeholder bytes for copy steps.
    let copy_bytes = CopyBytes::new(vec![(0, false, false); access_list.len()], None, None);

    // Add copy event to copy table.
    let copy_event = CopyEvent {
        src_type: CopyDataType::AccessListAddresses,
        dst_type: CopyDataType::AccessListAddresses,
        src_id: tx_id.clone(),
        dst_id: tx_id,
        // Access list address index starts from 1 in tx-table.
        src_addr: 1,
        src_addr_end: access_list.len() as u64 + 1,
        dst_addr: 1,
        rw_counter_start,
        copy_bytes,
        access_list,
        log_id: None,
    };

    state.push_copy(exec_step, copy_event)?;

    Ok(())
}

fn add_access_list_storage_key_copy_event(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
) -> Result<(), Error> {
    let tx_id = state.tx_ctx.id();
    let rw_counter_start = state.block_ctx.rwc;

    // Build copy access list including addresses and storage keys.
    let mut sks_acc: usize = 0;
    let access_list = state
        .tx
        .access_list
        .clone()
        .map_or(Ok(vec![]), |al| {
            al.0.iter()
                .map(|item| {
                    item.storage_keys
                        .iter()
                        .map(|&sk| {
                            let sk = sk.to_word();
                            sks_acc += 1;

                            // Add RW write operations for access list address storage keys
                            // (will lookup in copy circuit).
                            let is_warm_prev = !state
                                .sdb
                                .add_account_storage_to_access_list((item.address, sk));
                            state.tx_access_list_storage_key_write(
                                exec_step,
                                tx_id,
                                item.address,
                                sk,
                                true,
                                is_warm_prev,
                            )?;

                            // Save address, storage_key, storage_key_index and is_warm_prev
                            // to column value_word_rlc, value_word_rlc_prev, value and
                            // value_prev in copy circuit.
                            Ok(CopyAccessList::new(
                                item.address,
                                sk,
                                sks_acc as u64,
                                is_warm_prev,
                            ))
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, Error>>()
        })?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    // Unnecessary to add copy event if no access-list storage key.
    if access_list.is_empty() {
        return Ok(());
    }

    let tx_id = NumberOrHash::Number(state.tx_ctx.id());

    // Use placeholder bytes for copy steps.
    let copy_bytes = CopyBytes::new(vec![(0, false, false); access_list.len()], None, None);

    // Add copy event to copy table.
    let copy_event = CopyEvent {
        src_type: CopyDataType::AccessListStorageKeys,
        dst_type: CopyDataType::AccessListStorageKeys,
        src_id: tx_id.clone(),
        dst_id: tx_id,
        // Access list storage key index starts from 0 in tx-table.
        src_addr: 0,
        src_addr_end: access_list.len() as u64,
        dst_addr: 0,
        rw_counter_start,
        copy_bytes,
        access_list,
        log_id: None,
    };

    state.push_copy(exec_step, copy_event)?;

    Ok(())
}
