use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::Opcode;
use crate::operation::{AccountField, AccountOp, CallContextField, TxAccessListAccountOp, RW};
use crate::Error;
use eth_types::{evm_types::gas_utils::memory_expansion_gas_cost, GethExecStep, ToWord};
use keccak256::EMPTY_HASH;

#[derive(Debug, Copy, Clone)]
pub struct DummyCreate<const IS_CREATE2: bool>;

impl<const IS_CREATE2: bool> Opcode for DummyCreate<IS_CREATE2> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        // TODO: replace dummy create here
        let geth_step = &geth_steps[0];

        let offset = geth_step.stack.nth_last(1)?.as_usize();
        let length = geth_step.stack.nth_last(2)?.as_usize();

        let curr_memory_word_size = (state.call_ctx()?.memory.len() as u64) / 32;
        if length != 0 {
            state
                .call_ctx_mut()?
                .memory
                .extend_at_least(offset + length);
        }
        let next_memory_word_size = (state.call_ctx()?.memory.len() as u64) / 32;

        let mut exec_step = state.new_step(geth_step)?;

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

        state.stack_write(
            &mut exec_step,
            geth_step.stack.nth_last_filled(n_pop - 1),
            address.to_word(),
        )?;

        let tx_id = state.tx_ctx.id();
        let call = state.parse_call(geth_step)?;
        let current_call = state.call()?.clone();

        // Quote from [EIP-2929](https://eips.ethereum.org/EIPS/eip-2929)
        // > When a CREATE or CREATE2 opcode is called,
        // > immediately (i.e. before checks are done to determine
        // > whether or not the address is unclaimed)
        // > add the address being created to accessed_addresses,
        // > but gas costs of CREATE and CREATE2 are unchanged
        let is_warm = state.sdb.check_account_in_access_list(&address);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        // Increase caller's nonce
        let nonce_prev = state.sdb.get_nonce(&call.caller_address);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            AccountOp {
                address: call.caller_address,
                field: AccountField::Nonce,
                value: (nonce_prev + 1).into(),
                value_prev: nonce_prev.into(),
            },
        )?;

        // Add callee into access list
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

        state.push_call(call.clone());

        // Increase callee's nonce
        let nonce_prev = state.sdb.get_nonce(&call.address);
        debug_assert!(nonce_prev == 0);
        state.push_op_reversible(
            &mut exec_step,
            RW::WRITE,
            AccountOp {
                address: call.address,
                field: AccountField::Nonce,
                value: 1.into(),
                value_prev: 0.into(),
            },
        )?;

        state.transfer(
            &mut exec_step,
            call.caller_address,
            call.address,
            call.value,
        )?;

        let memory_expansion_gas_cost =
            memory_expansion_gas_cost(curr_memory_word_size, next_memory_word_size);

        // EIP-150: all but one 64th of the caller's gas is sent to the callee.
        let caller_gas_left =
            (geth_step.gas.0 - geth_step.gas_cost.0 - memory_expansion_gas_cost) / 64;

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
                // +3 is because we do some transfers after pushing the call. can be just push the
                // call later?
                (exec_step.reversible_write_counter + 3).into(),
            ),
        ] {
            state.call_context_write(&mut exec_step, current_call.call_id, field, value);
        }

        for (field, value) in [
            (CallContextField::CallerId, current_call.call_id.into()),
            (CallContextField::IsSuccess, call.is_success.to_word()),
            (CallContextField::IsPersistent, call.is_persistent.to_word()),
            (CallContextField::TxId, state.tx_ctx.id().into()),
            (
                CallContextField::CallerAddress,
                current_call.address.to_word(),
            ),
            (CallContextField::CalleeAddress, call.address.to_word()),
        ] {
            state.call_context_write(&mut exec_step, call.call_id, field, value);
        }

        // state.push_call(call.clone());

        if call.code_hash.to_fixed_bytes() == *EMPTY_HASH {
            // 1. Create with empty initcode.
            state.handle_return(geth_step)?;
            Ok(vec![exec_step])
        } else {
            // 2. Create with non-empty initcode.
            Ok(vec![exec_step])
        }
    }
}
