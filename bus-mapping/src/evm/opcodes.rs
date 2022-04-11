//! Definition of each opcode of the EVM.
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    evm::OpcodeId,
    operation::{
        AccountField, AccountOp, CallContextField, CallContextOp, TxAccessListAccountOp,
        TxRefundOp, RW,
    },
    Error,
};
use core::fmt::Debug;
use eth_types::{
    evm_types::{GasCost, MAX_REFUND_QUOTIENT_OF_GAS_USED},
    GethExecStep, ToWord,
};
use keccak256::EMPTY_HASH;
use log::warn;

mod call;
mod calldatacopy;
mod calldataload;
mod calldatasize;
mod caller;
mod callvalue;
mod chainid;
mod codecopy;
mod dup;
mod extcodehash;
mod gasprice;
mod mload;
mod mstore;
mod number;
mod origin;
mod selfbalance;
mod sload;
mod sstore;
mod stackonlyop;
mod stop;
mod swap;

use call::Call;
use calldatacopy::Calldatacopy;
use calldataload::Calldataload;
use calldatasize::Calldatasize;
use caller::Caller;
use callvalue::Callvalue;
use codecopy::Codecopy;
use dup::Dup;
use extcodehash::Extcodehash;
use gasprice::GasPrice;
use mload::Mload;
use mstore::Mstore;
use origin::Origin;
use selfbalance::Selfbalance;
use sload::Sload;
use sstore::Sstore;
use stackonlyop::StackOnlyOpcode;
use stop::Stop;
use swap::Swap;

/// Generic opcode trait which defines the logic of the
/// [`Operation`](crate::operation::Operation) that should be generated for one
/// or multiple [`ExecStep`](crate::circuit_input_builder::ExecStep) depending
/// of the [`OpcodeId`] it contains.
pub trait Opcode: Debug {
    /// Generate the associated [`MemoryOp`](crate::operation::MemoryOp)s,
    /// [`StackOp`](crate::operation::StackOp)s, and
    /// [`StorageOp`](crate::operation::StorageOp)s associated to the Opcode
    /// is implemented for.
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error>;
}

fn dummy_gen_associated_ops(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    Ok(vec![state.new_step(&geth_steps[0])?])
}

type FnGenAssociatedOps = fn(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error>;

fn fn_gen_associated_ops(opcode_id: &OpcodeId) -> FnGenAssociatedOps {
    match opcode_id {
        OpcodeId::STOP => Stop::gen_associated_ops,
        OpcodeId::ADD => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::MUL => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::SUB => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::DIV => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::SDIV => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::MOD => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::SMOD => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::ADDMOD => StackOnlyOpcode::<3, 1>::gen_associated_ops,
        OpcodeId::MULMOD => StackOnlyOpcode::<3, 1>::gen_associated_ops,
        OpcodeId::EXP => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::SIGNEXTEND => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::LT => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::GT => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::SLT => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::SGT => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::EQ => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::ISZERO => StackOnlyOpcode::<1, 1>::gen_associated_ops,
        OpcodeId::AND => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::OR => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::XOR => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::NOT => StackOnlyOpcode::<1, 1>::gen_associated_ops,
        OpcodeId::BYTE => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::SHL => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::SHR => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::SAR => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        OpcodeId::SHA3 => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        // OpcodeId::ADDRESS => {},
        // OpcodeId::BALANCE => {},
        OpcodeId::ORIGIN => Origin::gen_associated_ops,
        OpcodeId::CALLER => Caller::gen_associated_ops,
        OpcodeId::CALLVALUE => Callvalue::gen_associated_ops,
        OpcodeId::CALLDATASIZE => Calldatasize::gen_associated_ops,
        OpcodeId::CALLDATALOAD => Calldataload::gen_associated_ops,
        OpcodeId::CALLDATACOPY => Calldatacopy::gen_associated_ops,
        // OpcodeId::CODESIZE => {},
        OpcodeId::GASPRICE => GasPrice::gen_associated_ops,
        OpcodeId::CODECOPY => Codecopy::gen_associated_ops,
        // OpcodeId::EXTCODESIZE => {},
        // OpcodeId::EXTCODECOPY => {},
        // OpcodeId::RETURNDATASIZE => {},
        // OpcodeId::RETURNDATACOPY => {},
        OpcodeId::EXTCODEHASH => Extcodehash::gen_associated_ops,
        // OpcodeId::BLOCKHASH => {},
        OpcodeId::COINBASE => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::TIMESTAMP => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::NUMBER => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        // OpcodeId::DIFFICULTY => {},
        // OpcodeId::GASLIMIT => {},
        OpcodeId::CHAINID => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::SELFBALANCE => Selfbalance::gen_associated_ops,
        // OpcodeId::BASEFEE => {},
        OpcodeId::POP => StackOnlyOpcode::<1, 0>::gen_associated_ops,
        OpcodeId::MLOAD => Mload::gen_associated_ops,
        OpcodeId::MSTORE => Mstore::<false>::gen_associated_ops,
        OpcodeId::MSTORE8 => Mstore::<true>::gen_associated_ops,
        OpcodeId::SLOAD => Sload::gen_associated_ops,
        OpcodeId::SSTORE => Sstore::gen_associated_ops,
        OpcodeId::JUMP => StackOnlyOpcode::<1, 0>::gen_associated_ops,
        OpcodeId::JUMPI => StackOnlyOpcode::<2, 0>::gen_associated_ops,
        OpcodeId::PC => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::MSIZE => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::GAS => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::JUMPDEST => dummy_gen_associated_ops,
        OpcodeId::PUSH1 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH2 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH3 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH4 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH5 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH6 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH7 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH8 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH9 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH10 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH11 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH12 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH13 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH14 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH15 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH16 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH17 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH18 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH19 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH20 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH21 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH22 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH23 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH24 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH25 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH26 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH27 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH28 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH29 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH30 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH31 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::PUSH32 => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::DUP1 => Dup::<1>::gen_associated_ops,
        OpcodeId::DUP2 => Dup::<2>::gen_associated_ops,
        OpcodeId::DUP3 => Dup::<3>::gen_associated_ops,
        OpcodeId::DUP4 => Dup::<4>::gen_associated_ops,
        OpcodeId::DUP5 => Dup::<5>::gen_associated_ops,
        OpcodeId::DUP6 => Dup::<6>::gen_associated_ops,
        OpcodeId::DUP7 => Dup::<7>::gen_associated_ops,
        OpcodeId::DUP8 => Dup::<8>::gen_associated_ops,
        OpcodeId::DUP9 => Dup::<9>::gen_associated_ops,
        OpcodeId::DUP10 => Dup::<10>::gen_associated_ops,
        OpcodeId::DUP11 => Dup::<11>::gen_associated_ops,
        OpcodeId::DUP12 => Dup::<12>::gen_associated_ops,
        OpcodeId::DUP13 => Dup::<13>::gen_associated_ops,
        OpcodeId::DUP14 => Dup::<14>::gen_associated_ops,
        OpcodeId::DUP15 => Dup::<15>::gen_associated_ops,
        OpcodeId::DUP16 => Dup::<16>::gen_associated_ops,
        OpcodeId::SWAP1 => Swap::<1>::gen_associated_ops,
        OpcodeId::SWAP2 => Swap::<2>::gen_associated_ops,
        OpcodeId::SWAP3 => Swap::<3>::gen_associated_ops,
        OpcodeId::SWAP4 => Swap::<4>::gen_associated_ops,
        OpcodeId::SWAP5 => Swap::<5>::gen_associated_ops,
        OpcodeId::SWAP6 => Swap::<6>::gen_associated_ops,
        OpcodeId::SWAP7 => Swap::<7>::gen_associated_ops,
        OpcodeId::SWAP8 => Swap::<8>::gen_associated_ops,
        OpcodeId::SWAP9 => Swap::<9>::gen_associated_ops,
        OpcodeId::SWAP10 => Swap::<10>::gen_associated_ops,
        OpcodeId::SWAP11 => Swap::<11>::gen_associated_ops,
        OpcodeId::SWAP12 => Swap::<12>::gen_associated_ops,
        OpcodeId::SWAP13 => Swap::<13>::gen_associated_ops,
        OpcodeId::SWAP14 => Swap::<14>::gen_associated_ops,
        OpcodeId::SWAP15 => Swap::<15>::gen_associated_ops,
        OpcodeId::SWAP16 => Swap::<16>::gen_associated_ops,
        // OpcodeId::LOG0 => {},
        // OpcodeId::LOG1 => {},
        // OpcodeId::LOG2 => {},
        OpcodeId::LOG3 => StackOnlyOpcode::<5, 0>::gen_associated_ops,
        // OpcodeId::LOG4 => {},
        // OpcodeId::CREATE => {},
        OpcodeId::CALL => Call::gen_associated_ops,
        // OpcodeId::CALLCODE => {},
        // TODO: Handle RETURN by its own gen_associated_ops.
        OpcodeId::RETURN => Stop::gen_associated_ops,
        // OpcodeId::DELEGATECALL => {},
        // OpcodeId::CREATE2 => {},
        // OpcodeId::STATICCALL => {},
        // TODO: Handle REVERT by its own gen_associated_ops.
        OpcodeId::REVERT => Stop::gen_associated_ops,
        // OpcodeId::SELFDESTRUCT => {},
        OpcodeId::CALLCODE | OpcodeId::DELEGATECALL | OpcodeId::STATICCALL => {
            warn!("Using dummy gen_call_ops for opcode {:?}", opcode_id);
            dummy_gen_call_ops
        }
        _ => {
            warn!("Using dummy gen_associated_ops for opcode {:?}", opcode_id);
            dummy_gen_associated_ops
        }
    }
}

/// Generate the associated operations according to the particular
/// [`OpcodeId`].
pub fn gen_associated_ops(
    opcode_id: &OpcodeId,
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let fn_gen_associated_ops = fn_gen_associated_ops(opcode_id);
    fn_gen_associated_ops(state, geth_steps)
}

pub fn gen_begin_tx_ops(state: &mut CircuitInputStateRef) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_begin_tx_step();
    let call = state.call()?.clone();

    for (field, value) in [
        (CallContextField::TxId, state.tx_ctx.id().into()),
        (
            CallContextField::RwCounterEndOfReversion,
            call.rw_counter_end_of_reversion.into(),
        ),
        (
            CallContextField::IsPersistent,
            (call.is_persistent as usize).into(),
        ),
    ] {
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: call.call_id,
                field,
                value,
            },
        );
    }

    let caller_address = call.caller_address;
    let nonce_prev = state.sdb.increase_nonce(&caller_address);
    state.push_op(
        &mut exec_step,
        RW::WRITE,
        AccountOp {
            address: caller_address,
            field: AccountField::Nonce,
            value: (nonce_prev + 1).into(),
            value_prev: (nonce_prev).into(),
        },
    );

    for address in [call.caller_address, call.address] {
        state.sdb.add_account_to_access_list(address);
        state.push_op(
            &mut exec_step,
            RW::WRITE,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address,
                value: true,
                value_prev: false,
            },
        );
    }

    let call_data_gas_cost = state
        .tx
        .input
        .iter()
        .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 });
    let intrinsic_gas_cost = if state.tx.is_create() {
        GasCost::CREATION_TX.as_u64()
    } else {
        GasCost::TX.as_u64()
    } + call_data_gas_cost;
    exec_step.gas_cost = GasCost(intrinsic_gas_cost);

    let (found, caller_account) = state.sdb.get_account_mut(&call.caller_address);
    if !found {
        return Err(Error::AccountNotFound(call.caller_address));
    }
    let caller_balance_prev = caller_account.balance;
    let caller_balance = caller_account.balance - call.value - state.tx.gas_price * state.tx.gas;
    state.push_op_reversible(
        &mut exec_step,
        RW::WRITE,
        AccountOp {
            address: call.caller_address,
            field: AccountField::Balance,
            value: caller_balance,
            value_prev: caller_balance_prev,
        },
    )?;

    let (found, callee_account) = state.sdb.get_account_mut(&call.address);
    if !found {
        return Err(Error::AccountNotFound(call.address));
    }
    let callee_balance_prev = callee_account.balance;
    let callee_balance = callee_account.balance + call.value;
    let code_hash = callee_account.code_hash;
    state.push_op_reversible(
        &mut exec_step,
        RW::WRITE,
        AccountOp {
            address: call.address,
            field: AccountField::Balance,
            value: callee_balance,
            value_prev: callee_balance_prev,
        },
    )?;

    // There are 4 branches from here.
    match (
        call.is_create(),
        state.is_precompiled(&call.address),
        code_hash.to_fixed_bytes() == *EMPTY_HASH,
    ) {
        // 1. Creation transaction.
        (true, _, _) => {
            warn!("Creation transaction is left unimplemented");
            Ok(exec_step)
        }
        // 2. Call to precompiled.
        (_, true, _) => {
            warn!("Call to precompiled is left unimplemented");
            Ok(exec_step)
        }
        (_, _, is_empty_code_hash) => {
            state.push_op(
                &mut exec_step,
                RW::READ,
                AccountOp {
                    address: call.address,
                    field: AccountField::CodeHash,
                    value: code_hash.to_word(),
                    value_prev: code_hash.to_word(),
                },
            );

            // 3. Call to account with empty code.
            if is_empty_code_hash {
                warn!("Call to account with empty code is left unimplemented");
                return Ok(exec_step);
            }

            // 4. Call to account with non-empty code.
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
                (CallContextField::IsCreate, 0.into()),
                (CallContextField::CodeSource, code_hash.to_word()),
            ] {
                state.push_op(
                    &mut exec_step,
                    RW::READ,
                    CallContextOp {
                        call_id: call.call_id,
                        field,
                        value,
                    },
                );
            }

            Ok(exec_step)
        }
    }
}

pub fn gen_end_tx_ops(state: &mut CircuitInputStateRef) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_end_tx_step();
    let call = state.tx.calls()[0].clone();

    state.push_op(
        &mut exec_step,
        RW::READ,
        CallContextOp {
            call_id: call.call_id,
            field: CallContextField::TxId,
            value: state.tx_ctx.id().into(),
        },
    );

    let refund = state.sdb.refund();
    state.push_op(
        &mut exec_step,
        RW::READ,
        TxRefundOp {
            tx_id: state.tx_ctx.id(),
            value: refund,
            value_prev: refund,
        },
    );

    let effective_refund =
        refund.min((state.tx.gas - exec_step.gas_left.0) / MAX_REFUND_QUOTIENT_OF_GAS_USED as u64);
    let (found, caller_account) = state.sdb.get_account_mut(&call.caller_address);
    if !found {
        return Err(Error::AccountNotFound(call.caller_address));
    }
    let caller_balance_prev = caller_account.balance;
    let caller_balance =
        caller_account.balance + state.tx.gas_price * (exec_step.gas_left.0 + effective_refund);
    state.push_op(
        &mut exec_step,
        RW::WRITE,
        AccountOp {
            address: call.caller_address,
            field: AccountField::Balance,
            value: caller_balance,
            value_prev: caller_balance_prev,
        },
    );

    let effective_tip = state.tx.gas_price - state.block.base_fee;
    let (found, coinbase_account) = state.sdb.get_account_mut(&state.block.coinbase);
    if !found {
        return Err(Error::AccountNotFound(state.block.coinbase));
    }
    let coinbase_balance_prev = coinbase_account.balance;
    let coinbase_balance =
        coinbase_account.balance + effective_tip * (state.tx.gas - exec_step.gas_left.0);
    state.push_op(
        &mut exec_step,
        RW::WRITE,
        AccountOp {
            address: state.block.coinbase,
            field: AccountField::Balance,
            value: coinbase_balance,
            value_prev: coinbase_balance_prev,
        },
    );

    if !state.tx_ctx.is_last_tx() {
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.block_ctx.rwc.0 + 1,
                field: CallContextField::TxId,
                value: (state.tx_ctx.id() + 1).into(),
            },
        );
    }

    Ok(exec_step)
}

fn dummy_gen_call_ops(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let geth_step = &geth_steps[0];
    let exec_step = state.new_step(geth_step)?;

    let call = state.call()?.clone();
    let callee = state.parse_call(geth_step)?;

    let (_, account) = state.sdb.get_account(&callee.address);
    let callee_code_hash = account.code_hash;

    state.push_call(callee.clone(), geth_step);

    match (
        state.is_precompiled(&call.address),
        callee_code_hash.to_fixed_bytes() == *EMPTY_HASH,
    ) {
        // 1. Call to precompiled.
        (true, _) => Ok(vec![exec_step]),
        // 2. Call to account with empty code.
        (_, true) => {
            state.handle_return()?;
            Ok(vec![exec_step])
        }
        // 3. Call to account with non-empty code.
        (_, false) => Ok(vec![exec_step]),
    }
}
