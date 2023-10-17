//! Definition of each opcode of the EVM.
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecState, ExecStep},
    error::{
        ContractAddressCollisionError, DepthError, ExecError, InsufficientBalanceError,
        NonceUintOverflowError, OogError,
    },
    evm::OpcodeId,
    operation::{AccountField, AccountOp, TxAccessListAccountOp},
    Error,
};
use core::fmt::Debug;
use eth_types::{evm_unimplemented, GethExecStep, ToAddress, ToWord, Word};

use crate::util::CHECK_MEM_STRICT;

#[cfg(any(feature = "test", test))]
pub use self::sha3::sha3_tests::{gen_sha3_code, MemoryKind};

mod address;
mod balance;
mod begin_end_tx;
mod blockhash;
mod calldatacopy;
mod calldataload;
mod calldatasize;
mod caller;
mod callop;
mod callvalue;
mod chainid;
mod codecopy;
mod codesize;
mod create;
mod dup;
mod exp;
mod extcodecopy;
mod extcodehash;
mod extcodesize;
mod gasprice;
mod logs;
mod mload;
mod mstore;
mod number;
mod origin;
mod precompiles;
mod push0;
mod pushn;
mod return_revert;
mod returndatacopy;
mod returndatasize;
mod selfbalance;
mod sha3;
mod sload;
mod sstore;
mod stackonlyop;
mod stop;
mod swap;

mod error_codestore;
mod error_contract_address_collision;
mod error_invalid_creation_code;
mod error_invalid_jump;
mod error_oog_account_access;
mod error_oog_call;
mod error_oog_log;
mod error_oog_memory_copy;
mod error_oog_precompile;
mod error_oog_sload_sstore;
mod error_precompile_failed;
mod error_return_data_outofbound;
mod error_write_protection;

#[cfg(test)]
mod memory_expansion_test;
#[cfg(feature = "test")]
pub use callop::tests::PrecompileCallArgs;

use self::{pushn::PushN, sha3::Sha3};

use address::Address;
use balance::Balance;
use begin_end_tx::BeginEndTx;
use blockhash::Blockhash;
use calldatacopy::Calldatacopy;
use calldataload::Calldataload;
use calldatasize::Calldatasize;
use caller::Caller;
use callop::CallOpcode;
use callvalue::Callvalue;
use codecopy::Codecopy;
use codesize::Codesize;
use create::Create;
use dup::Dup;
use error_codestore::ErrorCodeStore;
use error_invalid_creation_code::ErrorCreationCode;
use error_invalid_jump::InvalidJump;
use error_oog_account_access::ErrorOOGAccountAccess;
use error_oog_call::OOGCall;
use error_oog_log::ErrorOOGLog;
use error_oog_memory_copy::OOGMemoryCopy;
use error_oog_sload_sstore::OOGSloadSstore;
use error_precompile_failed::PrecompileFailed;
use error_return_data_outofbound::ErrorReturnDataOutOfBound;
use error_write_protection::ErrorWriteProtection;
use exp::Exponentiation;
use extcodecopy::Extcodecopy;
use extcodehash::Extcodehash;
use extcodesize::Extcodesize;
use gasprice::GasPrice;
use logs::Log;
use mload::Mload;
use mstore::Mstore;
use origin::Origin;
use push0::Push0;
use return_revert::ReturnRevert;
use returndatacopy::Returndatacopy;
use returndatasize::Returndatasize;
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

/// Generic trait for tx execution steps
/// which only supports ExecState::BeginTx and ExecState:EndTx
pub trait TxExecSteps: Debug {
    fn gen_associated_steps(
        state: &mut CircuitInputStateRef,
        execution_step: ExecState,
    ) -> Result<ExecStep, Error>;
}

#[derive(Debug, Copy, Clone)]
struct Dummy;

impl Opcode for Dummy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        Ok(vec![state.new_step(&geth_steps[0])?])
    }
}

type FnGenAssociatedOps = fn(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error>;

fn fn_gen_associated_ops(opcode_id: &OpcodeId) -> FnGenAssociatedOps {
    if opcode_id.is_push_with_data() {
        return PushN::gen_associated_ops;
    }

    match opcode_id {
        OpcodeId::PUSH0 => Push0::gen_associated_ops,
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
        OpcodeId::SHA3 => Sha3::gen_associated_ops,
        OpcodeId::ADDRESS => Address::gen_associated_ops,
        OpcodeId::BALANCE => Balance::gen_associated_ops,
        OpcodeId::ORIGIN => Origin::gen_associated_ops,
        OpcodeId::CALLER => Caller::gen_associated_ops,
        OpcodeId::CALLVALUE => Callvalue::gen_associated_ops,
        OpcodeId::CALLDATASIZE => Calldatasize::gen_associated_ops,
        OpcodeId::CALLDATALOAD => Calldataload::gen_associated_ops,
        OpcodeId::CALLDATACOPY => Calldatacopy::gen_associated_ops,
        OpcodeId::GASPRICE => GasPrice::gen_associated_ops,
        OpcodeId::CODECOPY => Codecopy::gen_associated_ops,
        OpcodeId::CODESIZE => Codesize::gen_associated_ops,
        OpcodeId::EXP => Exponentiation::gen_associated_ops,
        OpcodeId::EXTCODESIZE => Extcodesize::gen_associated_ops,
        OpcodeId::EXTCODECOPY => Extcodecopy::gen_associated_ops,
        OpcodeId::RETURNDATASIZE => Returndatasize::gen_associated_ops,
        OpcodeId::RETURNDATACOPY => Returndatacopy::gen_associated_ops,
        OpcodeId::EXTCODEHASH => Extcodehash::gen_associated_ops,
        OpcodeId::BLOCKHASH => Blockhash::gen_associated_ops,
        OpcodeId::COINBASE => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::TIMESTAMP => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::NUMBER => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::DIFFICULTY => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::GASLIMIT => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::CHAINID => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::SELFBALANCE => Selfbalance::gen_associated_ops,
        OpcodeId::BASEFEE => StackOnlyOpcode::<0, 1>::gen_associated_ops,
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
        OpcodeId::JUMPDEST => Dummy::gen_associated_ops,
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
        OpcodeId::LOG0 => Log::gen_associated_ops,
        OpcodeId::LOG1 => Log::gen_associated_ops,
        OpcodeId::LOG2 => Log::gen_associated_ops,
        OpcodeId::LOG3 => Log::gen_associated_ops,
        OpcodeId::LOG4 => Log::gen_associated_ops,
        OpcodeId::CALL | OpcodeId::CALLCODE => CallOpcode::<7>::gen_associated_ops,
        OpcodeId::DELEGATECALL | OpcodeId::STATICCALL => CallOpcode::<6>::gen_associated_ops,
        OpcodeId::CREATE => Create::<false>::gen_associated_ops,
        OpcodeId::CREATE2 => Create::<true>::gen_associated_ops,
        OpcodeId::RETURN | OpcodeId::REVERT => ReturnRevert::gen_associated_ops,
        OpcodeId::INVALID(_) => Stop::gen_associated_ops,
        OpcodeId::SELFDESTRUCT => {
            log::debug!("Using dummy gen_selfdestruct_ops for opcode SELFDESTRUCT");
            DummySelfDestruct::gen_associated_ops
        }
        _ => {
            log::debug!("Using dummy gen_associated_ops for opcode {:?}", opcode_id);
            Dummy::gen_associated_ops
        }
    }
}

fn fn_gen_error_state_associated_ops(
    geth_step: &GethExecStep,
    error: &ExecError,
) -> Option<FnGenAssociatedOps> {
    match error {
        ExecError::InvalidJump => Some(InvalidJump::gen_associated_ops),
        ExecError::InvalidOpcode => Some(StackOnlyOpcode::<0, 0, true>::gen_associated_ops),
        // Depth error could occur in CALL, CALLCODE, DELEGATECALL and STATICCALL.
        ExecError::Depth(DepthError::Call) => match geth_step.op {
            OpcodeId::CALL | OpcodeId::CALLCODE => Some(CallOpcode::<7>::gen_associated_ops),
            OpcodeId::DELEGATECALL | OpcodeId::STATICCALL => {
                Some(CallOpcode::<6>::gen_associated_ops)
            }
            op => unreachable!("ErrDepth cannot occur in {op}"),
        },
        // Depth error could occur in CREATE and CREATE2.
        ExecError::Depth(DepthError::Create) => Some(Create::<false>::gen_associated_ops),
        ExecError::Depth(DepthError::Create2) => Some(Create::<true>::gen_associated_ops),
        ExecError::OutOfGas(OogError::Call) => Some(OOGCall::gen_associated_ops),
        ExecError::OutOfGas(OogError::Constant) => {
            Some(StackOnlyOpcode::<0, 0, true>::gen_associated_ops)
        }
        ExecError::OutOfGas(OogError::Create) => match geth_step.op {
            OpcodeId::CREATE => Some(StackOnlyOpcode::<3, 0, true>::gen_associated_ops),
            OpcodeId::CREATE2 => Some(StackOnlyOpcode::<4, 0, true>::gen_associated_ops),
            op => unreachable!("OOG Create cannot occur in {op}"),
        },
        ExecError::OutOfGas(OogError::Log) => Some(ErrorOOGLog::gen_associated_ops),
        ExecError::OutOfGas(OogError::DynamicMemoryExpansion) => {
            Some(StackOnlyOpcode::<2, 0, true>::gen_associated_ops)
        }
        ExecError::OutOfGas(OogError::StaticMemoryExpansion) => {
            Some(StackOnlyOpcode::<1, 0, true>::gen_associated_ops)
        }
        ExecError::OutOfGas(OogError::Exp) => {
            Some(StackOnlyOpcode::<2, 0, true>::gen_associated_ops)
        }
        ExecError::OutOfGas(OogError::MemoryCopy) => Some(OOGMemoryCopy::gen_associated_ops),
        ExecError::OutOfGas(OogError::Sha3) => {
            Some(StackOnlyOpcode::<2, 0, true>::gen_associated_ops)
        }
        ExecError::OutOfGas(OogError::SloadSstore) => Some(OOGSloadSstore::gen_associated_ops),
        ExecError::OutOfGas(OogError::AccountAccess) => {
            Some(ErrorOOGAccountAccess::gen_associated_ops)
        }
        // ExecError::
        ExecError::StackOverflow => Some(StackOnlyOpcode::<0, 0, true>::gen_associated_ops),
        ExecError::StackUnderflow => Some(StackOnlyOpcode::<0, 0, true>::gen_associated_ops),
        ExecError::CodeStoreOutOfGas => Some(ErrorCodeStore::gen_associated_ops),
        ExecError::MaxCodeSizeExceeded => Some(ErrorCodeStore::gen_associated_ops),
        // call & callcode can encounter InsufficientBalance error, Use pop-7 generic CallOpcode
        ExecError::InsufficientBalance(InsufficientBalanceError::Call) => {
            Some(CallOpcode::<7>::gen_associated_ops)
        }
        // create & create2 can encounter insufficient balance.
        ExecError::InsufficientBalance(InsufficientBalanceError::Create) => {
            Some(Create::<false>::gen_associated_ops)
        }
        ExecError::InsufficientBalance(InsufficientBalanceError::Create2) => {
            Some(Create::<true>::gen_associated_ops)
        }
        ExecError::PrecompileFailed => Some(PrecompileFailed::gen_associated_ops),
        ExecError::WriteProtection => Some(ErrorWriteProtection::gen_associated_ops),
        ExecError::ReturnDataOutOfBounds => Some(ErrorReturnDataOutOfBound::gen_associated_ops),
        // create & create2 can encounter contract address collision.
        ExecError::ContractAddressCollision(ContractAddressCollisionError::Create) => {
            Some(Create::<false>::gen_associated_ops)
        }
        ExecError::ContractAddressCollision(ContractAddressCollisionError::Create2) => {
            Some(Create::<true>::gen_associated_ops)
        }
        // create & create2 can encounter nonce uint overflow.
        ExecError::NonceUintOverflow(NonceUintOverflowError::Create) => {
            Some(Create::<false>::gen_associated_ops)
        }
        ExecError::NonceUintOverflow(NonceUintOverflowError::Create2) => {
            Some(Create::<true>::gen_associated_ops)
        }
        ExecError::InvalidCreationCode => Some(ErrorCreationCode::gen_associated_ops),
        // more future errors place here
        _ => {
            evm_unimplemented!("TODO: error state {:?} not implemented", error);
            None
        }
    }
}

#[allow(clippy::collapsible_else_if)]
/// Generate the associated operations according to the particular
/// [`OpcodeId`].
pub fn gen_associated_ops(
    opcode_id: &OpcodeId,
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let check_level = if *CHECK_MEM_STRICT { 2 } else { 0 }; // 0: no check, 1: check and log error and fix, 2: check and assert_eq
    if check_level >= 1 {
        let memory_enabled = !geth_steps.iter().all(|s| s.memory.is_empty());
        assert!(memory_enabled);
        if memory_enabled {
            #[allow(clippy::collapsible_else_if)]
            if state.call_ctx()?.memory != geth_steps[0].memory {
                log::error!(
                    "wrong mem before {:?}. len in state {}, len in step {}",
                    opcode_id,
                    &state.call_ctx()?.memory.len(),
                    &geth_steps[0].memory.len(),
                );
                log::error!("state mem {:?}", &state.call_ctx()?.memory);
                log::error!("step  mem {:?}", &geth_steps[0].memory);

                for i in 0..std::cmp::min(
                    state.call_ctx()?.memory.0.len(),
                    geth_steps[0].memory.0.len(),
                ) {
                    let state_mem = state.call_ctx()?.memory.0[i];
                    let step_mem = geth_steps[0].memory.0[i];
                    if state_mem != step_mem {
                        log::error!(
                            "diff at {}: state {:?} != step {:?}",
                            i,
                            state_mem,
                            step_mem
                        );
                    }
                }
                if check_level >= 2 {
                    panic!("mem wrong");
                }
                state.call_ctx_mut()?.memory = geth_steps[0].memory.clone();
            }
        }
    }

    // check if have error
    let geth_step = &geth_steps[0];
    let mut exec_step = state.new_step(geth_step)?;
    let next_step = if geth_steps.len() > 1 {
        Some(&geth_steps[1])
    } else {
        None
    };
    if let Some(exec_error) = state.get_step_err(geth_step, next_step).unwrap() {
        log::debug!(
            "geth error {:?} occurred in  {:?} at pc {:?}",
            exec_error,
            geth_step.op,
            geth_step.pc,
        );

        exec_step.error = Some(exec_error.clone());
        // TODO: after more error state handled, refactor all error handling in
        // fn_gen_error_state_associated_ops method
        // For exceptions that have been implemented
        if let Some(fn_gen_error_ops) = fn_gen_error_state_associated_ops(geth_step, &exec_error) {
            let mut steps = fn_gen_error_ops(state, geth_steps)?;
            if let Some(e) = &steps[0].error {
                debug_assert_eq!(&exec_error, e);
            }
            steps[0].error = Some(exec_error.clone());
            return Ok(steps);
        } else {
            // For exceptions that fail to enter next call context, we need
            // to restore call context of current caller
            let mut need_restore = true;

            // For exceptions that already enter next call context, but fail immediately
            // (e.g. Depth, InsufficientBalance), we still need to parse the call.
            if geth_step.op.is_call_or_create()
                && !matches!(exec_error, ExecError::OutOfGas(OogError::Create))
            {
                let call = state.parse_call(geth_step)?;
                state.push_call(call);
                need_restore = false;
            }

            state.handle_return(&mut [&mut exec_step], geth_steps, need_restore)?;
            return Ok(vec![exec_step]);
        }
    }
    // if no errors, continue as normal
    let fn_gen_associated_ops = fn_gen_associated_ops(opcode_id);
    fn_gen_associated_ops(state, geth_steps)
}

pub fn gen_associated_steps(
    state: &mut CircuitInputStateRef,
    execution_step: ExecState,
) -> Result<ExecStep, Error> {
    let fn_gen_associated_steps = match execution_step {
        ExecState::BeginTx | ExecState::EndTx => BeginEndTx::gen_associated_steps,
        _ => {
            unreachable!()
        }
    };

    fn_gen_associated_steps(state, execution_step)
}

#[derive(Debug, Copy, Clone)]
struct DummySelfDestruct;

impl Opcode for DummySelfDestruct {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        dummy_gen_selfdestruct_ops(state, geth_steps)
    }
}
fn dummy_gen_selfdestruct_ops(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let geth_step = &geth_steps[0];
    let mut exec_step = state.new_step(geth_step)?;
    let sender = state.call()?.address;
    let receiver = geth_step.stack.last()?.to_address();

    let is_warm = state.sdb.check_account_in_access_list(&receiver);
    state.push_op_reversible(
        &mut exec_step,
        TxAccessListAccountOp {
            tx_id: state.tx_ctx.id(),
            address: receiver,
            is_warm: true,
            is_warm_prev: is_warm,
        },
    )?;

    let (found, receiver_account) = state.sdb.get_account(&receiver);
    if !found {
        return Err(Error::AccountNotFound(receiver));
    }
    let receiver_account = &receiver_account.clone();
    let (found, sender_account) = state.sdb.get_account(&sender);
    if !found {
        return Err(Error::AccountNotFound(sender));
    }
    let sender_account = &sender_account.clone();
    let value = sender_account.balance;
    log::trace!(
        "self destruct, sender {:?} receiver {:?} value {:?}",
        sender,
        receiver,
        value
    );
    // NOTE: In this dummy implementation we assume that the receiver already
    // exists.

    state.push_op_reversible(
        &mut exec_step,
        AccountOp {
            address: sender,
            field: AccountField::Balance,
            value: Word::zero(),
            value_prev: value,
        },
    )?;
    state.push_op_reversible(
        &mut exec_step,
        AccountOp {
            address: sender,
            field: AccountField::Nonce,
            value: Word::zero(),
            value_prev: sender_account.nonce,
        },
    )?;
    state.push_op_reversible(
        &mut exec_step,
        AccountOp {
            address: sender,
            field: AccountField::CodeHash,
            value: Word::zero(),
            value_prev: sender_account.code_hash.to_word(),
        },
    )?;
    if receiver != sender {
        state.transfer_to(
            &mut exec_step,
            receiver,
            !receiver_account.is_empty(),
            false,
            value,
            true,
        )?;
    }

    if state.call()?.is_persistent {
        state.sdb.destruct_account(sender);
    }

    if let Ok(caller) = state.caller_ctx_mut() {
        caller.return_data.clear();
    }
    state.handle_return(&mut [&mut exec_step], geth_steps, !state.call()?.is_root)?;
    Ok(vec![exec_step])
}
