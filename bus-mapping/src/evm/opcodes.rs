//! Definition of each opcode of the EVM.
mod coinbase;
mod dup;
mod jump;
mod jumpdest;
mod jumpi;
mod mload;
mod msize;
mod mstore;
mod pc;
mod pop;
mod push;
mod sload;
mod stackonlyop;
mod stop;
mod swap;

use crate::circuit_input_builder::CircuitInputStateRef;
use crate::evm::OpcodeId;
use crate::Error;
use core::fmt::Debug;
use eth_types::GethExecStep;
use log::warn;

use self::push::Push;
use coinbase::Coinbase;
use dup::Dup;
use jump::Jump;
use jumpdest::Jumpdest;
use jumpi::Jumpi;
use mload::Mload;
use msize::Msize;
use mstore::Mstore;
use pc::Pc;
use pop::Pop;
use sload::Sload;
use stackonlyop::StackOnlyOpcode;
use stop::Stop;
use swap::Swap;

/// Generic opcode trait which defines the logic of the
/// [`Operation`](crate::operation::Operation) that should be generated for an
/// [`ExecStep`](crate::circuit_input_builder::ExecStep) depending of the
/// [`OpcodeId`] it contains.
pub trait Opcode: Debug {
    /// Generate the associated [`MemoryOp`](crate::operation::MemoryOp)s,
    /// [`StackOp`](crate::operation::StackOp)s, and
    /// [`StorageOp`](crate::operation::StorageOp)s associated to the Opcode
    /// is implemented for.
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        next_steps: &[GethExecStep],
    ) -> Result<(), Error>;
}

fn dummy_gen_associated_ops(
    _state: &mut CircuitInputStateRef,
    _next_steps: &[GethExecStep],
) -> Result<(), Error> {
    Ok(())
}

type FnGenAssociatedOps = fn(
    state: &mut CircuitInputStateRef,
    next_steps: &[GethExecStep],
) -> Result<(), Error>;

fn fn_gen_associated_ops(opcode_id: &OpcodeId) -> FnGenAssociatedOps {
    match opcode_id {
        OpcodeId::STOP => Stop::gen_associated_ops,
        OpcodeId::ADD => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::MUL => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::SUB => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::DIV => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::SDIV => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::MOD => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::SMOD => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::ADDMOD => StackOnlyOpcode::<3>::gen_associated_ops,
        OpcodeId::MULMOD => StackOnlyOpcode::<3>::gen_associated_ops,
        OpcodeId::EXP => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::SIGNEXTEND => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::LT => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::GT => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::SLT => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::SGT => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::EQ => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::ISZERO => StackOnlyOpcode::<1>::gen_associated_ops,
        OpcodeId::AND => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::OR => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::XOR => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::NOT => StackOnlyOpcode::<1>::gen_associated_ops,
        OpcodeId::BYTE => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::SHL => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::SHR => StackOnlyOpcode::<2>::gen_associated_ops,
        OpcodeId::SAR => StackOnlyOpcode::<2>::gen_associated_ops,
        // OpcodeId::SHA3 => {},
        // OpcodeId::ADDRESS => {},
        // OpcodeId::BALANCE => {},
        // OpcodeId::ORIGIN => {},
        // OpcodeId::CALLER => {},
        // OpcodeId::CALLVALUE => {},
        // OpcodeId::CALLDATALOAD => {},
        // OpcodeId::CALLDATASIZE => {},
        // OpcodeId::CALLDATACOPY => {},
        // OpcodeId::CODESIZE => {},
        // OpcodeId::CODECOPY => {},
        // OpcodeId::GASPRICE => {},
        // OpcodeId::EXTCODESIZE => {},
        // OpcodeId::EXTCODECOPY => {},
        // OpcodeId::RETURNDATASIZE => {},
        // OpcodeId::RETURNDATACOPY => {},
        // OpcodeId::EXTCODEHASH => {},
        // OpcodeId::BLOCKHASH => {},
        OpcodeId::COINBASE => Coinbase::gen_associated_ops,
        // OpcodeId::TIMESTAMP => {},
        // OpcodeId::NUMBER => {},
        // OpcodeId::DIFFICULTY => {},
        // OpcodeId::GASLIMIT => {},
        // OpcodeId::CHAINID => {},
        // OpcodeId::SELFBALANCE => {},
        // OpcodeId::BASEFEE => {},
        OpcodeId::POP => Pop::gen_associated_ops,
        OpcodeId::MLOAD => Mload::gen_associated_ops,
        OpcodeId::MSTORE => Mstore::<false>::gen_associated_ops,
        OpcodeId::MSTORE8 => Mstore::<true>::gen_associated_ops,
        OpcodeId::SLOAD => Sload::gen_associated_ops,
        // OpcodeId::SSTORE => {},
        OpcodeId::JUMP => Jump::gen_associated_ops,
        OpcodeId::JUMPI => Jumpi::gen_associated_ops,
        OpcodeId::PC => Pc::gen_associated_ops,
        OpcodeId::MSIZE => Msize::gen_associated_ops,
        // OpcodeId::GAS => {},
        OpcodeId::JUMPDEST => Jumpdest::gen_associated_ops,
        OpcodeId::PUSH1 => Push::<1>::gen_associated_ops,
        OpcodeId::PUSH2 => Push::<2>::gen_associated_ops,
        OpcodeId::PUSH3 => Push::<3>::gen_associated_ops,
        OpcodeId::PUSH4 => Push::<4>::gen_associated_ops,
        OpcodeId::PUSH5 => Push::<5>::gen_associated_ops,
        OpcodeId::PUSH6 => Push::<6>::gen_associated_ops,
        OpcodeId::PUSH7 => Push::<7>::gen_associated_ops,
        OpcodeId::PUSH8 => Push::<8>::gen_associated_ops,
        OpcodeId::PUSH9 => Push::<9>::gen_associated_ops,
        OpcodeId::PUSH10 => Push::<10>::gen_associated_ops,
        OpcodeId::PUSH11 => Push::<11>::gen_associated_ops,
        OpcodeId::PUSH12 => Push::<12>::gen_associated_ops,
        OpcodeId::PUSH13 => Push::<13>::gen_associated_ops,
        OpcodeId::PUSH14 => Push::<14>::gen_associated_ops,
        OpcodeId::PUSH15 => Push::<15>::gen_associated_ops,
        OpcodeId::PUSH16 => Push::<16>::gen_associated_ops,
        OpcodeId::PUSH17 => Push::<17>::gen_associated_ops,
        OpcodeId::PUSH18 => Push::<18>::gen_associated_ops,
        OpcodeId::PUSH19 => Push::<19>::gen_associated_ops,
        OpcodeId::PUSH20 => Push::<20>::gen_associated_ops,
        OpcodeId::PUSH21 => Push::<21>::gen_associated_ops,
        OpcodeId::PUSH22 => Push::<22>::gen_associated_ops,
        OpcodeId::PUSH23 => Push::<23>::gen_associated_ops,
        OpcodeId::PUSH24 => Push::<24>::gen_associated_ops,
        OpcodeId::PUSH25 => Push::<25>::gen_associated_ops,
        OpcodeId::PUSH26 => Push::<26>::gen_associated_ops,
        OpcodeId::PUSH27 => Push::<27>::gen_associated_ops,
        OpcodeId::PUSH28 => Push::<28>::gen_associated_ops,
        OpcodeId::PUSH29 => Push::<29>::gen_associated_ops,
        OpcodeId::PUSH30 => Push::<30>::gen_associated_ops,
        OpcodeId::PUSH31 => Push::<31>::gen_associated_ops,
        OpcodeId::PUSH32 => Push::<32>::gen_associated_ops,
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
        // OpcodeId::LOG3 => {},
        // OpcodeId::LOG4 => {},
        // OpcodeId::CREATE => {},
        // OpcodeId::CALL => {},
        // OpcodeId::CALLCODE => {},
        // OpcodeId::RETURN => {},
        // OpcodeId::DELEGATECALL => {},
        // OpcodeId::CREATE2 => {},
        // OpcodeId::STATICCALL => {},
        // OpcodeId::REVERT => {},
        // OpcodeId::SELFDESTRUCT => {},
        // _ => panic!("Opcode {:?} gen_associated_ops not implemented",
        // self),
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
    next_steps: &[GethExecStep],
) -> Result<(), Error> {
    let fn_gen_associated_ops = fn_gen_associated_ops(opcode_id);
    fn_gen_associated_ops(state, next_steps)
}
