//! Evm types needed for parsing instruction sets as well

pub(crate) mod opcodes;
pub(crate) mod precompiled;

pub use eth_types::evm_types::opcode_ids::OpcodeId;
pub use opcodes::Opcode;
