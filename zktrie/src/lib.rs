//! mpt-zktrie circuits and utils
//
#![deny(missing_docs)]

pub use mpt_circuits::hash;
pub use mpt_circuits::operation;
pub use mpt_circuits::serde;
pub use mpt_circuits::CommitmentIndexs;
pub use mpt_circuits::EthTrie;
pub use mpt_circuits::EthTrieCircuit;
pub use mpt_circuits::EthTrieConfig;
pub use mpt_circuits::MPTProofType;

//pub use mpt_circuits::hash;
//use mpt_circuits::{hash::Hashable, operation::AccountOp, EthTrie,
// EthTrieCircuit, HashCircuit, MPTProofType};

/// the state modules include structures represent zktrie and witness generator
pub mod state;
