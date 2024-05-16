//! mpt-zktrie circuits and utils
//
#![deny(missing_docs)]
#![allow(dead_code)]

/// the state modules include structures represent zktrie and helpers
pub mod state;
pub use crate::state::ZktrieState;
pub use state::builder::{
    self, extend_address_to_h256, AccountData, AccountProof, BytesArray, CanRead, StorageProof,
    TrieProof, SECURE_HASH_DOMAIN,
};
pub use zktrie::{ZkTrie, ZkTrieNode};
