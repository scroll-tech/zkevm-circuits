//! Represent the storage state under zktrie as implement

use bus_mapping::state_db::StateDB;
//use eth_types::Word;
use eth_types::{Address, Bytes, Hash};
use mpt_circuits::MPTProofType;

pub use zktrie::{ZkMemoryDb, ZkTrie, ZkTrieNode, Hash as ZkTrieHash};
use std::collections::HashMap;

pub mod witness;
pub mod builder;

use std::{rc::Rc, cell::RefCell};
use std::fmt;

/// turn a integer (expressed by field) into MPTProofType
pub fn as_proof_type(v: i32) -> MPTProofType {

    match v {
        1 => MPTProofType::NonceChanged,
        2 => MPTProofType::BalanceChanged,
        3 => MPTProofType::CodeHashExists,
        4 => MPTProofType::AccountDoesNotExist,
        5 => MPTProofType::AccountDestructed,
        6 => MPTProofType::StorageChanged,
        7 => MPTProofType::StorageDoesNotExist,
        _ => unreachable!("unexpected proof type number {:?}", v),
    }
}


/// represent a storage state being applied in specified block
#[derive(Clone, Default)]
pub struct ZktrieState {
    sdb: StateDB,
    zk_db: Rc<RefCell<ZkMemoryDb>>,
    trie_root: ZkTrieHash,
    accounts: HashMap<Address, ZkTrieHash>,
}

impl fmt::Debug for ZktrieState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ZktrieState: {{sdb: {:?}, trie: {:x?}, accounts: {:?}}}", self.sdb, self.trie_root, self.accounts.keys())
    }
}

impl ZktrieState {
    /// construct from external data
    pub fn construct<'d>(
        sdb: StateDB,
        state_root: Hash,
        proofs: impl IntoIterator<Item=&'d Bytes>,
        acc_storage_roots: impl IntoIterator<Item=(&'d Address, &'d Hash)>,
    ) -> Self {

        let mut zk_db = ZkMemoryDb::default();
        for bytes in proofs {
            zk_db.add_node_bytes(bytes.as_ref()).unwrap();
        }

        let accounts = acc_storage_roots.into_iter()
            .map(|(addr_r, hash_r)|(*addr_r, hash_r.0))
            .collect();
        
        Self {
            sdb,
            zk_db: Rc::new(RefCell::new(zk_db)),
            trie_root: state_root.0,
            accounts,
        }

    }



}