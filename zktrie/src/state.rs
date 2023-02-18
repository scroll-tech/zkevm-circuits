//! Represent the storage state under zktrie as implement

use bus_mapping::state_db::{Account, StateDB};
use eth_types::{Address, Hash, Word, H256, U256};
use mpt_circuits::MPTProofType;

use std::collections::HashMap;
use std::io::Error;
pub use zktrie::{Hash as ZkTrieHash, ZkMemoryDb, ZkTrie, ZkTrieNode};

pub mod builder;
pub mod witness;

use std::fmt;
use std::{cell::RefCell, rc::Rc};

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

unsafe impl Send for ZktrieState {}

impl fmt::Debug for ZktrieState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ZktrieState: {{sdb: {:?}, trie: {:x?}, accounts: {:?}}}",
            self.sdb,
            self.trie_root,
            self.accounts.keys()
        )
    }
}

impl ZktrieState {
    /// help to query account data
    pub fn root(&self) -> &ZkTrieHash {
        &self.trie_root
    }

    /// help to query account data
    pub fn state(&self) -> &StateDB {
        &self.sdb
    }

    /// construct from external data
    pub fn construct<'d>(
        sdb: StateDB,
        state_root: Hash,
        proofs: impl IntoIterator<Item = &'d [u8]>,
        acc_storage_roots: impl IntoIterator<Item = (Address, Hash)>,
    ) -> Self {
        assert!(
            *builder::HASH_SCHEME_DONE,
            "must set hash scheme into zktrie"
        );

        let mut zk_db = ZkMemoryDb::default();
        for bytes in proofs {
            zk_db.add_node_bytes(bytes).unwrap();
        }

        let accounts = acc_storage_roots
            .into_iter()
            .map(|(addr_r, hash_r)| (addr_r, hash_r.0))
            .collect();

        Self {
            sdb,
            zk_db: Rc::new(RefCell::new(zk_db)),
            trie_root: state_root.0,
            accounts,
        }
    }

    /// construct from external data
    pub fn from_trace<'d, BYTES>(
        state_root: Hash,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES)> + Clone,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES)> + Clone,
    ) -> Result<Self, Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        use builder::{AccountProof, BytesArray, StorageProof};

        let mut sdb = StateDB::new();
        let mut acc_storage_roots: HashMap<Address, Hash> = Default::default();

        let proofs = account_proofs
            .clone()
            .flat_map(|(_, bytes)| bytes)
            .chain(storage_proofs.clone().flat_map(|(_, _, bytes)| bytes));

        for (addr, bytes) in account_proofs {
            let acc_proof = builder::verify_proof_leaf(
                AccountProof::try_from(BytesArray(bytes.into_iter()))?,
                &builder::extend_address_to_h256(addr),
            );
            if acc_proof.key.is_some() {
                let acc_data = acc_proof.data;
                sdb.set_account(
                    addr,
                    Account {
                        nonce: U256::from(acc_data.nonce),
                        balance: acc_data.balance,
                        code_hash: acc_data.code_hash,
                        storage: Default::default(),
                    },
                );

                acc_storage_roots.insert(*addr, acc_data.storage_root);
            } else {
                sdb.set_account(addr, Account::zero());
                acc_storage_roots.insert(*addr, H256::zero());
            }
        }

        for (addr, key, bytes) in storage_proofs {
            let (_, acc) = sdb.get_account_mut(addr);
            let mut key_buf = [0u8; 32];
            key.to_big_endian(key_buf.as_mut_slice());
            let store_proof = builder::verify_proof_leaf(
                StorageProof::try_from(BytesArray(bytes.into_iter()))?,
                &key_buf,
            );
            if store_proof.key.is_some() {
                if !store_proof.data.as_ref().is_zero() {
                    acc.storage.insert(*key, *store_proof.data.as_ref());
                } else {
                    acc.storage.remove(key);
                }
            } else {
                acc.storage.remove(key);
                //acc.storage.insert(*key, U256::zero());
            }
        }

        Ok(Self::construct(sdb, state_root, proofs, acc_storage_roots))
    }
}

#[cfg(any(feature = "test", test))]
mod test;
