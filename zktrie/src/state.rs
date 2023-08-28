//! Represent the storage state under zktrie as implement
use eth_types::{Address, Hash, Word};
use mpt_circuits::MPTProofType;

use std::{collections::HashMap, io::Error};
pub use zktrie::{Hash as ZkTrieHash, ZkMemoryDb, ZkTrie, ZkTrieNode};

pub mod builder;
pub mod witness;
pub use builder::{AccountData, StorageData};

use std::{cell::RefCell, fmt, rc::Rc};

/// represent a storage state being applied in specified block
#[derive(Clone, Default)]
pub struct ZktrieState {
    accounts: HashMap<Address, AccountData>,
    account_storages: HashMap<(Address, Word), StorageData>,
    zk_db: Rc<RefCell<ZkMemoryDb>>,
    trie_root: ZkTrieHash,
}

unsafe impl Send for ZktrieState {}

impl fmt::Debug for ZktrieState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ZktrieState: {{accounts: {:?}, storage: {:?}, trie: {:x?}}}",
            self.accounts, self.account_storages, self.trie_root,
        )
    }
}

impl ZktrieState {
    /// help to query account data
    pub fn root(&self) -> &ZkTrieHash {
        &self.trie_root
    }

    /// help to query account data
    pub fn state(&self) -> &HashMap<Address, AccountData> {
        &self.accounts
    }

    /// help to query storage data
    pub fn storage(&self) -> &HashMap<(Address, Word), StorageData> {
        &self.account_storages
    }

    /// construct from external data
    pub fn construct(
        //sdb: StateDB,
        state_root: Hash,
        //proofs: impl IntoIterator<Item = &'d [u8]>,
        //acc_storage_roots: impl IntoIterator<Item = (Address, Hash)>,
    ) -> Self {
        assert!(
            *builder::HASH_SCHEME_DONE,
            "must set hash scheme into zktrie"
        );

        let zk_db = ZkMemoryDb::default();
        Self {
            zk_db: Rc::new(RefCell::new(zk_db)),
            trie_root: state_root.0,
            ..Default::default()
        }
    }

    /// incremental updating for account from external data, catch each written of new account in
    /// tries
    pub fn update_account_from_proofs<'d, BYTES>(
        &mut self,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES)>,
        mut on_account: impl FnMut(&Address, &AccountData) -> Result<(), Error> + 'd,
    ) -> Result<(), Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        use builder::{AccountProof, BytesArray};

        for (addr, bytes) in account_proofs {
            let acc_proof = builder::verify_proof_leaf(
                AccountProof::try_from(BytesArray(bytes.into_iter()))?,
                &builder::extend_address_to_h256(addr),
            );
            let acc_data = acc_proof.data;
            let acc = self.accounts.get(addr);
            if acc.is_some() {
                log::trace!(
                    "skip trace account into sdb: addr {:?}, new {:?}, keep old: {:?}",
                    addr,
                    acc_data,
                    acc
                );
                continue;
            }
            if acc_proof.key.is_some() {
                log::trace!("trace account into sdb: {:?} => {:?}", addr, acc_data);
                on_account(addr, &acc_data)?;
                self.accounts.insert(*addr, acc_data);
            } else {
                on_account(addr, &Default::default())?;
                self.accounts.insert(*addr, Default::default());
            }
        }

        Ok(())
    }

    /// incremental updating for storage from external data, catch each written of new (non-zero)
    /// value in tries
    pub fn update_storage_from_proofs<'d, BYTES>(
        &mut self,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES)>,
        mut on_storage: impl FnMut(&(Address, Word), &StorageData) -> Result<(), Error> + 'd,
    ) -> Result<(), Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        use builder::{BytesArray, StorageProof};

        for (&addr, &key, bytes) in storage_proofs {
            let storage_key: (Address, Word) = (addr, key);
            let old_value = self.account_storages.get(&storage_key);
            if old_value.is_some() {
                continue;
            }
            let mut key_buf = [0u8; 32];
            key.to_big_endian(key_buf.as_mut_slice());
            let bytes_array = BytesArray(bytes.into_iter());
            let store_proof =
                builder::verify_proof_leaf(StorageProof::try_from(bytes_array)?, &key_buf);
            if store_proof.key.is_some() {
                log::trace!(
                    "insert storage key {:?} value {:?}",
                    storage_key,
                    *store_proof.data.as_ref()
                );

                on_storage(&storage_key, &store_proof.data)?;
                self.account_storages.insert(storage_key, store_proof.data);
            } else {
                log::trace!("insert storage key {:?} for zero", storage_key,);
                self.account_storages
                    .insert(storage_key, Default::default());
            }
        }

        Ok(())
    }

    /// incremental updating nodes in db from external data
    pub fn update_nodes_from_proofs<'d, BYTES1, BYTES2>(
        &mut self,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES1)>,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES2)>,
        additional_proofs: impl Iterator<Item = &'d [u8]>,
    ) where
        BYTES1: IntoIterator<Item = &'d [u8]>,
        BYTES2: IntoIterator<Item = &'d [u8]>,
    {
        let proofs = account_proofs
            .flat_map(|(_, bytes)| bytes)
            .chain(storage_proofs.flat_map(|(_, _, bytes)| bytes))
            .chain(additional_proofs);
        let mut zk_db = self.zk_db.borrow_mut();
        for bytes in proofs {
            zk_db.add_node_bytes(bytes).unwrap();
        }
    }

    /// construct from external data, with additional proofs (trie node) can be
    /// provided
    pub fn from_trace_with_additional<'d, BYTES1, BYTES2>(
        state_root: Hash,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES1)> + Clone,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES2)> + Clone,
        additional_proofs: impl Iterator<Item = &'d [u8]>,
        light_mode: bool,
    ) -> Result<Self, Error>
    where
        BYTES1: IntoIterator<Item = &'d [u8]>,
        BYTES2: IntoIterator<Item = &'d [u8]>,
    {
        let mut state = ZktrieState::construct(state_root);
        if !light_mode {
            // a lot of poseidon computation
            state.update_nodes_from_proofs(
                account_proofs.clone(),
                storage_proofs.clone(),
                additional_proofs,
            );
        }
        state.update_account_from_proofs(account_proofs, |_, _| Ok(()))?;
        state.update_storage_from_proofs(storage_proofs, |_, _| Ok(()))?;

        Ok(state)
    }
}

#[cfg(any(feature = "test", test))]
mod test;
