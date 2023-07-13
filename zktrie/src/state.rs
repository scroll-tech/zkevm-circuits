//! Represent the storage state under zktrie as implement

use bus_mapping::state_db::{Account, StateDB};
use eth_types::{Address, Hash, Word, H256, U256};
use mpt_circuits::MPTProofType;

use std::{collections::HashMap, io::Error};
pub use zktrie::{Hash as ZkTrieHash, ZkMemoryDb, ZkTrie, ZkTrieNode};

pub mod builder;
pub mod witness;

use std::{cell::RefCell, fmt, rc::Rc};

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

    /// ...
    pub fn set_state(&mut self, statedb: StateDB) {
        self.sdb = statedb
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
            sdb: Default::default(),
            zk_db: Rc::new(RefCell::new(zk_db)),
            trie_root: state_root.0,
            accounts: Default::default(),
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
        Self::from_trace_with_additional(
            state_root,
            account_proofs,
            storage_proofs,
            std::iter::empty(),
        )
    }

    /// ..
    pub fn update_statedb_from_proofs<'d, BYTES>(
        &mut self,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES)> + Clone,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES)> + Clone,
        _additional_proofs: impl Iterator<Item = &'d [u8]> + Clone,
    ) -> Result<(), Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        use builder::{AccountProof, BytesArray, StorageProof};

        for (addr, bytes) in account_proofs {
            let acc_proof = builder::verify_proof_leaf(
                AccountProof::try_from(BytesArray(bytes.into_iter()))?,
                &builder::extend_address_to_h256(addr),
            );
            let acc_data = acc_proof.data;
            let (exists, acc) = self.sdb.get_account(addr);
            if exists {
                log::trace!(
                    "overwrite trace account in sdb: addr {:?}, new {:?}, replace old: {:?}",
                    addr,
                    acc_data,
                    acc
                );
                //continue;
            }
            if acc_proof.key.is_some() {
                log::trace!("trace account into sdb: {:?} => {:?}", addr, acc_data);
                self.sdb.set_account(
                    addr,
                    Account {
                        nonce: acc_data.nonce.into(),
                        balance: acc_data.balance,
                        code_hash: acc_data.poseidon_code_hash,
                        keccak_code_hash: acc_data.keccak_code_hash,

                        code_size: acc_data.code_size.into(),
                        storage: Default::default(),
                    },
                );
                self.accounts.insert(*addr, acc_data.storage_root.0);
            } else {
                self.sdb.set_account(addr, Account::zero());
                self.accounts.insert(*addr, H256::zero().0);
            }
        }

        for (addr, key, bytes) in storage_proofs {
            let (_exists, old_value) = self.sdb.get_storage(addr, key);
            let old_value = *old_value;
            //if exists {
            //    continue;
            //}
            let (_, acc) = self.sdb.get_account_mut(addr);
            let mut key_buf = [0u8; 32];
            key.to_big_endian(key_buf.as_mut_slice());
            let bytes_array = BytesArray(bytes.into_iter());
            let store_proof =
                builder::verify_proof_leaf(StorageProof::try_from(bytes_array)?, &key_buf);
            if store_proof.key.is_some() {
                if !store_proof.data.as_ref().is_zero() {
                    log::trace!(
                        "insert storage addr {:?} key {:?} value {:?}",
                        addr,
                        key,
                        *store_proof.data.as_ref()
                    );
                    acc.storage.insert(*key, *store_proof.data.as_ref());
                } else {
                    log::trace!(
                        "set storage to 0, addr {:?} key {:?} old value {:?}",
                        addr,
                        key,
                        old_value
                    );
                    //acc.storage.remove(key);
                    acc.storage.insert(*key, U256::zero());
                }
            } else {
                log::trace!(
                    "clear storage addr {:?} key {:?} old value {:?}",
                    addr,
                    key,
                    old_value
                );
                // acc.storage.remove(key);
                acc.storage.insert(*key, U256::zero());
            }
        }

        Ok(())
    }
    /// ..
    pub fn update_from_proofs<'d, BYTES>(
        &mut self,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES)> + Clone,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES)> + Clone,
        additional_proofs: impl Iterator<Item = &'d [u8]> + Clone,
    ) -> Result<(), Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        self.update_statedb_from_proofs(
            account_proofs.clone(),
            storage_proofs.clone(),
            additional_proofs.clone(),
        )?;
        self.update_nodes_from_proofs(account_proofs, storage_proofs, additional_proofs)?;
        Ok(())
    }
    /// ..
    pub fn update_nodes_from_proofs<'d, BYTES>(
        &mut self,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES)> + Clone,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES)> + Clone,
        additional_proofs: impl Iterator<Item = &'d [u8]> + Clone,
    ) -> Result<(), Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        let proofs = account_proofs
            .flat_map(|(_, bytes)| bytes)
            .chain(storage_proofs.flat_map(|(_, _, bytes)| bytes))
            .chain(additional_proofs);
        let mut zk_db = self.zk_db.borrow_mut();
        for bytes in proofs {
            zk_db.add_node_bytes(bytes).unwrap();
        }
        Ok(())
    }

    /// construct from external data, with additional proofs (trie node) can be
    /// provided
    pub fn from_trace_with_additional<'d, BYTES>(
        state_root: Hash,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES)> + Clone,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d Word, BYTES)> + Clone,
        additional_proofs: impl Iterator<Item = &'d [u8]> + Clone,
    ) -> Result<Self, Error>
    where
        BYTES: IntoIterator<Item = &'d [u8]>,
    {
        let mut state = ZktrieState::construct(state_root);
        state.update_statedb_from_proofs(
            account_proofs.clone(),
            storage_proofs.clone(),
            additional_proofs.clone(),
        )?;
        state.update_nodes_from_proofs(account_proofs, storage_proofs, additional_proofs)?;
        Ok(state)
    }
}

#[cfg(any(feature = "test", test))]
mod test;
