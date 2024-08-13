//! Represent the storage state under zktrie as implement
use eth_types::{Address, Hash, H256};

use std::{collections::HashSet, io::Error};
pub use zktrie::{Hash as ZkTrieHash, ZkMemoryDb, ZkTrieNode};
use zktrie::{UpdateDb, ZkTrie as ZktrieT};
/// export updatable type of zktrie
pub type ZkTrie = ZktrieT<UpdateDb>;

pub mod builder;
pub use builder::{AccountData, StorageData};

use std::{fmt, rc::Rc};

/// represent a storage state being applied in specified block
#[derive(Clone)]
pub struct ZktrieState {
    /// The underlying db
    pub zk_db: Rc<ZkMemoryDb>,
    /// Trie root
    pub trie_root: ZkTrieHash,
    addr_cache: HashSet<Address>,
    storage_cache: HashSet<(Address, H256)>,
}

//unsafe impl Send for ZktrieState {}

impl fmt::Debug for ZktrieState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ZktrieState: {:x?}", self.trie_root,)
    }
}

impl Default for ZktrieState {
    fn default() -> Self {
        Self::construct(Default::default())
    }
}

impl ZktrieState {
    /// help to query account data
    pub fn root(&self) -> &ZkTrieHash {
        &self.trie_root
    }
    /// construct from external data
    pub fn construct(
        //sdb: StateDB,
        state_root: Hash,
        //proofs: impl IntoIterator<Item = &'d [u8]>,
        //acc_storage_roots: impl IntoIterator<Item = (Address, Hash)>,
    ) -> Self {
        builder::init_hash_scheme();

        Self {
            zk_db: Rc::new(ZkMemoryDb::new()),
            trie_root: state_root.0,
            addr_cache: HashSet::new(),
            storage_cache: HashSet::new(),
        }
    }

    /// expose writable db, has to be used when no trie is created
    pub fn expose_db(&mut self) -> &mut ZkMemoryDb {
        Rc::get_mut(&mut self.zk_db).expect("no extra reference")
    }

    /// apply the updates in Zktries into underlying db
    pub fn updated_with_trie(&mut self, tries: impl Iterator<Item = ZkTrie>) {
        let updated_data = tries.map(|tr| tr.updated_db()).collect::<Vec<_>>();
        // note we must first collect the dbs (and drop all reference to current underlying db)
        // or `exposed_db` would fail
        updated_data
            .into_iter()
            .fold(self.expose_db(), |db, merged_db| {
                db.update(merged_db);
                db
            });
    }

    /// prepare to switch to another root state (trie snapshot)
    /// it is ok that even the db is not ready for this state
    /// cache is cleared so user can fill db with new storage traces
    pub fn prepare_switch_to(&mut self, new_root: ZkTrieHash) {
        self.trie_root = new_root;
        self.addr_cache.clear();
        self.storage_cache.clear();
    }

    /// switch to another root state (trie snapshot)
    /// return true if the switch success, or false if db have not contain
    /// corresponding root yet
    /// if we have built ZkTrie from the underlying db and updated it
    /// (like in mpt witness updating), the updated Zktrie must be merged back
    /// to the underlying db by `updated_with_trie`
    /// notice the cached key would not be clean if we can successfully switch to
    /// new snapshot since we consider it is not need to send more nodes data
    /// from storage trace for the updated leaves
    pub fn switch_to(&mut self, new_root: ZkTrieHash) -> bool {
        let test_trie = self.zk_db.new_trie(&new_root);
        if test_trie.is_none() {
            return false;
        }
        self.trie_root = new_root;
        true
    }

    /// query a series account data from underlying db
    pub fn query_accounts<'d: 'a, 'a>(
        &self,
        accounts: impl Iterator<Item = &'a Address> + 'd,
    ) -> impl Iterator<Item = (Address, Option<AccountData>)> + 'a {
        let trie = self.zk_db.new_ref_trie(&self.trie_root).unwrap();
        accounts.map(move |&addr| {
            let account = trie.get_account(addr.as_bytes()).map(AccountData::from);
            (addr, account)
        })
    }

    /// query a series store data from underlying db
    pub fn query_storages<'d: 'a, 'a>(
        &self,
        storages: impl Iterator<Item = (&'a Address, &'a H256)> + 'd,
    ) -> impl Iterator<Item = ((Address, H256), Option<StorageData>)> + 'a {
        use std::collections::{hash_map::Entry::*, HashMap};
        let zk_db = self.zk_db.clone();
        let account_trie = zk_db.new_ref_trie(&self.trie_root).unwrap();
        let mut trie_cache = HashMap::new();
        storages.map(move |(&addr, &key)| {
            let store_val = match trie_cache.entry(addr) {
                Occupied(entry) => Some(entry.into_mut()),
                Vacant(entry) => account_trie
                    .get_account(addr.as_bytes())
                    .map(AccountData::from)
                    .and_then(|account| {
                        zk_db
                            .new_ref_trie(&account.storage_root.0)
                            .map(|tr| entry.insert(tr))
                    }),
            }
            .and_then(|tr| tr.get_store(key.as_bytes()).map(StorageData::from));
            ((addr, key), store_val)
        })
    }

    /// Helper for parsing account data from external data (mainly storage trace)
    pub fn parse_account_from_proofs<'d: 'a, 'a, BYTES>(
        account_proofs: impl Iterator<Item = (&'a Address, BYTES)> + 'd,
    ) -> impl Iterator<Item = Result<(Address, AccountData), Error>> + 'a
    where
        BYTES: IntoIterator<Item = &'a [u8]>,
    {
        use builder::{AccountProof, BytesArray};
        account_proofs.map(|(&addr, bytes)| {
            let acc_proof = builder::verify_proof_leaf(
                AccountProof::try_from(BytesArray(bytes.into_iter()))?,
                &builder::extend_address_to_h256(&addr),
            );
            Ok((addr, acc_proof.data))
        })
    }

    /// Helper for parsing storage value from external data
    pub fn parse_storage_from_proofs<'d: 'a, 'a, BYTES>(
        storage_proofs: impl Iterator<Item = (&'a Address, &'a H256, BYTES)> + 'd,
    ) -> impl Iterator<Item = Result<((Address, H256), StorageData), Error>> + 'a
    where
        BYTES: IntoIterator<Item = &'a [u8]>,
    {
        use builder::{BytesArray, StorageProof};
        storage_proofs.map(|(&addr, &key, bytes)| {
            let storage_key: (Address, H256) = (addr, key);
            let key_buf = key.to_fixed_bytes();
            let bytes_array = BytesArray(bytes.into_iter());
            let store_proof =
                builder::verify_proof_leaf(StorageProof::try_from(bytes_array)?, &key_buf);
            if store_proof.key.is_some() {
                log::trace!(
                    "insert storage key {:?} value {:?}",
                    storage_key,
                    *store_proof.data.as_ref()
                );
                Ok((storage_key, store_proof.data))
            } else {
                log::trace!("insert storage key {:?} for zero", storage_key);
                Ok((storage_key, Default::default()))
            }
        })
    }

    /// incremental updating nodes in db from external data
    pub fn update_from_trace<'d, BYTES1, BYTES2>(
        &mut self,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES1)>,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d H256, BYTES2)>,
        additional_proofs: impl Iterator<Item = &'d [u8]>,
    ) where
        BYTES1: IntoIterator<Item = &'d [u8]>,
        BYTES2: IntoIterator<Item = &'d [u8]>,
    {
        let proofs = account_proofs
            .filter(|(&addr, _)| self.addr_cache.insert(addr))
            .flat_map(|(_, bytes)| bytes)
            .chain(
                storage_proofs
                    .filter(|(&addr, &key, _)| self.storage_cache.insert((addr, key)))
                    .flat_map(|(_, _, bytes)| bytes),
            )
            .chain(additional_proofs);
        let zk_db = Rc::get_mut(&mut self.zk_db).expect("no extra reference");
        for bytes in proofs {
            zk_db.add_node_data(bytes).unwrap();
        }
    }

    /// construct from external data, with additional proofs (trie node) can be
    /// provided
    pub fn from_trace_with_additional<'d, BYTES1, BYTES2>(
        state_root: Hash,
        account_proofs: impl Iterator<Item = (&'d Address, BYTES1)>,
        storage_proofs: impl Iterator<Item = (&'d Address, &'d H256, BYTES2)>,
        additional_proofs: impl Iterator<Item = &'d [u8]>,
    ) -> Result<Self, Error>
    where
        BYTES1: IntoIterator<Item = &'d [u8]>,
        BYTES2: IntoIterator<Item = &'d [u8]>,
    {
        let mut state = ZktrieState::construct(state_root);

        // a lot of poseidon computation
        state.update_from_trace(account_proofs, storage_proofs, additional_proofs);

        Ok(state)
    }

    /// get the inner zk memory db
    pub fn into_inner(self) -> Rc<ZkMemoryDb> {
        self.zk_db
    }
}
