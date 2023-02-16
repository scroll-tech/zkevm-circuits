//! Implementation of an in-memory key-value database to represent the
//! Ethereum State Trie.

use crate::precompile::is_precompiled;
use eth_types::{Address, Hash, Word, H256, U256};
use ethers_core::utils::keccak256;
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};

lazy_static! {
    static ref ACCOUNT_ZERO: Account = Account::zero();
    static ref VALUE_ZERO: Word = Word::zero();
    static ref CODE_HASH_ZERO: Hash = H256(keccak256([]));
}

/// Define any object can encode the code to a 32 bytes hash
pub trait CodeHash: std::fmt::Debug {
    /// encode code
    fn hash_code(&self, code: &[u8]) -> Hash;
}

/// Helper trait for clone object in a object-safe way
pub trait CodeHashCopy: CodeHash {
    /// clone to a boxed obect
    fn clone_box(&self) -> Box<dyn CodeHashCopy>;
}

impl<T> CodeHashCopy for T
where
    T: 'static + CodeHash + Clone,
{
    fn clone_box(&self) -> Box<dyn CodeHashCopy> {
        Box::new(self.clone())
    }
}

/// Memory storage for contract code by code hash.
#[derive(Debug)]
pub struct CodeDB(pub HashMap<Hash, Vec<u8>>, Box<dyn CodeHashCopy>);

impl Clone for CodeDB {
    fn clone(&self) -> Self {
        CodeDB(self.0.clone(), self.1.clone_box())
    }
}

impl Default for CodeDB {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct EthCodeHash;

impl CodeHash for EthCodeHash {
    fn hash_code(&self, code: &[u8]) -> Hash {
        H256(keccak256(code))
    }
}

impl CodeDB {
    /// Create a new empty Self with specified code hash method
    pub fn new_with_code_hasher(hasher: Box<dyn CodeHashCopy>) -> Self {
        Self(HashMap::new(), hasher)
    }
    /// Create a new empty Self.
    pub fn new() -> Self {
        Self::new_with_code_hasher(Box::new(EthCodeHash))
    }
    /// Insert code indexed by code hash, and return the code hash. Notice we
    /// always return Self::empty_code_hash() for empty code
    pub fn insert(&mut self, code: Vec<u8>) -> Hash {
        let hash = if code.is_empty() {
            Self::empty_code_hash()
        } else {
            self.1.hash_code(&code)
        };
        self.0.insert(hash, code);
        hash
    }
    /// Specify code hash for empty code (nil), it should be kept consistent
    /// between different methods because many contract use this magic hash
    /// for distinguishing accounts without contracts
    pub fn empty_code_hash() -> Hash {
        *CODE_HASH_ZERO
    }
}

/// Account of the Ethereum State Trie, which contains an in-memory key-value
/// database that represents the Account Storage Trie.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Account {
    /// Nonce
    pub nonce: Word,
    /// Balance
    pub balance: Word,
    /// Storage key-value map
    pub storage: HashMap<Word, Word>,
    /// Code hash
    pub code_hash: Hash,
}

impl Account {
    /// Return an empty account, with all values set at zero.
    pub fn zero() -> Self {
        Self {
            nonce: Word::zero(),
            balance: Word::zero(),
            storage: HashMap::new(),
            code_hash: *CODE_HASH_ZERO,
        }
    }

    /// Return if account is empty or not.
    pub fn is_empty(&self) -> bool {
        self.nonce.is_zero() && self.balance.is_zero() && self.code_hash.eq(&CODE_HASH_ZERO)
    }
}

/// In-memory key-value database that represents the Ethereum State Trie.
#[derive(Debug, Clone, Default)]
pub struct StateDB {
    state: HashMap<Address, Account>,

    // Fields with transaction lifespan, will be clear in `clear_access_list_and_refund`.
    access_list_account: HashSet<Address>,
    access_list_account_storage: HashSet<(Address, U256)>,
    // `dirty_storage` contains writes during current transaction.
    // When current transaction finishes, `dirty_storage` will be committed into `state`.
    // The reason why we need this is that EVM needs committed state, namely
    // state before current transaction, to calculate gas cost for some opcodes like sstore.
    // So both dirty storage and committed storage are needed.
    dirty_storage: HashMap<(Address, Word), Word>,
    // Accounts that have been through `SELFDESTRUCT` under the situation that `is_persistent` is
    // `true`. These accounts will be reset once `commit_tx` is called.
    destructed_account: HashSet<Address>,
    refund: u64,
}

impl StateDB {
    /// Create an empty Self
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
            access_list_account: HashSet::new(),
            access_list_account_storage: HashSet::new(),
            dirty_storage: HashMap::new(),
            destructed_account: HashSet::new(),
            refund: 0,
        }
    }

    /// Set an [`Account`] at `addr` in the StateDB.
    pub fn set_account(&mut self, addr: &Address, acc: Account) {
        self.state.insert(*addr, acc);
    }

    /// Get a reference to the [`Account`] at `addr`.  Returns false and a zero
    /// [`Account`] when the [`Account`] wasn't found in the state.
    pub fn get_account(&self, addr: &Address) -> (bool, &Account) {
        match self.state.get(addr) {
            Some(acc) => (true, acc),
            None => (false, &(*ACCOUNT_ZERO)),
        }
    }

    /// Get a mutable reference to the [`Account`] at `addr`.  If the
    /// [`Account`] is not found in the state, a zero one will be inserted
    /// and returned along with false.
    pub fn get_account_mut(&mut self, addr: &Address) -> (bool, &mut Account) {
        let found = if self.state.contains_key(addr) {
            true
        } else {
            self.state.insert(*addr, Account::zero());
            false
        };
        (found, self.state.get_mut(addr).expect("addr not inserted"))
    }

    /// Get a reference to the storage value from [`Account`] at `addr`, at
    /// `key`.  Returns false and a zero [`Word`] when the [`Account`] or `key`
    /// wasn't found in the state.
    /// Returns dirty storage state, which includes writes in current tx
    pub fn get_storage(&self, addr: &Address, key: &Word) -> (bool, &Word) {
        match self.dirty_storage.get(&(*addr, *key)) {
            Some(v) => (true, v),
            None => self.get_committed_storage(addr, key),
        }
    }

    /// Get a reference to the storage value from [`Account`] at `addr`, at
    /// `key`.  Returns false and a zero [`Word`] when the [`Account`] or `key`
    /// wasn't found in the state.
    /// Returns committed storage, which is storage state before current tx
    pub fn get_committed_storage(&self, addr: &Address, key: &Word) -> (bool, &Word) {
        let (_, acc) = self.get_account(addr);
        match acc.storage.get(key) {
            Some(value) => (true, value),
            None => (false, &(*VALUE_ZERO)),
        }
    }

    /// Get a mutable reference to the storage value from [`Account`] at `addr`,
    /// at `key`.  Returns false when the [`Account`] or `key` wasn't found in
    /// the state and it is created.  If the [`Account`] or `key` is not found
    /// in the state, a zero [`Account`] will be inserted, a zero value will
    /// be inserted at `key` in its storage, and the value will be returned
    /// along with false.
    pub fn get_storage_mut(&mut self, addr: &Address, key: &Word) -> (bool, &mut Word) {
        let (_, acc) = self.get_account_mut(addr);
        let found = if acc.storage.contains_key(key) {
            true
        } else {
            acc.storage.insert(*key, Word::zero());
            false
        };
        (found, acc.storage.get_mut(key).expect("key not inserted"))
    }

    /// Set storage value at `addr` and `key`.
    /// Writes into dirty_storage during transaction execution.
    /// After transaction execution, `dirty_storage` is committed into `storage`
    /// in `commit_tx` method.
    pub fn set_storage(&mut self, addr: &Address, key: &Word, value: &Word) {
        self.dirty_storage.insert((*addr, *key), *value);
    }

    /// Get nonce of account with `addr`.
    pub fn get_nonce(&self, addr: &Address) -> u64 {
        let (_, account) = self.get_account(addr);
        account.nonce.as_u64()
    }

    /// Increase nonce of account with `addr` and return the previous value.
    pub fn increase_nonce(&mut self, addr: &Address) -> u64 {
        let (_, account) = self.get_account_mut(addr);
        let nonce = account.nonce.as_u64();
        account.nonce = account.nonce + 1;
        nonce
    }

    /// Check whether `addr` exists in account access list.
    ///
    /// Note: After the hardfork Berlin,
    /// all the precompiled contracts addresses are always considered warm.
    pub fn check_account_in_access_list(&self, addr: &Address) -> bool {
        is_precompiled(addr) || self.access_list_account.contains(addr)
    }

    /// Add `addr` into account access list. Returns `true` if it's not in the
    /// access list before.
    pub fn add_account_to_access_list(&mut self, addr: Address) -> bool {
        self.access_list_account.insert(addr)
    }

    /// Remove `addr` from account access list.
    pub fn remove_account_from_access_list(&mut self, addr: &Address) {
        let exist = self.access_list_account.remove(addr);
        debug_assert!(exist);
    }

    /// Check whether `(addr, key)` exists in account storage access list.
    pub fn check_account_storage_in_access_list(&self, pair: &(Address, Word)) -> bool {
        self.access_list_account_storage.contains(pair)
    }

    /// Add `(addr, key)` into account storage access list. Returns `true` if
    /// it's not in the access list before.
    pub fn add_account_storage_to_access_list(&mut self, (addr, key): (Address, Word)) -> bool {
        self.access_list_account_storage.insert((addr, key))
    }

    /// Remove `(addr, key)` from account storage access list.
    pub fn remove_account_storage_from_access_list(&mut self, pair: &(Address, Word)) {
        let exist = self.access_list_account_storage.remove(pair);
        debug_assert!(exist);
    }

    /// Set account as self destructed.
    pub fn destruct_account(&mut self, addr: Address) {
        self.destructed_account.insert(addr);
    }

    /// Retrieve refund.
    pub fn refund(&self) -> u64 {
        self.refund
    }

    /// Set refund
    pub fn set_refund(&mut self, value: u64) {
        self.refund = value;
    }

    /// Clear access list and refund, and commit dirty storage.
    /// It should be invoked before processing
    /// with new transaction with the same [`StateDB`].
    pub fn commit_tx(&mut self) {
        self.access_list_account = HashSet::new();
        self.access_list_account_storage = HashSet::new();
        for ((addr, key), value) in self.dirty_storage.clone() {
            let (_, ptr) = self.get_storage_mut(&addr, &key);
            *ptr = value;
        }
        self.dirty_storage = HashMap::new();
        for addr in self.destructed_account.clone() {
            let (_, account) = self.get_account_mut(&addr);
            *account = ACCOUNT_ZERO.clone();
        }
        self.refund = 0;
    }
}

#[cfg(test)]
mod statedb_tests {
    use super::*;
    use eth_types::address;

    #[test]
    fn statedb() {
        let addr_a = address!("0x0000000000000000000000000000000000000001");
        let addr_b = address!("0x0000000000000000000000000000000000000002");
        let mut statedb = StateDB::new();

        // Get non-existing account
        let (found, acc) = statedb.get_account(&addr_a);
        assert!(!found);
        assert_eq!(acc, &Account::zero());

        // Get non-existing storage key for non-existing account
        let (found, value) = statedb.get_storage(&addr_a, &Word::from(2));
        assert!(!found);
        assert_eq!(value, &Word::zero());

        // Get mut non-existing account and set nonce
        let (found, acc) = statedb.get_account_mut(&addr_a);
        assert!(!found);
        assert_eq!(acc, &Account::zero());
        acc.nonce = Word::from(100);

        // Get existing account and check nonce
        let (found, acc) = statedb.get_account(&addr_a);
        assert!(found);
        assert_eq!(acc.nonce, Word::from(100));

        // Get non-existing storage key for existing account and set value
        let (found, value) = statedb.get_storage_mut(&addr_a, &Word::from(2));
        assert!(!found);
        assert_eq!(value, &Word::zero());
        *value = Word::from(101);

        // Get existing storage key and check value
        let (found, value) = statedb.get_storage(&addr_a, &Word::from(2));
        assert!(found);
        assert_eq!(value, &Word::from(101));

        // Get non-existing storage key for non-existing account and set value
        let (found, value) = statedb.get_storage_mut(&addr_b, &Word::from(3));
        assert!(!found);
        assert_eq!(value, &Word::zero());
        *value = Word::from(102);

        // Get existing account and check nonce
        let (found, acc) = statedb.get_account(&addr_b);
        assert!(found);
        assert_eq!(acc.nonce, Word::zero());

        // Get existing storage key and check value
        let (found, value) = statedb.get_storage(&addr_b, &Word::from(3));
        assert!(found);
        assert_eq!(value, &Word::from(102));
    }
}
