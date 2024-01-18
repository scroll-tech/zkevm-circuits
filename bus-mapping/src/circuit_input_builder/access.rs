use crate::operation::RW;
use eth_types::{geth_types::GethData, Address, GethPrestateTrace, Word};
use std::collections::{hash_map::Entry, HashMap, HashSet};

/// State and Code Access with "keys/index" used in the access operation.
#[derive(Debug, PartialEq, Eq)]
pub enum AccessValue {
    /// Account access
    Account {
        /// Account address
        address: Address,
    },
    /// Storage access
    Storage {
        /// Storage account address
        address: Address,
        /// Storage key
        key: Word,
    },
    /// Code access
    Code {
        /// Code address
        address: Address,
    },
}

/// State Access caused by a transaction or an execution step
#[derive(Debug, PartialEq, Eq)]
pub struct Access {
    step_index: Option<usize>,
    rw: RW,
    value: AccessValue,
}

impl Access {
    pub(crate) fn new(step_index: Option<usize>, rw: RW, value: AccessValue) -> Self {
        Self {
            step_index,
            rw,
            value,
        }
    }
}

/// State and Code Access set.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct AccessSet {
    /// Set of accounts
    pub state: HashMap<Address, HashSet<Word>>,
    /// Set of accounts code
    pub code: HashSet<Address>,
}

impl AccessSet {
    #[inline(always)]
    pub(crate) fn add_account(&mut self, address: Address) {
        self.state.entry(address).or_default();
    }

    #[inline(always)]
    pub(crate) fn add_storage(&mut self, address: Address, key: Word) {
        match self.state.entry(address) {
            Entry::Vacant(entry) => {
                let mut storage = HashSet::new();
                storage.insert(key);
                entry.insert(storage);
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().insert(key);
            }
        }
    }

    #[inline(always)]
    pub(crate) fn add_code(&mut self, address: Address) {
        self.state.entry(address).or_default();
        self.code.insert(address);
    }

    pub(crate) fn extend_from_access(&mut self, list: Vec<Access>) {
        for access in list {
            match access.value {
                AccessValue::Account { address } => self.add_account(address),
                AccessValue::Storage { address, key } => self.add_storage(address, key),
                AccessValue::Code { address } => self.add_code(address),
            }
        }
    }

    pub(crate) fn extend_from_traces(&mut self, traces: &HashMap<Address, GethPrestateTrace>) {
        for (address, trace) in traces.iter() {
            self.add_account(*address);
            self.add_code(*address);
            if let Some(ref storage) = trace.storage {
                for key in storage.keys() {
                    self.add_storage(*address, *key);
                }
            }
        }
    }

    pub(crate) fn extend(&mut self, other: &mut Self) {
        self.state.extend(other.state.drain());
        self.code.extend(other.code.drain());
    }

    pub(crate) fn from_geth_data(geth_data: &GethData) -> Self {
        let mut access_set = AccessSet::default();
        access_set.add_account(geth_data.eth_block.author.unwrap());
        for trace in geth_data.geth_traces.iter() {
            access_set.extend_from_traces(&trace.prestate);
        }
        access_set
    }
}

/// Source of the code in the EVM execution.
#[derive(Debug, Clone, Copy)]
pub enum CodeSource {
    /// Code comes from a deployed contract at `Address`.
    Address(Address),
    /// Code comes from tx.data when tx.to == null.
    Tx,
    /// Code comes from Memory by a CREATE* opcode.
    Memory,
}

impl Default for CodeSource {
    fn default() -> Self {
        Self::Tx
    }
}
