//! Doc this
use crate::Error;
use crate::{DebugWord, Word};
use std::collections::HashMap;
use std::fmt;

/// Represents a snapshot of the EVM stack state at a certain
/// execution step height.
#[derive(Clone, Eq, PartialEq)]
pub struct Storage(pub(crate) HashMap<Word, Word>);

impl<T: Into<HashMap<Word, Word>>> From<T> for Storage {
    fn from(map: T) -> Self {
        Self(map.into())
    }
}

impl fmt::Debug for Storage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(k, v)| (DebugWord(k), DebugWord(v))))
            .finish()
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::empty()
    }
}

impl Storage {
    /// Generate an empty instance of EVM Storage.
    pub fn empty() -> Self {
        Storage(HashMap::new())
    }

    /// Generate an new instance of EVM storage given a `HashMap<Word, Word>`.
    pub fn new(map: HashMap<Word, Word>) -> Self {
        Self::from(map)
    }

    /// Get the word for a given key in the EVM storage
    pub fn get(&self, key: &Word) -> Option<&Word> {
        self.0.get(key)
    }

    /// Get the word for a given key in the EVM storage.  Returns error if key
    /// is not found.
    pub fn get_or_err(&self, key: &Word) -> Result<Word, Error> {
        self.get(key).cloned().ok_or(Error::InvalidStorageKey)
    }
}
