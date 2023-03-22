//! Doc this
use crate::{DebugWord, Error, ToBigEndian, Word};
use serde::{ser::SerializeMap, Serialize, Serializer};
use std::{collections::HashMap, fmt};

/// Represents a snapshot of the EVM stack state at a certain
/// execution step height.
#[derive(Clone, Eq, PartialEq)]
pub struct Storage(pub HashMap<Word, Word>);

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

impl Serialize for Storage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.0.iter() {
            ser.serialize_entry(&hex::encode(k.to_be_bytes()), &hex::encode(v.to_be_bytes()))?;
        }
        ser.end()
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
