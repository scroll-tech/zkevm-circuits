//! Doc this
use crate::{DebugWord, Word};
use crate::{Error, ToBigEndian};
use core::str::FromStr;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;

/// Represents a `StackAddress` of the EVM.
/// The address range goes `TOP -> DOWN (1024, 0]`.
#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub struct StackAddress(pub usize);

impl fmt::Debug for StackAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl StackAddress {
    /// Generates a new StackAddress given a `usize`.
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    /// Apply a function to the contained value.
    pub fn map<F: FnOnce(usize) -> usize>(&self, f: F) -> Self {
        Self(f(self.0))
    }
}

// Mostly impl for testing.
impl_from_usize_wrappers!(StackAddress = StackAddress, (u8, u16, u32, usize, i32, i64));

impl From<StackAddress> for usize {
    fn from(addr: StackAddress) -> usize {
        addr.0
    }
}

impl FromStr for StackAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let value = usize::from_str_radix(s, 16).map_err(|_| Error::StackAddressParsing)?;
        // Stack only has 1023 slots available.
        if value >= 1024 {
            return Err(Error::InvalidStackPointer);
        };
        Ok(StackAddress(value))
    }
}

/// Represents a snapshot of the EVM stack state at a certain
/// execution step height.
#[derive(Clone, Eq, PartialEq, Deserialize)]
pub struct Stack(pub Vec<Word>);

impl fmt::Debug for Stack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(DebugWord))
            .finish()
    }
}

impl Serialize for Stack {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser = serializer.serialize_seq(Some(self.0.len()))?;
        for e in self.0.iter() {
            let encoded = hex::encode(e.to_be_bytes());
            let trimmed = encoded.trim_start_matches('0');
            if trimmed.is_empty() {
                ser.serialize_element("0")?;
            } else {
                ser.serialize_element(trimmed)?;
            }
        }
        ser.end()
    }
}

impl<T: Into<Vec<Word>>> From<T> for Stack {
    fn from(words: T) -> Self {
        Stack(words.into())
    }
}

impl Stack {
    /// Generate a new instance of EVM stack.
    pub const fn new() -> Stack {
        Stack(vec![])
    }

    /// Generates a `Stack` instance from the given slice.
    pub fn from_slice(words: &[Word]) -> Self {
        Stack(words.into())
    }

    /// Generates a `Stack` instance from the given vec.
    pub const fn from_vec(words: Vec<Word>) -> Self {
        Stack(words)
    }

    /// Returns the first available/free `StackAddress`.
    pub fn stack_pointer(&self) -> StackAddress {
        // Stack has 1024 slots.
        // First allocation slot for us in the stack is 1023.
        StackAddress::from(1024 - self.0.len())
    }

    /// Returns the last filled `StackAddress`.
    pub fn last_filled(&self) -> StackAddress {
        StackAddress::from(1024 - self.0.len())
    }

    /// Returns the n-th last filled `StackAddress`.
    pub fn nth_last_filled(&self, nth: usize) -> StackAddress {
        StackAddress::from(1024 - self.0.len() + nth)
    }

    /// Returns the last [`Word`] allocated in the `Stack`.
    pub fn last(&self) -> Result<Word, Error> {
        self.0.last().cloned().ok_or(Error::InvalidStackPointer)
    }

    /// Returns the n-th last [`Word`] allocated in the `Stack`.
    pub fn nth_last(&self, nth: usize) -> Result<Word, Error> {
        if self.0.len() < (nth + 1) {
            return Err(Error::InvalidStackPointer);
        }
        self.0
            .get(self.0.len() - (nth + 1))
            .cloned()
            .ok_or(Error::InvalidStackPointer)
    }
}

#[cfg(test)]
mod stack_tests {
    use super::*;
    use crate::word;

    fn setup_stack(stack_value: [&str; 3]) -> Stack {
        Stack::from_vec(vec![
            word!(stack_value[0]),
            word!(stack_value[1]),
            word!(stack_value[2]),
        ])
    }

    #[test]
    fn stack_addr_conversion() -> Result<(), Error> {
        let first_usize = 1023usize;
        let addr1 = StackAddress(first_usize);
        let addr2 = StackAddress::from_str("0x3ff")?;

        assert_eq!(addr1.0, first_usize);
        assert_eq!(addr2.0, first_usize);
        Ok(())
    }

    #[test]
    fn stack_pointer() -> Result<(), Error> {
        let stack = setup_stack(["0x15", "0x16", "0x17"]);

        assert_eq!(stack.stack_pointer(), StackAddress(1021));
        assert_eq!(stack.last_filled(), StackAddress(1021));
        assert_eq!(stack.nth_last_filled(1), StackAddress(1022));
        Ok(())
    }

    #[test]
    fn stack_get_value() -> Result<(), Error> {
        let stack = setup_stack(["0x15", "0x16", "0x17"]);

        assert_eq!(stack.last().unwrap(), word!("0x17"));
        assert_eq!(stack.nth_last(1).unwrap(), word!("0x16"));
        Ok(())
    }
}
