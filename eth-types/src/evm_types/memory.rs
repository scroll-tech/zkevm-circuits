//! Doc this
use crate::Error;
use crate::{DebugByte, ToBigEndian, Word};
use core::ops::{Add, AddAssign, Index, IndexMut, Mul, MulAssign, Range, Sub, SubAssign};
use core::str::FromStr;
use itertools::Itertools;
use serde::{Serialize, Serializer};
use std::fmt;

/// Represents a `MemoryAddress` of the EVM.
#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub struct MemoryAddress(pub usize);

impl fmt::Debug for MemoryAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("0x{:06x}", self.0))
    }
}

impl MemoryAddress {
    /// Returns the zero address for Memory targets.
    pub const fn zero() -> MemoryAddress {
        MemoryAddress(0usize)
    }

    /// Return the little-endian byte representation of the word as a 32-byte
    /// array.
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut array = [0u8; 32];
        let bytes = self.0.to_le_bytes();
        array[..bytes.len()].copy_from_slice(&bytes[0..bytes.len()]);

        array
    }

    /// Return the big-endian byte representation of the word as a 32-byte
    /// array.
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut array = [0u8; 32];
        let bytes = self.0.to_be_bytes();
        array[32 - bytes.len()..].copy_from_slice(&bytes[0..bytes.len()]);

        array
    }

    /// Generate a MemoryAddress from the provided set of little-endian bytes.
    pub fn from_le_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Error> {
        if bytes.as_ref().len() > core::mem::size_of::<usize>() {
            return Err(Error::InvalidMemoryPointer);
        }
        let mut array = [0u8; core::mem::size_of::<usize>()];
        array[..].copy_from_slice(&bytes.as_ref()[..core::mem::size_of::<usize>()]);
        Ok(MemoryAddress::from(usize::from_le_bytes(array)))
    }

    /// Generate a MemoryAddress from the provided set of big-endian bytes.
    pub fn from_be_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Error> {
        if bytes.as_ref().len() > core::mem::size_of::<usize>() {
            return Err(Error::InvalidMemoryPointer);
        }
        let mut array = [0u8; core::mem::size_of::<usize>()];
        array[..].copy_from_slice(&bytes.as_ref()[..core::mem::size_of::<usize>()]);
        Ok(MemoryAddress::from(usize::from_be_bytes(array)))
    }

    /// Apply a function to the contained value.
    pub fn map<F: FnOnce(usize) -> usize>(&self, f: F) -> Self {
        Self(f(self.0))
    }
}

impl TryFrom<Word> for MemoryAddress {
    type Error = Error;

    fn try_from(word: Word) -> Result<Self, Self::Error> {
        if word.bits() > core::mem::size_of::<usize>() * 8 {
            return Err(Error::WordToMemAddr);
        }
        Ok(MemoryAddress(word.as_usize()))
    }
}

impl_from_usize_wrappers!(
    MemoryAddress = MemoryAddress,
    (u8, u16, u32, u64, usize, i32, i64)
);

impl FromStr for MemoryAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(MemoryAddress(
            usize::from_str_radix(s, 16).map_err(|_| Error::MemAddressParsing)?,
        ))
    }
}

impl Add<&MemoryAddress> for &MemoryAddress {
    type Output = MemoryAddress;

    fn add(self, rhs: &MemoryAddress) -> Self::Output {
        MemoryAddress(self.0 + rhs.0)
    }
}

define_add_variants!(
    LHS = MemoryAddress,
    RHS = MemoryAddress,
    Output = MemoryAddress
);

impl<'b> AddAssign<&'b MemoryAddress> for MemoryAddress {
    fn add_assign(&mut self, _rhs: &'b MemoryAddress) {
        *self = *self + _rhs;
    }
}

define_add_assign_variants!(LHS = MemoryAddress, RHS = MemoryAddress);

impl Sub<&MemoryAddress> for &MemoryAddress {
    type Output = MemoryAddress;

    fn sub(self, rhs: &MemoryAddress) -> Self::Output {
        MemoryAddress(self.0 - rhs.0)
    }
}

define_sub_variants!(
    LHS = MemoryAddress,
    RHS = MemoryAddress,
    Output = MemoryAddress
);

impl<'b> SubAssign<&'b MemoryAddress> for MemoryAddress {
    fn sub_assign(&mut self, _rhs: &'b MemoryAddress) {
        *self = *self - _rhs;
    }
}

define_sub_assign_variants!(LHS = MemoryAddress, RHS = MemoryAddress);

impl Mul<&MemoryAddress> for &MemoryAddress {
    type Output = MemoryAddress;

    fn mul(self, rhs: &MemoryAddress) -> Self::Output {
        MemoryAddress(self.0 * rhs.0)
    }
}

define_mul_variants!(
    LHS = MemoryAddress,
    RHS = MemoryAddress,
    Output = MemoryAddress
);

impl<'b> MulAssign<&'b MemoryAddress> for MemoryAddress {
    fn mul_assign(&mut self, _rhs: &'b MemoryAddress) {
        *self = *self * _rhs;
    }
}

define_mul_assign_variants!(LHS = MemoryAddress, RHS = MemoryAddress);

/// Represents a snapshot of the EVM memory state at a certain
/// execution step height.
#[derive(Clone, Eq, PartialEq)]
pub struct Memory(pub Vec<u8>);

impl fmt::Debug for Memory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            // When formatting with "{:#?}" provide a pretty hex dump
            f.write_str("[\n")?;
            for (index, b) in self.0.chunks(16).enumerate() {
                f.write_fmt(format_args!("\t{:08x}  ", index * 16))?;
                f.write_fmt(format_args!(
                    "{:02x} {:02x} {:02x} {:02x} ",
                    b[0], b[1], b[2], b[3]
                ))?;
                f.write_fmt(format_args!(
                    "{:02x} {:02x} {:02x} {:02x}  ",
                    b[4], b[5], b[6], b[7]
                ))?;
                f.write_fmt(format_args!(
                    "{:02x} {:02x} {:02x} {:02x} ",
                    b[8], b[9], b[10], b[11]
                ))?;
                f.write_fmt(format_args!(
                    "{:02x} {:02x} {:02x} {:02x} ",
                    b[12], b[13], b[14], b[15]
                ))?;
                f.write_str("\n")?;
            }
            f.write_str("]")
        } else {
            f.debug_list()
                .entries(self.0.iter().map(|b| DebugByte(*b)))
                .finish()
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<u8>> for Memory {
    fn from(vec: Vec<u8>) -> Self {
        Memory(vec)
    }
}

impl From<Vec<Word>> for Memory {
    fn from(vec: Vec<Word>) -> Self {
        Memory(vec.iter().flat_map(|word| word.to_be_bytes()).collect())
    }
}

impl Index<Range<usize>> for Memory {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        self.0.index(index)
    }
}

impl IndexMut<Range<usize>> for Memory {
    fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
        self.0.index_mut(index)
    }
}

impl<A: Into<MemoryAddress>> Index<A> for Memory {
    type Output = u8;

    fn index(&self, index: A) -> &Self::Output {
        // MemoryAddress is in base 16. Therefore since the vec is not, we need
        // to shift the addr.
        &self.0[index.into().0 >> 5]
    }
}

impl<A: Into<MemoryAddress>> IndexMut<A> for Memory {
    fn index_mut(&mut self, index: A) -> &mut Self::Output {
        &mut self.0[index.into().0 >> 5]
    }
}

impl Serialize for Memory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = hex::encode(&self.0);
        serializer.serialize_str(encoded.as_str())
    }
}

define_range_index_variants!(
    IN_RANGE = usize,
    OUT_RANGE = MemoryAddress,
    STRUCT_CONTAINER = Memory,
    INDEX_OUTPUT = [u8]
);

impl Memory {
    /// Generate an new empty instance of EVM memory.
    pub const fn new() -> Memory {
        Memory(Vec::new())
    }

    /// Returns true if memory contains no elements.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of elements in the memory.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Pushes a set of bytes or an [`Word`] in the last `Memory` position.
    pub fn push<T: AsRef<[u8]>>(&mut self, input: T) {
        self.0.extend(input.as_ref())
    }

    /// Returns the last memory address written at this execution step height.
    pub fn last_filled_addr(&self) -> MemoryAddress {
        self.0.len().into()
    }

    /// Reads an entire [`Word`] which starts at the provided [`MemoryAddress`]
    /// `addr` and finnishes at `addr + 32`.
    pub fn read_word(&self, addr: MemoryAddress) -> Word {
        Word::from_big_endian(&self.read_chunk(addr, MemoryAddress::from(32)))
    }

    /// Reads an chunk of memory[offset..offset+length]. Zeros will be padded if
    /// index out of range.
    pub fn read_chunk(&self, offset: MemoryAddress, length: MemoryAddress) -> Vec<u8> {
        let chunk = if self.0.len() < offset.0 {
            &[]
        } else {
            &self.0[offset.0..]
        };
        let chunk = if chunk.len() < length.0 {
            // Expand chunk to expected size
            chunk.iter().cloned().pad_using(length.0, |_| 0).collect()
        } else {
            chunk[..length.0].to_vec()
        };
        chunk
    }

    /// Returns the size of memory in word.
    pub fn word_size(&self) -> usize {
        self.0.len() / 32
    }

    /// Resize the memory for at least length and align to 32 bytes.
    pub fn extend_at_least(&mut self, minimal_length: usize) {
        let memory_size = (minimal_length + 31) / 32 * 32;
        if memory_size > self.0.len() {
            self.0.resize(memory_size, 0);
        }
    }

    /// Copy source data to memory. Used in (ext)codecopy/calldatacopy.
    pub fn copy_from(&mut self, dst_offset: Word, src_offset: Word, length: Word, data: &[u8]) {
        // Reference go-ethereum `opCallDataCopy` function for defails.
        // https://github.com/ethereum/go-ethereum/blob/bb4ac2d396de254898a5f44b1ea2086bfe5bd193/core/vm/instructions.go#L299

        // `length` should be checked for overflow during gas cost calculation.
        // Otherwise should return an out of gas error previously.
        let length = length.as_usize();
        if length != 0 {
            // `dst_offset` should be within range if length is non-zero.
            // https://github.com/ethereum/go-ethereum/blob/bb4ac2d396de254898a5f44b1ea2086bfe5bd193/core/vm/common.go#L37
            let dst_offset = dst_offset.as_u64();

            // Reset data offset to the maximum value of Uint64 if overflow.
            let src_offset = u64::try_from(src_offset).unwrap_or(u64::MAX);

            let minimal_length = dst_offset as usize + length;
            self.extend_at_least(minimal_length);

            let mem_starts = dst_offset as usize;
            let mem_ends = mem_starts + length as usize;
            let dst_slice = &mut self.0[mem_starts..mem_ends];
            dst_slice.fill(0);
            let data_starts = src_offset as usize;
            let actual_length = std::cmp::min(
                length,
                data.len().checked_sub(data_starts).unwrap_or_default(),
            );
            if actual_length != 0 {
                let src_slice = &data[data_starts..data_starts + actual_length];
                dst_slice[..actual_length].copy_from_slice(src_slice);
            }
        }
    }
}

#[cfg(test)]
mod memory_tests {

    use super::*;

    #[test]
    fn evmword_mem_addr_conversion() -> Result<(), Error> {
        let first_usize = 64536usize;
        let word = Word::from(first_usize);
        let addr = MemoryAddress::from(first_usize);
        let obtained_addr: MemoryAddress = word.try_into()?;

        assert_eq!(addr, obtained_addr);
        Ok(())
    }

    #[test]
    fn mem_addr_bytes_serialization_trip() -> Result<(), Error> {
        let first_usize = 64536usize;
        // Parsing on both ways works.
        assert_eq!(
            MemoryAddress::from_le_bytes(first_usize.to_le_bytes())?,
            MemoryAddress::from_be_bytes(first_usize.to_be_bytes())?
        );
        let addr = MemoryAddress::from_le_bytes(first_usize.to_le_bytes())?;
        assert_eq!(addr, MemoryAddress::from(first_usize));

        // Little endian export
        let le_obtained_usize = addr.to_le_bytes();
        let mut le_array = [0u8; 8];
        le_array.copy_from_slice(&le_obtained_usize[0..8]);

        // Big endian export
        let mut be_array = [0u8; 8];
        let be_obtained_usize = addr.to_be_bytes();
        be_array.copy_from_slice(&be_obtained_usize[24..32]);

        assert_eq!(first_usize, usize::from_le_bytes(le_array));
        assert_eq!(first_usize, usize::from_be_bytes(be_array));

        Ok(())
    }

    #[test]
    fn push_and_read_works() -> Result<(), Error> {
        let mem_map = Memory(
            [Word::from(0), Word::from(0), Word::from(0x80)]
                .iter()
                .flat_map(|w| w.to_be_bytes())
                .collect(),
        );

        // At this point at position [0x40, 0x80) we've allocated the `0x80`
        // value.

        // If we read a word at addr `0x40` we should get `0x80`.
        assert_eq!(
            mem_map.read_word(MemoryAddress::from(0x40)),
            Word::from(0x80)
        );

        Ok(())
    }
}
