//! Doc this
use crate::{DebugByte, Error, ToBigEndian, Word};
use core::{
    ops::{Add, AddAssign, Index, IndexMut, Mul, MulAssign, Range, Sub, SubAssign},
    str::FromStr,
};
use itertools::Itertools;
use serde::{Serialize, Serializer};
use std::{cmp, cmp::max, fmt};

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

impl_partial_eq_wrappers!(MemoryAddress, (u8, u16, u32, u64, usize, i32, i64));

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
        Word::from_big_endian(&self.read_chunk(MemoryRange::new_with_length(addr, 32)))
    }

    /// Reads an chunk of memory[offset..offset+length]. Zeros will be padded if
    /// index out of range.
    pub fn read_chunk(&self, range: impl Into<MemoryRange>) -> Vec<u8> {
        MemoryRef::from(self).read_chunk(range)
    }

    /// Write a chunk of memory[offset..offset+length]. If any data is written out-of-bound, it must
    /// be zeros. This does not resize the memory.
    pub fn write_chunk(&mut self, offset: MemoryAddress, data: &[u8]) {
        let len = if self.0.len() > offset.0 {
            let len = cmp::min(data.len(), self.0.len() - offset.0);
            // Copy the data to the in-bound memory.
            self.0[offset.0..offset.0 + len].copy_from_slice(&data[..len]);
            len
        } else {
            0
        };
        // Check that the out-of-bound data is all zeros.
        for b in &data[len..] {
            assert_eq!(*b, 0);
        }
    }

    /// Returns the size of memory in word.
    pub fn word_size(&self) -> usize {
        self.0.len() / 32
    }

    /// Resize the memory for at least length and align to 32 bytes.
    /// Note: must not be called when the length accessed is zero. Prefer extend_for_range(..).
    pub fn extend_at_least(&mut self, minimal_size: usize) {
        let memory_size = Self::align_length(minimal_size);
        if memory_size > self.0.len() {
            self.0.resize(memory_size, 0);
        }
    }

    /// Resize the memory for at least `offset+length` and align to 32 bytes, except if `length=0`
    /// then do nothing.
    pub fn extend_for_range(&mut self, offset: Word, length: Word) {
        // `length` should be checked for overflow during gas cost calculation.
        let length = length.as_usize();
        if length != 0 {
            // `dst_offset` should be within range if length is non-zero.
            let offset = offset.as_usize();
            self.extend_at_least(offset + length);
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
            let mem_ends = mem_starts + length;
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

    /// Calculate memory length aligned to 32 bytes.
    #[inline(always)]
    fn align_length(len: usize) -> usize {
        (len + 31) / 32 * 32
    }
}

/// Reference of the EVM memory
pub struct MemoryRef<'a>(pub &'a [u8]);

impl<'a> From<&'a Memory> for MemoryRef<'a> {
    fn from(memory: &'a Memory) -> Self {
        MemoryRef(&memory.0)
    }
}

impl<'a> MemoryRef<'a> {
    /// Reads an chunk of memory[offset..offset+length]. Zeros will be padded if
    /// index out of range.
    pub fn read_chunk(&self, range: impl Into<MemoryRange>) -> Vec<u8> {
        let range = range.into();
        let start_offset = range.start.0;
        let length = range.length().0;
        let chunk = if self.0.len() < start_offset {
            &[]
        } else {
            &self.0[start_offset..]
        };
        let chunk = if chunk.len() < length {
            // Expand chunk to expected size
            chunk.iter().cloned().pad_using(length, |_| 0).collect()
        } else {
            chunk[..length].to_vec()
        };
        chunk
    }
}

/// Represents a range of memory addresses of [start,end).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MemoryRange {
    start: MemoryAddress,
    end: MemoryAddress,
}

impl MemoryRange {
    /// Creates a new memory range with the provided start and length.
    pub fn new_with_length(
        start: impl Into<MemoryAddress>,
        length: impl Into<MemoryAddress>,
    ) -> Self {
        let start = start.into();
        let end = start + length.into();
        Self { start, end }
    }

    /// length of the memory range.
    #[inline(always)]
    pub fn length(&self) -> MemoryAddress {
        self.end - self.start
    }
}

/// Represents a 32 bytes .
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MemoryWordRange {
    /// a memory range aligned to 32 bytes
    range: MemoryRange,
    /// length of the original range in bytes
    original_length: MemoryAddress,
    /// shift bytes regard to the start
    shift: MemoryAddress,
}

impl MemoryWordRange {
    /// Manually construct a new MemoryWordRange.
    ///
    /// # Panics
    /// - Will panic if `start` is not aligned to 32 bytes.
    /// - Will panic if `full_length` is not aligned to 32 bytes.
    /// - Will panic if `original_length` is not greater than `full_length`.
    /// - Will panic if `shift` is greater than 31.
    pub fn new(
        start: impl Into<MemoryAddress>,
        full_length: impl Into<MemoryAddress>,
        original_length: impl Into<MemoryAddress>,
        shift: impl Into<MemoryAddress>,
    ) -> Self {
        let start = start.into();
        let full_length = full_length.into();
        let original_length = original_length.into();
        let shift = shift.into();
        assert_eq!(start.0 % 32, 0, "start must be a aligned to 32 bytes");
        assert_eq!(
            full_length.0 % 32,
            0,
            "full_length must be a aligned to 32 bytes"
        );
        assert!(
            original_length <= full_length,
            "original_length must be less or equal than full_length"
        );
        assert!(shift.0 < 32, "shift must be less than 32");
        let range = MemoryRange::new_with_length(start, full_length);
        Self {
            range,
            original_length,
            shift,
        }
    }

    /// Manually construct a new MemoryWordRange with already aligned range.
    #[inline(always)]
    pub fn new_aligned(start: impl Into<MemoryAddress>, length: usize) -> Self {
        Self::new(start, length, length, 0)
    }

    /// Find the aligned range that contains an unaligned range.
    ///
    /// Given a range `[offset; offset+length)`, return:
    /// - the `slot` offset, aligned to 32 bytes, at or just before `offset`.
    /// - the `full_length` as a multiple of 32 bytes, such that `[slot, slot+full_length)` contains
    ///   the given range. If `length=0`, then `full_length=0` too.
    /// - the `shift` of the offset into the slot, such that `offset = slot + shift`.
    pub fn align_range(offset: impl Into<MemoryAddress>, length: impl Into<MemoryAddress>) -> Self {
        let offset = offset.into().0;
        let length = length.into().0;
        let shift = offset % 32;
        let slot = offset - shift;

        let slot_end = Memory::align_length(offset + length);
        let full_length = if length == 0 { 0 } else { slot_end - slot };

        Self::new(slot, full_length, length, shift)
    }

    /// Ensure that two range has same length.
    #[inline(always)]
    pub fn ensure_equal_length(&mut self, other: &mut Self) {
        let full_length = max(self.full_length(), other.full_length());
        self.range = MemoryRange::new_with_length(self.range.start, full_length);
        other.range = MemoryRange::new_with_length(other.range.start, full_length);
    }

    /// Returns the word count of the aligned range.
    #[inline(always)]
    pub fn word_count(&self) -> usize {
        self.full_length().0 / 32
    }

    /// Returns the start slot as MemoryAddress.
    #[inline(always)]
    pub fn start_slot(&self) -> MemoryAddress {
        self.range.start
    }

    /// Returns the end slot as MemoryAddress.
    #[inline(always)]
    pub fn end_slot(&self) -> MemoryAddress {
        self.range.end
    }

    /// Returns the length of the aligned range.
    #[inline(always)]
    pub fn full_length(&self) -> MemoryAddress {
        self.range.length()
    }

    /// Returns the length of the original range
    #[inline(always)]
    pub fn original_length(&self) -> MemoryAddress {
        self.original_length
    }

    /// Returns the shift of the offset into the start slot.
    #[inline(always)]
    pub fn shift(&self) -> MemoryAddress {
        self.shift
    }
}

impl From<MemoryWordRange> for MemoryRange {
    fn from(value: MemoryWordRange) -> Self {
        value.range
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

    #[test]
    fn align_range() {
        const WORD: usize = 32;

        // Adding 32 to an offsets or to a length does not change the logic of alignment,
        // so we test different combinations of base `o` and base `l`.
        let base_offsets = [0, WORD, 1000000 * WORD];
        let base_lengths = [0, WORD, 1000000 * WORD];

        for o in base_offsets {
            // Get (slot, full_length, shift) from (offset, length).

            // When length=0, full_length=0.
            assert_eq!(
                MemoryWordRange::new(o, 0, 0, 0),
                MemoryWordRange::align_range(o, 0)
            );
            assert_eq!(
                MemoryWordRange::new(o, 0, 0, 1),
                MemoryWordRange::align_range(o + 1, 0)
            );
            assert_eq!(
                MemoryWordRange::new(o, 0, 0, 31),
                MemoryWordRange::align_range(o + 31, 0)
            );

            for l in base_lengths {
                // When length=1, it is always ONE WORD.
                assert_eq!(
                    MemoryWordRange::new(o, l + WORD, l + 1, 0),
                    MemoryWordRange::align_range(o, l + 1)
                );
                assert_eq!(
                    MemoryWordRange::new(o, l + WORD, l + 1, 1),
                    MemoryWordRange::align_range(o + 1, l + 1)
                );
                assert_eq!(
                    MemoryWordRange::new(o, l + WORD, l + 1, 31),
                    MemoryWordRange::align_range(o + 31, l + 1)
                );

                // When the range is still within ONE WORD.
                assert_eq!(
                    MemoryWordRange::new(o, l + WORD, l + 2, 0),
                    MemoryWordRange::align_range(o, l + 2)
                );
                assert_eq!(
                    MemoryWordRange::new(o, l + WORD, l + 31, 0),
                    MemoryWordRange::align_range(o, l + 31)
                );
                assert_eq!(
                    MemoryWordRange::new(o, l + WORD, l + 30, 1),
                    MemoryWordRange::align_range(o + 1, l + 30)
                );
                assert_eq!(
                    MemoryWordRange::new(o, l + WORD, l + 1, 30),
                    MemoryWordRange::align_range(o + 30, l + 1)
                );

                // When the range ends exactly at a word boundary, it is still ONE WORD.
                assert_eq!(
                    MemoryWordRange::new(o, l + WORD, l + 32, 0),
                    MemoryWordRange::align_range(o, l + 32)
                );
                assert_eq!(
                    MemoryWordRange::new(o, l + WORD, l + 30, 2),
                    MemoryWordRange::align_range(o + 2, l + 30)
                );
                assert_eq!(
                    MemoryWordRange::new(o, l + WORD, l + 2, 30),
                    MemoryWordRange::align_range(o + 30, l + 2)
                );

                // When the range spills into a SECOND WORD.
                assert_eq!(
                    MemoryWordRange::new(o, l + 2 * WORD, l + 32, 1),
                    MemoryWordRange::align_range(o + 1, l + 32)
                );
                assert_eq!(
                    MemoryWordRange::new(o, l + 2 * WORD, l + 31, 2),
                    MemoryWordRange::align_range(o + 2, l + 31)
                );
                assert_eq!(
                    MemoryWordRange::new(o, l + 2 * WORD, l + 2, 31),
                    MemoryWordRange::align_range(o + 31, l + 2)
                );
                assert_eq!(
                    MemoryWordRange::new(o, l + 2 * WORD, l + 32, 31),
                    MemoryWordRange::align_range(o + 31, l + 32)
                );
            }
        }
    }
}
