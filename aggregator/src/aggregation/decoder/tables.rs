/// Since bitstrings to decode can be spanned over more than one byte from the encoded bytes, we
/// construct a table to accumulate the binary values of the byte-unaligned bitstrings for decoding
/// convenience.
mod bitstring_accumulation;
pub use bitstring_accumulation::BitstringAccumulationTable;

/// Decode the regenerated size from the literals header.
mod literals_header;
pub use literals_header::LiteralsHeaderTable;

/// The fixed code to Baseline/NumBits for Literal Length.
mod rom_sequence_codes;
pub use rom_sequence_codes::{
    LiteralLengthCodes, MatchLengthCodes, MatchOffsetCodes, RomSequenceCodes,
};

/// Validate the following tag given the tag currently being processed.
mod rom_tag;
pub use rom_tag::RomTagTable;
