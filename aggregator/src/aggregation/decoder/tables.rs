/// Since bitstrings to decode can be spanned over more than one byte from the encoded bytes, we
/// construct a table to accumulate the binary values of the byte-unaligned bitstrings for decoding
/// convenience.
mod bitstring;
pub use bitstring::BitstringTable;

/// FSE table.
mod fse;
pub use fse::FseTable;

/// Decode the regenerated size from the literals header.
mod literals_header;
pub use literals_header::LiteralsHeaderTable;

/// Input for validating the sequence instruction comes from the parsed value
mod seqinst_table;
pub use seqinst_table::SeqInstTable;

/// Fixed lookup table and its variants.
pub mod fixed;
pub use fixed::{FixedLookupTag, FixedTable};

#[cfg(test)]
pub use fixed::predefined_fse::{predefined_fse, PredefinedFse};
