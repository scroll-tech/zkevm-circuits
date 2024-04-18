/// Decode the regenerated size from the literals header.
mod literals_header;
pub use literals_header::LiteralsHeaderTable;

/// Validate the following tag given the tag currently being processed.
mod rom_tag;
pub use rom_tag::RomTagTable;
