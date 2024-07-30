use crate::{l2_types::BlockTrace, Error, H256};
use itertools::Itertools;

/// Collect bytecodes from trace
pub fn collect_codes(block: &BlockTrace) -> Result<Vec<(H256, Vec<u8>)>, Error> {
    if block.codes.is_empty() {
        return Err(Error::TracingError(format!(
            "codes not available for block {:?}",
            block.header.number
        )));
    }
    Ok(block
        .codes
        .iter()
        .map(|b| (b.hash, b.code.to_vec()))
        .collect_vec())
}
