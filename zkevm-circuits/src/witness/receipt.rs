use ethers_core::{
    types::{Bloom, Log},
    utils::rlp::{Encodable, RlpStream, TinyRlp},
};

/// EVM log's receipt.
#[derive(Clone, Debug, Default)]
pub struct Receipt {
    /// Denotes whether or not the tx was executed successfully.
    pub status: u8,
    /// Denotes the cumulative gas used by the tx execution.
    pub cumulative_gas_used: u64,
    /// Represents the 256-bytes bloom filter.
    pub bloom: Bloom,
    /// List of logs generated by the tx.
    pub logs: Vec<Log>,
}

impl Encodable for Receipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.status);
        s.append(&self.cumulative_gas_used);
        // Encode bloom filter using TinyRlp to reduce code size
        s.append(&TinyRlp(&self.bloom.0));
        // Use TinyRlp to encode logs to reduce code size
        s.append_list(&self.logs.iter().map(|log| TinyRlp(log)).collect::<Vec<_>>());
    }
}
