use ethers_core::utils::rlp::Encodable;

use super::{SignedTransaction, Transaction};

#[derive(Clone, Debug)]
pub struct TxEip155(pub Transaction);

impl Encodable for TxEip155 {
    fn rlp_append(&self, s: &mut ethers_core::utils::rlp::RlpStream) {
        self.0.rlp_append(s)
    }
}

#[derive(Clone, Debug)]
pub struct SignedTxEip155(pub SignedTransaction);

impl Encodable for SignedTxEip155 {
    fn rlp_append(&self, s: &mut ethers_core::utils::rlp::RlpStream) {
        self.0.rlp_append(s)
    }
}
