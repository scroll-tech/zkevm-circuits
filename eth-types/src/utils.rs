//! Some handy helpers

use crate::geth_types::TxType;
use crate::{Address, SignableTransaction, Signature, TransactionRequest};
use revm_precompile::Precompiles;

mod codehash;
pub use codehash::*;

/// Check if address is a precompiled or not.
pub fn is_precompiled(address: &Address) -> bool {
    #[cfg(feature = "scroll")]
    let precompiles = Precompiles::bernoulli();
    #[cfg(not(feature = "scroll"))]
    let precompiles = Precompiles::berlin();
    precompiles.get(address).is_some()
}

pub trait TxRlpExt {
    fn rlp(&self) -> Vec<u8>;
    fn rlp_unsigned(&self) -> Vec<u8>;

    fn rlp_signed(&self, sig: &Signature) -> Vec<u8>;
}

impl TxRlpExt for crate::Transaction {
    fn rlp(&self) -> Vec<u8> {
        todo!()
    }

    fn rlp_unsigned(&self) -> Vec<u8> {
        let tx_type = TxType::get_tx_type(self);
        let mut tx_req = self.clone().into_request();
        match tx_type {
            TxType::Eip155 => {
                let sig_v = self.signature.unwrap_or_default().v.to::<u64>();
                tx_req.chain_id = Some(self.chain_id.unwrap_or_else(|| {
                    let recv_v = TxType::Eip155.get_recovery_id(sig_v) as u64;
                    (sig_v - recv_v - 35) / 2
                }));
            }
            TxType::PreEip155 => {
                tx_req.chain_id = None;
            }
            TxType::L1Msg => return vec![], // L1Msg is not signed
            _ => {}
        };

        // sanity check
        #[cfg(debug_assertions)]
        match tx_type {
            TxType::Eip155 | TxType::PreEip155 => {
                tx_req.complete_legacy().unwrap();
                assert_eq!(tx_req.preferred_type(), alloy::consensus::TxType::Legacy);
            }
            TxType::Eip1559 => {
                tx_req.complete_1559().unwrap();
                assert_eq!(tx_req.preferred_type(), alloy::consensus::TxType::Eip1559);
            }
            TxType::Eip2930 => {
                tx_req.complete_2930().unwrap();
                assert_eq!(tx_req.preferred_type(), alloy::consensus::TxType::Eip2930);
            }
            TxType::L1Msg => unreachable!("L1Msg is not signed"),
        }

        let tx = tx_req.build_typed_tx().unwrap();
        match tx_type {
            TxType::Eip155 | TxType::PreEip155 => tx.legacy().unwrap().encoded_for_signing(),
            TxType::Eip1559 => tx.eip1559().unwrap().encoded_for_signing(),
            TxType::Eip2930 => tx.eip2930().unwrap().encoded_for_signing(),
            TxType::L1Msg => unreachable!("L1Msg is not signed"),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::geth_types::TxType;

    /// (old) Get the type of transaction
    pub fn get_tx_type_ethers(tx: &ethers_core::types::Transaction) -> TxType {
        use ethers_core::types::U64;
        match tx.transaction_type {
            Some(x) if x == U64::from(1) => TxType::Eip2930,
            Some(x) if x == U64::from(2) => TxType::Eip1559,
            Some(x) if x == U64::from(0x7e) => TxType::L1Msg,
            _ => {
                if cfg!(feature = "scroll") {
                    if tx.v.is_zero() && tx.r.is_zero() && tx.s.is_zero() {
                        TxType::L1Msg
                    } else {
                        match tx.v.as_u64() {
                            0 | 1 | 27 | 28 => TxType::PreEip155,
                            _ => TxType::Eip155,
                        }
                    }
                } else {
                    match tx.v.as_u64() {
                        0 | 1 | 27 | 28 => TxType::PreEip155,
                        _ => TxType::Eip155,
                    }
                }
            }
        }
    }

    /// (old) Get the RLP bytes for signing
    pub fn get_rlp_unsigned_ethers(tx: &ethers_core::types::Transaction) -> Vec<u8> {
        use ethers_core::types::{
            transaction::eip2718::TypedTransaction, Eip1559TransactionRequest,
            Eip2930TransactionRequest, TransactionRequest,
        };
        let sig_v = tx.v;
        match get_tx_type_ethers(tx) {
            TxType::Eip155 => {
                let mut tx: TransactionRequest = tx.into();
                tx.chain_id = Some(tx.chain_id.unwrap_or_else(|| {
                    let recv_v = TxType::Eip155.get_recovery_id(sig_v.as_u64()) as u64;
                    (sig_v - recv_v - 35) / 2
                }));
                tx.rlp().to_vec()
            }
            TxType::PreEip155 => {
                let tx: TransactionRequest = tx.into();
                tx.rlp_unsigned().to_vec()
            }
            TxType::Eip1559 => {
                let tx: Eip1559TransactionRequest = tx.into();
                let typed_tx: TypedTransaction = tx.into();
                typed_tx.rlp().to_vec()
            }
            TxType::Eip2930 => {
                let tx: Eip2930TransactionRequest = tx.into();
                let typed_tx: TypedTransaction = tx.into();
                typed_tx.rlp().to_vec()
            }
            TxType::L1Msg => {
                // L1 msg does not have signature
                vec![]
            }
        }
    }
}
