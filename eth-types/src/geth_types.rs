//! Types needed for generating Ethereum traces

#[cfg(feature = "scroll")]
use crate::l2_types::BlockTrace;
use crate::{
    sign_types::{biguint_to_32bytes_le, ct_option_ok_or, recover_pk2, SignData, SECP256K1_Q},
    AccessList, Address, Block, Bytes, Error, GethExecTrace, Hash, SignableTransaction,
    TransactionRequest, TxKind, TxSignature, TypedTransaction, Word, H256,
};
use halo2curves::{group::ff::PrimeField, secp256k1::Fq};
use num::Integer;
use num_bigint::BigUint;
use serde::{Serialize, Serializer};
use serde_with::serde_as;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use strum_macros::EnumIter;

/// Tx type
#[derive(Default, Debug, Copy, Clone, EnumIter, Serialize, PartialEq, Eq)]
pub enum TxType {
    /// EIP 155 tx
    #[default]
    Eip155 = 0,
    /// Pre EIP 155 tx
    PreEip155,
    /// EIP 1559 tx
    Eip1559,
    /// EIP 2930 tx
    Eip2930,
    /// L1 Message tx
    L1Msg,
}

impl From<TxType> for usize {
    fn from(value: TxType) -> Self {
        value as usize
    }
}

impl From<TxType> for u64 {
    fn from(value: TxType) -> Self {
        value as u64
    }
}

impl TxType {
    /// If this type is L1Msg or not
    pub fn is_l1_msg(&self) -> bool {
        matches!(*self, Self::L1Msg)
    }

    /// If this type is PreEip155
    pub fn is_pre_eip155(&self) -> bool {
        matches!(*self, TxType::PreEip155)
    }

    /// If this type is EIP155 or not
    pub fn is_eip155(&self) -> bool {
        matches!(*self, TxType::Eip155)
    }

    /// If this type is Eip1559 or not
    pub fn is_eip1559(&self) -> bool {
        matches!(*self, TxType::Eip1559)
    }

    /// If this type is Eip2930 or not
    pub fn is_eip2930(&self) -> bool {
        matches!(*self, TxType::Eip2930)
    }

    /// Get the type of transaction
    pub fn get_tx_type(tx: &crate::Transaction) -> Self {
        // Transaction type:
        // - Some(3) for EIP-4844 transaction
        // - Some(2) for EIP-1559 transaction
        // - Some(1) for AccessList transaction
        // - None or Some(0) for Legacy
        match tx.transaction_type {
            Some(1) => Self::Eip2930,
            Some(2) => Self::Eip1559,
            Some(0x7e) => Self::L1Msg,
            None | Some(0) => {
                let sig = tx.signature.unwrap_or_default();
                let v = sig.v.to::<u64>();
                if cfg!(feature = "scroll") {
                    if v == 0 && sig.r.is_zero() && sig.s.is_zero() {
                        Self::L1Msg
                    } else {
                        match v {
                            0 | 1 | 27 | 28 => Self::PreEip155,
                            _ => Self::Eip155,
                        }
                    }
                } else {
                    match v {
                        0 | 1 | 27 | 28 => Self::PreEip155,
                        _ => Self::Eip155,
                    }
                }
            }
            Some(x) => panic!("Unknown transaction type: {}", x), // panics on 4844
        }
    }

    /// Return the recovery id of signature for recovering the signing pk
    pub fn get_recovery_id(&self, v: u64) -> u8 {
        let recovery_id = match *self {
            TxType::Eip155 => (v + 1) % 2,
            TxType::PreEip155 => {
                assert!(v == 0x1b || v == 0x1c, "v: {v}");
                v - 27
            }
            TxType::Eip1559 => {
                assert!(v <= 1);
                v
            }
            TxType::Eip2930 => {
                assert!(v <= 1);
                v
            }
            TxType::L1Msg => {
                unreachable!("L1 msg does not have signature")
            }
        };

        recovery_id as u8
    }
}

/// Definition of all of the data related to an account.
#[serde_as]
#[derive(PartialEq, Eq, Debug, Default, Clone, Serialize)]
pub struct Account {
    /// Address
    pub address: Address,
    /// nonce
    pub nonce: Word,
    /// Balance
    pub balance: Word,
    /// EVM Code
    pub code: Bytes,
    /// Storage
    #[serde(serialize_with = "serde_account_storage")]
    pub storage: HashMap<Word, Word>,
}

impl Account {
    /// Return if account is empty or not.
    pub fn is_empty(&self) -> bool {
        self.nonce.is_zero()
            && self.balance.is_zero()
            && self.code.is_empty()
            && self.storage.is_empty()
    }
}

fn serde_account_storage<S: Serializer>(
    to_serialize: &HashMap<Word, Word>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    to_serialize
        .iter()
        .map(|(k, v)| (Hash::from(k.to_be_bytes()), Hash::from(v.to_be_bytes())))
        .collect::<HashMap<_, _>>()
        .serialize(serializer)
}

/// Definition of all of the constants related to an Ethereum block and
/// chain to be used as setup for the external tracer.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct BlockConstants {
    /// coinbase
    pub coinbase: Address,
    /// time
    pub timestamp: Word,
    /// number
    pub number: u64,
    /// difficulty
    pub difficulty: Word,
    /// gas limit
    pub gas_limit: Word,
    /// base fee
    pub base_fee: Word,
}

impl<TX> TryFrom<&Block<TX>> for BlockConstants {
    type Error = Error;

    fn try_from(block: &Block<TX>) -> Result<Self, Self::Error> {
        let header = &block.header;
        Ok(Self {
            coinbase: header.miner,
            timestamp: Word::from(header.timestamp),
            number: header.number.ok_or(Error::IncompleteBlock)?,
            difficulty: header.difficulty,
            gas_limit: Word::from(header.gas_limit),
            base_fee: header
                .base_fee_per_gas
                .map(Word::from)
                .ok_or(Error::IncompleteBlock)?,
        })
    }
}

impl BlockConstants {
    /// Generates a new `BlockConstants` instance from it's fields.
    pub fn new(
        coinbase: Address,
        timestamp: Word,
        number: u64,
        difficulty: Word,
        gas_limit: Word,
        base_fee: Word,
    ) -> BlockConstants {
        BlockConstants {
            coinbase,
            timestamp,
            number,
            difficulty,
            gas_limit,
            base_fee,
        }
    }
}

/// Definition of all of the constants related to an Ethereum transaction.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Transaction {
    /// Tx type
    pub tx_type: TxType,
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Transaction nonce
    pub nonce: Word,
    /// Gas Limit / Supplied gas
    pub gas_limit: Word,
    /// Transferred value
    pub value: Word,
    /// Gas Price
    pub gas_price: Option<Word>,
    /// Gas fee cap
    pub gas_fee_cap: Option<Word>,
    /// Gas tip cap
    pub gas_tip_cap: Option<Word>,
    /// The compiled code of a contract OR the first 4 bytes of the hash of the
    /// invoked method signature and encoded parameters. For details see
    /// Ethereum Contract ABI
    pub call_data: Bytes,
    /// Access list
    pub access_list: Option<AccessList>,

    /// "v" value of the transaction signature
    pub v: u64,
    /// "r" value of the transaction signature
    pub r: Word,
    /// "s" value of the transaction signature
    pub s: Word,

    /// RLP bytes
    pub rlp_bytes: Vec<u8>,
    /// RLP unsigned bytes
    pub rlp_unsigned_bytes: Vec<u8>,
    // TODO: add rlp_signed_bytes as well ?
    /// Transaction hash
    pub hash: H256,
}

impl From<&Transaction> for crate::Transaction {
    fn from(tx: &Transaction) -> crate::Transaction {
        crate::Transaction {
            from: tx.from,
            to: tx.to,
            nonce: tx.nonce.to(),
            gas: tx.gas_limit.to(),
            value: tx.value,
            gas_price: tx.gas_price.map(|g| g.to()),
            max_priority_fee_per_gas: tx.gas_tip_cap.map(|g| g.to()),
            max_fee_per_gas: tx.gas_fee_cap.map(|g| g.to()),
            input: tx.call_data.clone(),
            access_list: tx.access_list.clone(),
            signature: Some(TxSignature {
                v: Word::from(tx.v),
                r: tx.r,
                s: tx.s,
                ..Default::default()
            }),
            hash: tx.hash,
            ..Default::default()
        }
    }
}

impl From<&crate::Transaction> for Transaction {
    fn from(tx: &crate::Transaction) -> Transaction {
        let signature = tx.signature.unwrap_or_default();
        Transaction {
            tx_type: TxType::get_tx_type(tx),
            from: tx.from,
            to: tx.to,
            nonce: Word::from(tx.nonce),
            gas_limit: Word::from(tx.gas),
            value: tx.value,
            gas_price: tx.gas_price.map(Word::from),
            gas_tip_cap: tx.max_priority_fee_per_gas.map(Word::from),
            gas_fee_cap: tx.max_fee_per_gas.map(Word::from),
            call_data: tx.input.clone(),
            access_list: tx.access_list.clone(),
            v: signature.v.to(),
            r: signature.r,
            s: signature.s,
            rlp_bytes: tx.rlp().to_vec(),
            rlp_unsigned_bytes: get_rlp_unsigned(tx),
            hash: tx.hash,
        }
    }
}

impl From<&Transaction> for TransactionRequest {
    fn from(tx: &Transaction) -> TransactionRequest {
        TransactionRequest {
            from: Some(tx.from),
            to: tx.to.map(TxKind::Call),
            gas: Some(tx.gas_limit.to()),
            gas_price: tx.gas_price.map(|g| g.to()),
            value: Some(tx.value),
            data: Some(tx.call_data.clone()),
            nonce: Some(tx.nonce.to()),
            ..Default::default()
        }
    }
}

impl Transaction {
    /// Return the SignData associated with this Transaction.
    pub fn sign_data(&self) -> Result<SignData, Error> {
        let sig_r_le = self.r.to_le_bytes();
        let sig_s_le = self.s.to_le_bytes();
        let sig_r = ct_option_ok_or(Fq::from_repr(sig_r_le), Error::Signature)?;
        let sig_s = ct_option_ok_or(Fq::from_repr(sig_s_le), Error::Signature)?;
        let msg = self.rlp_unsigned_bytes.clone().into();
        let msg_hash: [u8; 32] = Keccak256::digest(&msg)
            .as_slice()
            .to_vec()
            .try_into()
            .expect("hash length isn't 32 bytes");
        let v = self.tx_type.get_recovery_id(self.v);
        let pk = recover_pk2(v, &self.r, &self.s, &msg_hash)?;
        // msg_hash = msg_hash % q
        let msg_hash = BigUint::from_bytes_be(msg_hash.as_slice());
        let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
        let msg_hash_le = biguint_to_32bytes_le(msg_hash);
        let msg_hash = ct_option_ok_or(Fq::from_repr(msg_hash_le), Error::Signature)?;
        Ok(SignData {
            signature: (sig_r, sig_s, v),
            pk,
            msg,
            msg_hash,
        })
    }
}

/// GethData is a type that contains all the information of a Ethereum block
#[derive(Default, Debug, Clone)]
pub struct GethData {
    /// chain id
    pub chain_id: u64,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the latest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// Block from geth
    pub eth_block: Block<crate::Transaction>,
    /// Execution Trace from geth
    pub geth_traces: Vec<GethExecTrace>,
    /// Accounts
    pub accounts: Vec<Account>,
    /// block trace
    #[cfg(feature = "scroll")]
    pub block_trace: BlockTrace,
}
/*
impl GethData {
    /// Signs transactions with selected wallets
    pub fn sign(&mut self, wallets: &HashMap<Address, LocalWallet>) {
        for tx in self.eth_block.transactions.iter_mut() {
            let wallet = wallets.get(&tx.from).unwrap();
            assert_eq!(wallet.chain_id(), self.chain_id);
            let geth_tx: Transaction = (&*tx).into();
            let req: TransactionRequest = (&geth_tx).into();
            let sig = wallet.sign_transaction_sync(&req.chain_id(self.chain_id).into());
            tx.v = U64::from(sig.v);
            tx.r = sig.r;
            tx.s = sig.s;
            // The previous tx.hash is calculated without signature.
            // Therefore we need to update tx.hash.
            tx.hash = tx.hash();
        }
    }
}
*/

/// Returns the number of addresses and the cumulative number of storage keys in
/// the entire access list.
pub fn access_list_size(access_list: &Option<AccessList>) -> (u64, u64) {
    access_list.as_ref().map_or_else(
        || (0, 0),
        |list| {
            (
                list.0.len() as u64,
                list.0
                    .iter()
                    .fold(0, |acc, item| acc + item.storage_keys.len()) as u64,
            )
        },
    )
}
