//! Types needed for generating Ethereum traces

use crate::{
    sign_types::{biguint_to_32bytes_le, ct_option_ok_or, recover_pk, SignData, SECP256K1_Q},
    AccessList, Address, Block, Bytes, Error, GethExecTrace, Hash, ToBigEndian, ToLittleEndian,
    Word, U64,
};
use ethers_core::types::{TransactionRequest, H256};
use ethers_signers::{LocalWallet, Signer};
use halo2_proofs::halo2curves::{group::ff::PrimeField, secp256k1};
use num::Integer;
use num_bigint::BigUint;
use serde::{Serialize, Serializer};
use serde_with::serde_as;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

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
    pub number: U64,
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
        Ok(Self {
            coinbase: block.author.ok_or(Error::IncompleteBlock)?,
            timestamp: block.timestamp,
            number: block.number.ok_or(Error::IncompleteBlock)?,
            difficulty: block.difficulty,
            gas_limit: block.gas_limit,
            base_fee: block.base_fee_per_gas.ok_or(Error::IncompleteBlock)?,
        })
    }
}

impl BlockConstants {
    /// Generates a new `BlockConstants` instance from it's fields.
    pub fn new(
        coinbase: Address,
        timestamp: Word,
        number: U64,
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
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Transaction nonce
    pub nonce: Word,
    /// Gas Limit / Supplied gas
    pub gas_limit: Word,
    /// Transfered value
    pub value: Word,
    /// Gas Price
    pub gas_price: Word,
    /// Gas fee cap
    pub gas_fee_cap: Word,
    /// Gas tip cap
    pub gas_tip_cap: Word,
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

    /// Transaction hash
    pub hash: H256,
}

impl From<&Transaction> for crate::Transaction {
    fn from(tx: &Transaction) -> crate::Transaction {
        crate::Transaction {
            from: tx.from,
            to: tx.to,
            nonce: tx.nonce,
            gas: tx.gas_limit,
            value: tx.value,
            gas_price: Some(tx.gas_price),
            max_priority_fee_per_gas: Some(tx.gas_fee_cap),
            max_fee_per_gas: Some(tx.gas_tip_cap),
            input: tx.call_data.clone(),
            access_list: tx.access_list.clone(),
            v: tx.v.into(),
            r: tx.r,
            s: tx.s,
            hash: tx.hash,
            ..Default::default()
        }
    }
}

impl From<&crate::Transaction> for Transaction {
    fn from(tx: &crate::Transaction) -> Transaction {
        Transaction {
            from: tx.from,
            to: tx.to,
            nonce: tx.nonce,
            gas_limit: tx.gas,
            value: tx.value,
            gas_price: tx.gas_price.unwrap_or_default(),
            gas_fee_cap: tx.max_priority_fee_per_gas.unwrap_or_default(),
            gas_tip_cap: tx.max_fee_per_gas.unwrap_or_default(),
            call_data: tx.input.clone(),
            access_list: tx.access_list.clone(),
            v: tx.v.as_u64(),
            r: tx.r,
            s: tx.s,
            hash: tx.hash,
        }
    }
}

impl From<&Transaction> for TransactionRequest {
    fn from(tx: &Transaction) -> TransactionRequest {
        TransactionRequest::new()
            .from(tx.from)
            .to(tx.to.unwrap())
            .nonce(tx.nonce)
            .value(tx.value)
            .data(tx.call_data.clone())
            .gas(tx.gas_limit)
            .gas_price(tx.gas_price)
    }
}

impl Transaction {
    /// Return the SignData associated with this Transaction.
    pub fn sign_data(&self, chain_id: u64) -> Result<SignData, Error> {
        let sig_r_le = self.r.to_le_bytes();
        let sig_s_le = self.s.to_le_bytes();
        let sig_r = ct_option_ok_or(
            secp256k1::Fq::from_repr(sig_r_le),
            Error::Signature(libsecp256k1::Error::InvalidSignature),
        )?;
        let sig_s = ct_option_ok_or(
            secp256k1::Fq::from_repr(sig_s_le),
            Error::Signature(libsecp256k1::Error::InvalidSignature),
        )?;
        // msg = rlp([nonce, gasPrice, gas, to, value, data, chain_id, 0, 0])
        let req: TransactionRequest = self.into();
        let msg = req.chain_id(chain_id).rlp();
        let msg_hash: [u8; 32] = Keccak256::digest(&msg)
            .as_slice()
            .to_vec()
            .try_into()
            .expect("hash length isn't 32 bytes");
        let v = ((self.v + 1) % 2) as u8;
        let pk = recover_pk(v, &self.r, &self.s, &msg_hash)?;
        // msg_hash = msg_hash % q
        let msg_hash = BigUint::from_bytes_be(msg_hash.as_slice());
        let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
        let msg_hash_le = biguint_to_32bytes_le(msg_hash);
        let msg_hash = ct_option_ok_or(
            secp256k1::Fq::from_repr(msg_hash_le),
            libsecp256k1::Error::InvalidMessage,
        )?;
        Ok(SignData {
            signature: (sig_r, sig_s),
            pk,
            msg,
            msg_hash,
        })
    }
}

/// GethData is a type that contains all the information of a Ethereum block
#[derive(Debug, Clone)]
pub struct GethData {
    /// chain id
    pub chain_id: Word,
    /// history hashes contains most recent 256 block hashes in history, where
    /// the lastest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// Block from geth
    pub eth_block: Block<crate::Transaction>,
    /// Execution Trace from geth
    pub geth_traces: Vec<GethExecTrace>,
    /// Accounts
    pub accounts: Vec<Account>,
}

impl GethData {
    /// Signs transactions with selected wallets
    pub fn sign(&mut self, wallets: &HashMap<Address, LocalWallet>) {
        for tx in self.eth_block.transactions.iter_mut() {
            let wallet = wallets.get(&tx.from).unwrap();
            assert_eq!(Word::from(wallet.chain_id()), self.chain_id);
            let geth_tx: Transaction = (&*tx).into();
            let req: TransactionRequest = (&geth_tx).into();
            let sig = wallet.sign_transaction_sync(&req.chain_id(self.chain_id.as_u64()).into());
            tx.v = U64::from(sig.v);
            tx.r = sig.r;
            tx.s = sig.s;
            // The previous tx.hash is calculated without signature.
            // Therefore we need to update tx.hash.
            tx.hash = tx.hash();
        }
    }
}
