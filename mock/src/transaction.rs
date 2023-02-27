//! Mock Transaction definition and builder related methods.

use super::{MOCK_ACCOUNTS, MOCK_CHAIN_ID, MOCK_GASPRICE};
use eth_types::word;
use eth_types::{
    geth_types::Transaction as GethTransaction, AccessList, Address, Bytes, Hash, Transaction,
    Word, U64,
};
use ethers_core::types::OtherFields;
use ethers_core::{
    rand::{CryptoRng, RngCore},
    types::TransactionRequest,
};
use ethers_signers::{LocalWallet, Signer};
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

lazy_static! {
    /// Collection of correctly hashed and signed Transactions which can be used to test circuits or opcodes that have to check integrity of the Tx itself.
    /// Some of the parameters of the Tx are hardcoded such as `nonce`, `value`, `gas_price` etc...
    pub static ref CORRECT_MOCK_TXS: Vec<MockTransaction> = {
        let mut rng = ChaCha20Rng::seed_from_u64(2u64);

        vec![
            MockTransaction::default()
                .transaction_idx(1u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(MOCK_ACCOUNTS[0])
                .nonce(word!("0x103"))
                .value(word!("0x3e8"))
                .gas_price(word!("0x4d2"))
                .input(vec![1, 2, 3, 4, 5, 0, 6, 7, 8, 9].into()) // call data gas cost of 0 is 4
                .build(),
            MockTransaction::default()
                .transaction_idx(2u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(MOCK_ACCOUNTS[1])
                .nonce(word!("0x104"))
                .value(word!("0x3e8"))
                .gas_price(word!("0x4d2"))
                .input(Bytes::from(b"hello"))
                .build(),
            MockTransaction::default()
                .transaction_idx(3u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(MOCK_ACCOUNTS[2])
                .nonce(word!("0x105"))
                .value(word!("0x3e8"))
                .gas_price(word!("0x4d2"))
                .input(Bytes::from(b"hello"))
                .build(),
            MockTransaction::default()
                .transaction_idx(4u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(MOCK_ACCOUNTS[3])
                .nonce(word!("0x106"))
                .value(word!("0x3e8"))
                .gas_price(word!("0x4d2"))
                .input(Bytes::from(b""))
                .build(),
            MockTransaction::default()
                .transaction_idx(5u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(MOCK_ACCOUNTS[4])
                .nonce(word!("0x0"))
                .value(word!("0x0"))
                .gas_price(word!("0x4d2"))
                .input(Bytes::from(b"hello"))
                .build(),
            MockTransaction::default()
                .transaction_idx(6u64)
                .from(AddrOrWallet::random(&mut rng))
                .to(AddrOrWallet::Addr(Address::zero()))
                .nonce(word!("0x0"))
                .value(word!("0x0"))
                .gas_price(word!("0x4d2"))
                .input(Bytes::from(b"hello"))
                .build(),
        ]
    };
}

#[derive(Debug, Clone)]
pub enum AddrOrWallet {
    Addr(Address),
    Wallet(LocalWallet),
}

impl Default for AddrOrWallet {
    fn default() -> Self {
        AddrOrWallet::Addr(Address::default())
    }
}

impl From<Address> for AddrOrWallet {
    fn from(addr: Address) -> Self {
        AddrOrWallet::Addr(addr)
    }
}

impl From<LocalWallet> for AddrOrWallet {
    fn from(wallet: LocalWallet) -> Self {
        AddrOrWallet::Wallet(wallet)
    }
}

impl AddrOrWallet {
    /// Generates a random Wallet from a random secpk256 keypair
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        AddrOrWallet::Wallet(LocalWallet::new(rng))
    }
}

impl AddrOrWallet {
    /// Returns the underlying address associated to the `AddrOrWallet` enum.
    pub fn address(&self) -> Address {
        match self {
            Self::Addr(addr) => *addr,
            Self::Wallet(wallet) => wallet.address(),
        }
    }

    /// Returns true if the enum variant of `self` corresponds to a
    /// [`LocalWallet`] structure and not simply and [`Address`].
    const fn is_wallet(&self) -> bool {
        matches!(self, Self::Wallet(_))
    }

    /// Returns the underlying wallet stored in the enum.
    /// # Panics
    /// This function will panic if the enum does not contain a [`LocalWallet`]
    /// and instead contains the [`Address`] variant.
    pub fn as_wallet(&self) -> LocalWallet {
        match self {
            Self::Wallet(wallet) => wallet.to_owned(),
            _ => panic!("Broken AddrOrWallet invariant"),
        }
    }
}

#[derive(Debug, Clone)]
/// Mock structure which represents a Transaction and can be used for tests.
/// It contains all the builder-pattern methods required to be able to specify
/// any of it's details.
pub struct MockTransaction {
    pub hash: Option<Hash>,
    pub nonce: Word,
    pub block_hash: Hash,
    pub block_number: U64,
    pub transaction_index: U64,
    pub from: AddrOrWallet,
    pub to: Option<AddrOrWallet>,
    pub value: Word,
    pub gas_price: Word,
    pub gas: Word,
    pub input: Bytes,
    pub v: Option<U64>,
    pub r: Option<Word>,
    pub s: Option<Word>,
    pub transaction_type: U64,
    pub access_list: AccessList,
    pub max_priority_fee_per_gas: Word,
    pub max_fee_per_gas: Word,
    pub chain_id: Word,
}

impl Default for MockTransaction {
    fn default() -> Self {
        MockTransaction {
            hash: None,
            nonce: Word::zero(),
            block_hash: Hash::zero(),
            block_number: U64::zero(),
            transaction_index: U64::zero(),
            from: AddrOrWallet::Addr(MOCK_ACCOUNTS[0]),
            to: None,
            value: Word::zero(),
            gas_price: *MOCK_GASPRICE,
            gas: Word::from(1_000_000u64),
            input: Bytes::default(),
            v: None,
            r: None,
            s: None,
            transaction_type: U64::zero(),
            access_list: AccessList::default(),
            max_priority_fee_per_gas: Word::zero(),
            max_fee_per_gas: Word::zero(),
            chain_id: *MOCK_CHAIN_ID,
        }
    }
}

impl From<MockTransaction> for Transaction {
    fn from(mock: MockTransaction) -> Self {
        Transaction {
            hash: mock.hash.unwrap_or_default(),
            nonce: mock.nonce,
            block_hash: Some(mock.block_hash),
            block_number: Some(mock.block_number),
            transaction_index: Some(mock.transaction_index),
            from: mock.from.address(),
            to: mock.to.map(|addr| addr.address()),
            value: mock.value,
            gas_price: Some(mock.gas_price),
            gas: mock.gas,
            input: mock.input,
            v: mock.v.unwrap_or_default(),
            r: mock.r.unwrap_or_default(),
            s: mock.s.unwrap_or_default(),
            transaction_type: Some(mock.transaction_type),
            access_list: Some(mock.access_list),
            max_priority_fee_per_gas: Some(mock.max_priority_fee_per_gas),
            max_fee_per_gas: Some(mock.max_fee_per_gas),
            chain_id: Some(mock.chain_id),
            other: OtherFields::default(),
        }
    }
}

impl From<MockTransaction> for GethTransaction {
    fn from(mock: MockTransaction) -> Self {
        GethTransaction::from(&Transaction::from(mock))
    }
}

impl MockTransaction {
    /// Tx Hash computed based on the fields of the Tx by
    /// default unless `Some(hash)` is specified on build process.
    pub fn hash(&mut self, hash: Hash) -> &mut Self {
        self.hash = Some(hash);
        self
    }

    /// Set nonce field for the MockTransaction.
    pub fn nonce(&mut self, nonce: Word) -> &mut Self {
        self.nonce = nonce;
        self
    }

    /// Set block_hash field for the MockTransaction.
    pub fn block_hash(&mut self, block_hash: Hash) -> &mut Self {
        self.block_hash = block_hash;
        self
    }

    /// Set block_number field for the MockTransaction.
    pub fn block_number(&mut self, block_number: u64) -> &mut Self {
        self.block_number = U64::from(block_number);
        self
    }

    /// Set transaction_idx field for the MockTransaction.
    pub fn transaction_idx(&mut self, transaction_idx: u64) -> &mut Self {
        self.transaction_index = U64::from(transaction_idx);
        self
    }

    /// Set from field for the MockTransaction.
    pub fn from<T: Into<AddrOrWallet>>(&mut self, from: T) -> &mut Self {
        self.from = from.into();
        self
    }

    /// Set to field for the MockTransaction.
    pub fn to<T: Into<AddrOrWallet>>(&mut self, to: T) -> &mut Self {
        self.to = Some(to.into());
        self
    }

    /// Set value field for the MockTransaction.
    pub fn value(&mut self, value: Word) -> &mut Self {
        self.value = value;
        self
    }

    /// Set gas_price field for the MockTransaction.
    pub fn gas_price(&mut self, gas_price: Word) -> &mut Self {
        self.gas_price = gas_price;
        self
    }

    /// Set gas field for the MockTransaction.
    pub fn gas(&mut self, gas: Word) -> &mut Self {
        self.gas = gas;
        self
    }

    /// Set input field for the MockTransaction.
    pub fn input(&mut self, input: Bytes) -> &mut Self {
        self.input = input;
        self
    }

    /// Set sig_data field for the MockTransaction.
    pub fn sig_data(&mut self, data: (u64, Word, Word)) -> &mut Self {
        self.v = Some(U64::from(data.0));
        self.r = Some(data.1);
        self.s = Some(data.2);
        self
    }

    /// Set transaction_type field for the MockTransaction.
    pub fn transaction_type(&mut self, transaction_type: u64) -> &mut Self {
        self.transaction_type = U64::from(transaction_type);
        self
    }

    /// Set access_list field for the MockTransaction.
    pub fn access_list(&mut self, access_list: AccessList) -> &mut Self {
        self.access_list = access_list;
        self
    }

    /// Set max_priority_fee_per_gas field for the MockTransaction.
    pub fn max_priority_fee_per_gas(&mut self, max_priority_fee_per_gas: Word) -> &mut Self {
        self.max_priority_fee_per_gas = max_priority_fee_per_gas;
        self
    }

    /// Set max_fee_per_gas field for the MockTransaction.
    pub fn max_fee_per_gas(&mut self, max_fee_per_gas: Word) -> &mut Self {
        self.max_fee_per_gas = max_fee_per_gas;
        self
    }

    /// Set chain_id field for the MockTransaction.
    pub fn chain_id(&mut self, chain_id: Word) -> &mut Self {
        self.chain_id = chain_id;
        self
    }

    /// Consumes the mutable ref to the MockTransaction returning the structure
    /// by value.
    pub fn build(&mut self) -> Self {
        let tx = TransactionRequest::new()
            .from(self.from.address())
            .to(self.to.clone().unwrap_or_default().address())
            .nonce(self.nonce)
            .value(self.value)
            .data(self.input.clone())
            .gas(self.gas)
            .gas_price(self.gas_price)
            .chain_id(self.chain_id.low_u64());

        match (self.v, self.r, self.s) {
            (None, None, None) => {
                // Compute sig params and set them in case we have a wallet as `from` attr.
                if self.from.is_wallet() && self.hash.is_none() {
                    let sig = self
                        .from
                        .as_wallet()
                        .with_chain_id(self.chain_id.low_u64())
                        .sign_transaction_sync(&tx.into());
                    // Set sig parameters
                    self.sig_data((sig.v, sig.r, sig.s));
                }
            }
            (Some(_), Some(_), Some(_)) => (),
            _ => panic!("Either all or none of the SigData params have to be set"),
        }

        // Compute tx hash in case is not already set
        if self.hash.is_none() {
            let tmp_tx = Transaction::from(self.to_owned());
            // FIXME: Note that tmp_tx does not have sigs if self.from.is_wallet() = false.
            //  This means tmp_tx.hash() is not correct.
            self.hash(tmp_tx.hash());
        }

        self.to_owned()
    }
}
