//! Mock Transaction definition and builder related methods.

use super::{MOCK_ACCOUNTS, MOCK_CHAIN_ID, MOCK_GASPRICE};
use eth_types::{AccessList, Address, Bytes, Hash, Transaction, Word, U64};

#[derive(Debug, Clone)]
/// Mock structure which represents a Transaction and can be used for tests.
/// It contains all the builder-pattern methods required to be able to specify
/// any of it's details.
pub struct MockTransaction {
    hash: Option<Hash>,
    nonce: Word,
    block_hash: Hash,
    block_number: U64,
    transaction_index: U64,
    from: Address,
    to: Option<Address>,
    value: Word,
    gas_price: Word,
    gas: Word,
    input: Bytes,
    v: U64,
    r: Word,
    s: Word,
    transaction_type: U64,
    access_list: AccessList,
    max_priority_fee_per_gas: Word,
    max_fee_per_gas: Word,
    chain_id: Word,
}

impl Default for MockTransaction {
    fn default() -> Self {
        MockTransaction {
            hash: Some(Hash::zero()),
            nonce: Word::zero(),
            block_hash: Hash::zero(),
            block_number: U64::zero(),
            transaction_index: U64::zero(),
            from: MOCK_ACCOUNTS[0],
            to: None,
            value: Word::zero(),
            gas_price: *MOCK_GASPRICE,
            gas: Word::from(1_000_000u64),
            input: Bytes::default(),
            v: U64::zero(),
            r: Word::zero(),
            s: Word::zero(),
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
            from: mock.from,
            to: mock.to,
            value: mock.value,
            gas_price: Some(mock.gas_price),
            gas: mock.gas,
            input: mock.input,
            v: mock.v,
            r: mock.r,
            s: mock.s,
            transaction_type: Some(mock.transaction_type),
            access_list: Some(mock.access_list),
            max_priority_fee_per_gas: Some(mock.max_priority_fee_per_gas),
            max_fee_per_gas: Some(mock.max_fee_per_gas),
            chain_id: Some(mock.chain_id),
        }
    }
}

impl MockTransaction {
    /// TODO: This should be computed based on the fields of the Tx by
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

    /// Set block_hash field for the MockBlock.
    pub fn block_hash(&mut self, block_hash: Hash) -> &mut Self {
        self.block_hash = block_hash;
        self
    }

    /// Set block_number field for the MockBlock.
    pub fn block_number(&mut self, block_number: u64) -> &mut Self {
        self.block_number = U64::from(block_number);
        self
    }

    /// Set transaction_idx field for the MockBlock.
    pub fn transaction_idx(&mut self, transaction_idx: u64) -> &mut Self {
        self.transaction_index = U64::from(transaction_idx);
        self
    }

    /// Set from field for the MockBlock.
    pub fn from(&mut self, from: Address) -> &mut Self {
        self.from = from;
        self
    }

    /// Set to field for the MockBlock.
    pub fn to(&mut self, to: Address) -> &mut Self {
        self.to = Some(to);
        self
    }

    /// Set value field for the MockBlock.
    pub fn value(&mut self, value: Word) -> &mut Self {
        self.value = value;
        self
    }

    /// Set gas_price field for the MockBlock.
    pub fn gas_price(&mut self, gas_price: Word) -> &mut Self {
        self.gas_price = gas_price;
        self
    }

    /// Set gas field for the MockBlock.
    pub fn gas(&mut self, gas: Word) -> &mut Self {
        self.gas = gas;
        self
    }

    /// Set input field for the MockBlock.
    pub fn input(&mut self, input: Bytes) -> &mut Self {
        self.input = input;
        self
    }

    /// Set sig_data field for the MockBlock.
    pub fn sig_data(&mut self, data: (u64, Word, Word)) -> &mut Self {
        self.v = U64::from(data.0);
        self.r = data.1;
        self.s = data.2;
        self
    }

    /// Set transaction_type field for the MockBlock.
    pub fn transaction_type(&mut self, transaction_type: u64) -> &mut Self {
        self.transaction_type = U64::from(transaction_type);
        self
    }

    /// Set access_list field for the MockBlock.
    pub fn access_list(&mut self, access_list: AccessList) -> &mut Self {
        self.access_list = access_list;
        self
    }

    /// Set max_priority_fee_per_gas field for the MockBlock.
    pub fn max_priority_fee_per_gas(&mut self, max_priority_fee_per_gas: Word) -> &mut Self {
        self.max_priority_fee_per_gas = max_priority_fee_per_gas;
        self
    }

    /// Set max_fee_per_gas field for the MockBlock.
    pub fn max_fee_per_gas(&mut self, max_fee_per_gas: Word) -> &mut Self {
        self.max_fee_per_gas = max_fee_per_gas;
        self
    }

    /// Set chain_id field for the MockBlock.
    pub fn chain_id(&mut self, chain_id: Word) -> &mut Self {
        self.chain_id = chain_id;
        self
    }

    /// Consumes the mutable ref to the MockBlock returning the structure by
    /// value.
    pub fn build(&mut self) -> Self {
        self.to_owned()
    }
}
