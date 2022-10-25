//! Mock Block definition and builder related methods.

use crate::{MockTransaction, MOCK_CHAIN_ID};
use eth_types::{Address, Block, Bytes, Hash, Transaction, Word, H64, U64};
use ethers_core::types::Bloom;
use ethers_core::types::OtherFields;

#[derive(Clone, Debug)]
/// Mock structure which represents an Ethereum Block and can be used for tests.
/// It contains all the builder-pattern methods required to be able to specify
/// any of it's details.
pub struct MockBlock {
    hash: Option<Hash>,
    parent_hash: Hash,
    uncles_hash: Hash,
    author: Address,
    state_root: Hash,
    transactions_root: Hash,
    receipts_root: Hash,
    number: U64,
    gas_used: Word,
    gas_limit: Word,
    base_fee_per_gas: Word,
    extra_data: Bytes,
    logs_bloom: Option<Bloom>,
    timestamp: Word,
    difficulty: Word,
    total_difficulty: Word,
    seal_fields: Vec<Bytes>,
    uncles: Vec<Hash>,
    pub(crate) transactions: Vec<MockTransaction>,
    size: Word,
    mix_hash: Hash,
    nonce: H64,
    // This field is handled here as we assume that all block txs have the same ChainId.
    // Also, the field is stored in the block_table since we don't have a chain_config
    // structure/table.
    pub(crate) chain_id: Word,
}

impl Default for MockBlock {
    fn default() -> Self {
        MockBlock {
            hash: Some(Hash::zero()),
            parent_hash: Hash::zero(),
            uncles_hash: Hash::zero(),
            author: Address::zero(),
            state_root: Hash::zero(),
            transactions_root: Hash::zero(),
            receipts_root: Hash::zero(),
            number: U64([0u64]),
            gas_used: Word::zero(),
            gas_limit: Word::from(0x2386f26fc10000u64),
            base_fee_per_gas: Word::zero(),
            extra_data: Bytes::default(),
            logs_bloom: None,
            timestamp: Word::from(123456789u64),
            difficulty: Word::from(0x200000u64),
            total_difficulty: Word::zero(),
            seal_fields: Vec::new(),
            uncles: Vec::new(),
            transactions: Vec::new(),
            size: Word::zero(),
            mix_hash: Hash::zero(),
            nonce: H64::zero(),
            chain_id: *MOCK_CHAIN_ID,
        }
    }
}

impl From<MockBlock> for Block<Transaction> {
    fn from(mut mock: MockBlock) -> Self {
        Block {
            hash: mock.hash.or_else(|| Some(Hash::default())),
            parent_hash: mock.parent_hash,
            uncles_hash: mock.uncles_hash,
            author: Some(mock.author),
            state_root: mock.state_root,
            transactions_root: mock.transactions_root,
            receipts_root: mock.receipts_root,
            number: Some(mock.number),
            gas_used: mock.gas_used,
            gas_limit: mock.gas_limit,
            extra_data: mock.extra_data,
            logs_bloom: mock.logs_bloom,
            timestamp: mock.timestamp,
            difficulty: mock.difficulty,
            total_difficulty: Some(mock.total_difficulty),
            seal_fields: mock.seal_fields,
            uncles: mock.uncles,
            transactions: mock
                .transactions
                .iter_mut()
                .map(|mock_tx| {
                    (mock_tx
                        .chain_id(mock.chain_id)
                        .block_number(mock.number.as_u64())
                        .to_owned())
                    .into()
                })
                .collect::<Vec<Transaction>>(),
            size: Some(mock.size),
            mix_hash: Some(mock.mix_hash),
            nonce: Some(mock.nonce),
            base_fee_per_gas: Some(mock.base_fee_per_gas),
            other: OtherFields::default(),
        }
    }
}

impl From<MockBlock> for Block<()> {
    fn from(mock: MockBlock) -> Self {
        Block {
            hash: mock.hash.or_else(|| Some(Hash::default())),
            parent_hash: mock.parent_hash,
            uncles_hash: mock.uncles_hash,
            author: Some(mock.author),
            state_root: mock.state_root,
            transactions_root: mock.transactions_root,
            receipts_root: mock.receipts_root,
            number: Some(mock.number),
            gas_used: mock.gas_used,
            gas_limit: mock.gas_limit,
            extra_data: mock.extra_data,
            logs_bloom: mock.logs_bloom,
            timestamp: mock.timestamp,
            difficulty: mock.difficulty,
            total_difficulty: Some(mock.total_difficulty),
            seal_fields: mock.seal_fields,
            uncles: mock.uncles,
            transactions: vec![],
            size: Some(mock.size),
            mix_hash: Some(mock.mix_hash),
            nonce: Some(mock.nonce),
            base_fee_per_gas: Some(mock.base_fee_per_gas),
            other: OtherFields::default(),
        }
    }
}

impl MockBlock {
    /// TODO: This should be computed based on the fields of the block by
    /// default unless `Some(hash)` is specified on build process.
    pub fn hash(&mut self, hash: Hash) -> &mut Self {
        self.hash = Some(hash);
        self
    }

    /// Set parent_hash field for the MockBlock.
    pub fn parent_hash(&mut self, parent_hash: Hash) -> &mut Self {
        self.parent_hash = parent_hash;
        self
    }

    /// Set uncles_hash field for the MockBlock.
    pub fn uncles_hash(&mut self, uncles_hash: Hash) -> &mut Self {
        self.uncles_hash = uncles_hash;
        self
    }

    /// Set author field for the MockBlock.
    pub fn author(&mut self, author: Address) -> &mut Self {
        self.author = author;
        self
    }

    /// Set state_root field for the MockBlock.
    pub fn state_root(&mut self, state_root: Hash) -> &mut Self {
        self.state_root = state_root;
        self
    }

    /// Set transactions_root field for the MockBlock.
    pub fn transactions_root(&mut self, transactions_root: Hash) -> &mut Self {
        self.transactions_root = transactions_root;
        self
    }

    /// Set receipts_root field for the MockBlock.
    pub fn receipts_root(&mut self, receipts_root: Hash) -> &mut Self {
        self.receipts_root = receipts_root;
        self
    }

    /// Set number field for the MockBlock.
    pub fn number(&mut self, number: u64) -> &mut Self {
        self.number = U64::from(number);
        self
    }

    /// Set gas_used field for the MockBlock.
    pub fn gas_used(&mut self, gas_used: Word) -> &mut Self {
        self.gas_used = gas_used;
        self
    }

    /// Set gas_limit field for the MockBlock.
    pub fn gas_limit(&mut self, gas_limit: Word) -> &mut Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Set base_fee_per_gas field for the MockBlock.
    pub fn base_fee_per_gas(&mut self, base_fee_per_gas: Word) -> &mut Self {
        self.base_fee_per_gas = base_fee_per_gas;
        self
    }

    /// Set extra_data field for the MockBlock.
    pub fn extra_data(&mut self, extra_data: Bytes) -> &mut Self {
        self.extra_data = extra_data;
        self
    }

    /// Set logs_bloom field for the MockBlock.
    pub fn logs_bloom(&mut self, logs_bloom: Bloom) -> &mut Self {
        self.logs_bloom = Some(logs_bloom);
        self
    }

    /// Set timestamp field for the MockBlock.
    pub fn timestamp(&mut self, timestamp: Word) -> &mut Self {
        self.timestamp = timestamp;
        self
    }

    /// Set difficulty field for the MockBlock.
    pub fn difficulty(&mut self, difficulty: Word) -> &mut Self {
        self.difficulty = difficulty;
        self
    }

    /// Set total_difficulty field for the MockBlock.
    pub fn total_difficulty(&mut self, total_difficulty: Word) -> &mut Self {
        self.total_difficulty = total_difficulty;
        self
    }

    /// Set seal_fields field for the MockBlock.
    pub fn seal_fields(&mut self, seal_fields: Vec<Bytes>) -> &mut Self {
        self.seal_fields = seal_fields;
        self
    }

    /// Set uncles field for the MockBlock.
    pub fn uncles(&mut self, uncles: Vec<Hash>) -> &mut Self {
        self.uncles = uncles;
        self
    }

    /// Set transactions field for the MockBlock.
    pub fn transactions<I: IntoIterator<Item = MockTransaction>>(
        &mut self,
        transactions: I,
    ) -> &mut Self {
        self.transactions.extend(transactions);
        self
    }

    /// Set size field for the MockBlock.
    pub fn size(&mut self, size: Word) -> &mut Self {
        self.size = size;
        self
    }

    /// Set mix_hash field for the MockBlock.
    pub fn mix_hash(&mut self, mix_hash: Hash) -> &mut Self {
        self.mix_hash = mix_hash;
        self
    }

    /// Set nonce field for the MockBlock.
    pub fn nonce(&mut self, nonce: H64) -> &mut Self {
        self.nonce = nonce;
        self
    }

    /// Set chain_id field for the MockBlock.
    pub fn chain_id(&mut self, chain_id: Word) -> &mut Self {
        self.chain_id = chain_id;
        self
    }

    /// Finalizes the current MockBlock under construction returning a new
    /// instance to it.
    pub fn build(&mut self) -> Self {
        self.to_owned()
    }
}
