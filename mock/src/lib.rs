//! Mock types and functions to generate GethData used for tests

use eth_types::{address, Address, Bytes, Word};
use ethers_signers::LocalWallet;
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
mod account;
mod block;
pub mod test_ctx;
mod transaction;

pub(crate) use account::MockAccount;
pub(crate) use block::MockBlock;
pub use test_ctx::TestContext;
pub use transaction::{AddrOrWallet, MockTransaction, CORRECT_MOCK_TXS};

lazy_static! {
    /// Mock 1 ETH
    pub static ref MOCK_1_ETH: Word = eth(1);
    /// Mock coinbase value
    pub static ref MOCK_COINBASE: Address =
        address!("0x00000000000000000000000000000000c014ba5e");
    /// Mock gasprice value
    pub static ref MOCK_GASPRICE: Word = Word::from(1u8);
    /// Mock BASEFEE value
    pub static ref MOCK_BASEFEE: Word = Word::zero();
     /// Mock GASLIMIT value
    pub static ref MOCK_GASLIMIT: Word = Word::from(0x2386f26fc10000u64);
    /// Mock chain ID value
    pub static ref MOCK_CHAIN_ID: Word = Word::from(1338u64);
    /// Mock DIFFICULTY value
    pub static ref MOCK_DIFFICULTY: Word = Word::from(0x200000u64);
    /// Mock accounts loaded with ETH to use for test cases.
    pub static ref MOCK_ACCOUNTS: Vec<Address> = vec![
        address!("0x000000000000000000000000000000000cafe111"),
        address!("0x000000000000000000000000000000000cafe222"),
        address!("0x000000000000000000000000000000000cafe333"),
        address!("0x000000000000000000000000000000000cafe444"),
        address!("0x000000000000000000000000000000000cafe555"),
    ];
    /// Mock EVM codes to use for test cases.
    pub static ref MOCK_CODES: Vec<Bytes> = vec![
        Bytes::from([0x60, 0x10, 0x00]), // PUSH1(0x10), STOP
        Bytes::from([0x60, 0x01, 0x60, 0x02, 0x01, 0x00]), // PUSH1(1), PUSH1(2), ADD, STOP
        Bytes::from([0x60, 0x01, 0x60, 0x02, 0x02, 0x00]), // PUSH1(1), PUSH1(2), MUL, STOP
        Bytes::from([0x60, 0x02, 0x60, 0x01, 0x03, 0x00]), // PUSH1(2), PUSH1(1), SUB, STOP
        Bytes::from([0x60, 0x09, 0x60, 0x03, 0x04, 0x00]), // PUSH1(9), PUSH1(3), DIV, STOP
    ];
    /// Mock wallets used to generate correctly signed and hashed Transactions.
    pub static ref MOCK_WALLETS: Vec<LocalWallet> = {
        let mut rng = ChaCha20Rng::seed_from_u64(2u64);
        vec![
            LocalWallet::new(&mut rng),
            LocalWallet::new(&mut rng),
            LocalWallet::new(&mut rng),
    ]
    };
}

/// Generate a [`Word`] which corresponds to a certain amount of ETH.
pub fn eth(x: u64) -> Word {
    Word::from(x) * Word::from(10u64.pow(18))
}

/// Express an amount of ETH in GWei.
pub fn gwei(x: u64) -> Word {
    Word::from(x) * Word::from(10u64.pow(9))
}
