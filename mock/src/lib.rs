//! Mock types and functions to generate GethData used for tests

use eth_types::{address, Address, Word};
use lazy_static::lazy_static;
mod account;
mod block;
pub mod test_ctx;
mod transaction;

pub(crate) use account::MockAccount;
pub(crate) use block::MockBlock;
pub use test_ctx::TestContext;
pub(crate) use transaction::MockTransaction;

lazy_static! {
    /// Mock coinbase value
    pub static ref MOCK_COINBASE: Address =
        address!("0x00000000000000000000000000000000c014ba5e");
    /// Mock gasprice value
    pub static ref MOCK_GASPRICE: Word = Word::from(1u8);
    /// Mock chain ID value
    pub static ref MOCK_CHAIN_ID: Word = Word::from(1338u64);
    /// Mock accounts loaded with ETH to use for test cases.
    pub static ref MOCK_ACCOUNTS: Vec<Address> = vec![
        address!("0x000000000000000000000000000000000cafe111"),
        address!("0x000000000000000000000000000000000cafe222"),
        address!("0x000000000000000000000000000000000cafe333"),
        address!("0x000000000000000000000000000000000cafe444"),
        address!("0x000000000000000000000000000000000cafe555"),
    ];
}
