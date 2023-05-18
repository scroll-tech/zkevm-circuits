//! l2 predeployed contract helpers

use eth_types::Address;

/// helper for L2MessageQueue contract
pub mod message_queue {
    use super::*;
    use eth_types::U256;
    use once_cell::sync::Lazy;
    use std::str::FromStr;

    /// address of L2MessageQueue predeploy
    pub static ADDRESS: Lazy<Address> =
        Lazy::new(|| Address::from_str("0x5300000000000000000000000000000000000000").unwrap());
    /// the slot of withdraw root in L2MessageQueue
    pub static WITHDRAW_TRIE_ROOT_SLOT: Lazy<U256> = Lazy::new(U256::zero);
}
