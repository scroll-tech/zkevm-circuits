//! l2 predeployed contract helpers

// Copied from https://github.com/scroll-tech/go-ethereum/blob/8dc419a70b94f5ca185dcf818a48a3bd2eefc392/rollup/rcfg/config.go#L42

use eth_types::Address;

/// helper for L2MessageQueue contract
pub mod message_queue {
    use super::*;
    use eth_types::U256;
    use std::{str::FromStr, sync::LazyLock};

    /// address of L2MessageQueue predeploy
    pub static ADDRESS: LazyLock<Address> =
        LazyLock::new(|| Address::from_str("0x5300000000000000000000000000000000000000").unwrap());
    /// the slot of withdraw root in L2MessageQueue
    pub static WITHDRAW_TRIE_ROOT_SLOT: U256 = U256::zero();
}

/// Helper for L1GasPriceOracle contract
#[allow(missing_docs)]
pub mod l1_gas_price_oracle {
    use eth_types::{Address, U256};
    use std::{str::FromStr, sync::LazyLock};

    /// L1GasPriceOracle predeployed address
    pub static ADDRESS: LazyLock<Address> =
        LazyLock::new(|| Address::from_str("0x5300000000000000000000000000000000000002").unwrap());
    /// L1 base fee slot in L1GasPriceOracle
    pub static BASE_FEE_SLOT: LazyLock<U256> = LazyLock::new(|| U256::from(1));

    /// The following 2 slots will be depreciated after curie fork
    /// L1 overhead slot in L1GasPriceOracle
    pub static OVERHEAD_SLOT: LazyLock<U256> = LazyLock::new(|| U256::from(2));
    /// L1 scalar slot in L1GasPriceOracle
    pub static SCALAR_SLOT: LazyLock<U256> = LazyLock::new(|| U256::from(3));

    /// THe following 3 slots plus `BASE_FEE_SLOT` will be used for l1 fee after curie fork
    pub static L1_BLOB_BASEFEE_SLOT: LazyLock<U256> = LazyLock::new(|| U256::from(5));
    pub static COMMIT_SCALAR_SLOT: LazyLock<U256> = LazyLock::new(|| U256::from(6));
    pub static BLOB_SCALAR_SLOT: LazyLock<U256> = LazyLock::new(|| U256::from(7));
    pub static IS_CURIE_SLOT: LazyLock<U256> = LazyLock::new(|| U256::from(8));
    pub static INITIAL_COMMIT_SCALAR: LazyLock<U256> =
        LazyLock::new(|| U256::from(230759955285u64));
    pub static INITIAL_BLOB_SCALAR: LazyLock<U256> = LazyLock::new(|| U256::from(417565260));

    /// Bytecode before curie hardfork
    /// curl 127.0.0.1:8545 -X POST -H "Content-Type: application/json" --data
    /// '{"method":"eth_getCode","params":["0x5300000000000000000000000000000000000002","latest"],"
    /// id":1,"jsonrpc":"2.0"}'
    pub static V1_BYTECODE: LazyLock<Vec<u8>> =
        LazyLock::new(|| hex::decode(include_str!("./data/v1_l1_oracle_bytecode.txt")).unwrap());
    /// Bytecode after curie hardfork
    /// https://github.com/scroll-tech/go-ethereum/blob/8dc419a70b94f5ca185dcf818a48a3bd2eefc392/rollup/rcfg/config.go#L42
    pub static V2_BYTECODE: LazyLock<Vec<u8>> =
        LazyLock::new(|| hex::decode(include_str!("./data/v2_l1_oracle_bytecode.txt")).unwrap());
}
