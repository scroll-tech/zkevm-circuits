//! l2 predeployed contract helpers

// Copied from https://github.com/scroll-tech/go-ethereum/blob/8dc419a70b94f5ca185dcf818a48a3bd2eefc392/rollup/rcfg/config.go#L42

use crate::{address, Address, U256};

/// helper for L2MessageQueue contract
pub mod message_queue {
    use super::*;

    /// address of L2MessageQueue predeploy
    pub const ADDRESS: Address = address!("5300000000000000000000000000000000000000");
    /// the slot of withdraw root in L2MessageQueue
    pub const WITHDRAW_TRIE_ROOT_SLOT: U256 = U256::ZERO;
}

/// Helper for L1GasPriceOracle contract
#[allow(missing_docs)]
pub mod l1_gas_price_oracle {
    use super::*;

    use crate::{geth_types::Account, Bytes};
    use std::sync::LazyLock;

    /// L1GasPriceOracle predeployed address
    pub const ADDRESS: Address = address!("5300000000000000000000000000000000000002");
    /// L1 base fee slot in L1GasPriceOracle
    pub const BASE_FEE_SLOT: U256 = U256::from_limbs([1, 0, 0, 0]);

    /// The following 2 slots will be depreciated after curie fork
    /// L1 overhead slot in L1GasPriceOracle
    pub const OVERHEAD_SLOT: U256 = U256::from_limbs([2, 0, 0, 0]);
    /// L1 scalar slot in L1GasPriceOracle
    pub const SCALAR_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);

    /// THe following 3 slots plus `BASE_FEE_SLOT` will be used for l1 fee after curie fork
    /// L1 BlobBaseFee slot in L1GasPriceOracle after Curie fork
    pub const L1_BLOB_BASEFEE_SLOT: U256 = U256::from_limbs([5, 0, 0, 0]);
    /// L1 commitScalar slot in L1GasPriceOracle after Curie fork
    pub const COMMIT_SCALAR_SLOT: U256 = U256::from_limbs([6, 0, 0, 0]);
    /// L1 blob_scalar slot in L1GasPriceOracle after Curie fork
    pub const BLOB_SCALAR_SLOT: U256 = U256::from_limbs([7, 0, 0, 0]);
    pub const IS_CURIE_SLOT: U256 = U256::from_limbs([8, 0, 0, 0]);
    pub const INITIAL_COMMIT_SCALAR: U256 = U256::from_limbs([230759955285, 0, 0, 0]);
    pub const INITIAL_BLOB_SCALAR: U256 = U256::from_limbs([417565260, 0, 0, 0]);

    /// Bytecode before curie hardfork
    /// curl 127.0.0.1:8545 -X POST -H "Content-Type: application/json" --data
    /// '{"method":"eth_getCode","params":["0x5300000000000000000000000000000000000002","latest"],"
    /// id":1,"jsonrpc":"2.0"}'
    pub static V1_BYTECODE: LazyLock<Vec<u8>> = LazyLock::new(|| {
        hex::decode(include_str!("./data/v1_l1_oracle_bytecode.txt")).expect("decode v1 bytecode")
    });
    /// Bytecode after curie hardfork
    /// https://github.com/scroll-tech/go-ethereum/blob/9ec83a509ac7f6dd2d0beb054eb14c19f3e67a72/rollup/rcfg/config.go#L50
    pub static V2_BYTECODE: LazyLock<Vec<u8>> = LazyLock::new(|| {
        hex::decode(include_str!("./data/v2_l1_oracle_bytecode.txt")).expect("decode v2 bytecode")
    });

    /// Default contract state for testing
    pub fn default_contract_account() -> Account {
        const STORAGES: [(U256, U256); 4] = [
            (BASE_FEE_SLOT, U256::from_limbs([1, 0, 0, 0])),
            (L1_BLOB_BASEFEE_SLOT, U256::from_limbs([1, 0, 0, 0])),
            (COMMIT_SCALAR_SLOT, INITIAL_COMMIT_SCALAR),
            (BLOB_SCALAR_SLOT, INITIAL_BLOB_SCALAR),
        ];

        Account {
            address: ADDRESS,
            nonce: U256::ZERO,
            balance: U256::from_limbs([1, 0, 0, 0]),
            code: Bytes::new(),
            storage: std::collections::HashMap::from_iter(STORAGES),
        }
    }
}
