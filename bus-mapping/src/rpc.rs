//! Module which contains all the RPC calls that are needed at any point to
//! query a Geth node in order to get a Block, Tx or Trace info.

use crate::Error;
use eth_types::{
    Address, Block, Bytes, EIP1186ProofResponse, GethExecTrace, Hash, ResultGethExecTraces,
    Transaction, Word, H256, U64,
};
pub use ethers_core::types::BlockNumber;
use ethers_providers::JsonRpcClient;
use serde::Serialize;

use crate::util::CHECK_MEM_STRICT;

/// Serialize a type.
///
/// # Panics
///
/// If the type returns an error during serialization.
pub fn serialize<T: serde::Serialize>(t: &T) -> serde_json::Value {
    serde_json::to_value(t).expect("Types never fail to serialize.")
}

#[derive(Serialize)]
#[doc(hidden)]
pub(crate) struct GethLoggerConfig {
    /// enable memory capture
    #[serde(rename = "EnableMemory")]
    enable_memory: bool,
    /// disable stack capture
    #[serde(rename = "DisableStack")]
    disable_stack: bool,
    /// disable storage capture
    #[serde(rename = "DisableStorage")]
    disable_storage: bool,
    /// enable return data capture
    #[serde(rename = "EnableReturnData")]
    enable_return_data: bool,
}

impl Default for GethLoggerConfig {
    fn default() -> Self {
        Self {
            enable_memory: false,
            disable_stack: false,
            disable_storage: false,
            enable_return_data: true,
        }
    }
}

/// Placeholder structure designed to contain the methods that the BusMapping
/// needs in order to enable Geth queries.
pub struct GethClient<P: JsonRpcClient>(pub P);

impl<P: JsonRpcClient> GethClient<P> {
    /// Generates a new `GethClient` instance.
    pub fn new(provider: P) -> Self {
        Self(provider)
    }

    /// Calls `eth_coinbase` via JSON-RPC returning the coinbase of the network.
    pub async fn get_coinbase(&self) -> Result<Address, Error> {
        self.0
            .request("eth_coinbase", ())
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))
    }

    /// Calls `eth_chainId` via JSON-RPC returning the chain id of the network.
    pub async fn get_chain_id(&self) -> Result<u64, Error> {
        let net_id: U64 = self
            .0
            .request("eth_chainId", ())
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))?;
        Ok(net_id.as_u64())
    }

    /// Calls `eth_getBlockByHash` via JSON-RPC returning a [`Block`] returning
    /// all the block information including it's transaction's details.
    pub async fn get_block_by_hash(&self, hash: Hash) -> Result<Block<Transaction>, Error> {
        let hash = serialize(&hash);
        let flag = serialize(&true);
        self.0
            .request("eth_getBlockByHash", [hash, flag])
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))
    }

    /// Calls `eth_getBlockByNumber` via JSON-RPC returning a [`Block`]
    /// returning all the block information including it's transaction's
    /// details.
    pub async fn get_block_by_number(
        &self,
        block_num: BlockNumber,
    ) -> Result<Block<Transaction>, Error> {
        let num = serialize(&block_num);
        let flag = serialize(&true);
        self.0
            .request("eth_getBlockByNumber", [num, flag])
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))
    }
    /// ..
    pub async fn get_tx_by_hash(&self, hash: H256) -> Result<Transaction, Error> {
        let hash = serialize(&hash);
        let tx = self
            .0
            .request("eth_getTransactionByHash", [hash])
            .await
            .map_err(|e| Error::JSONRpcError(e.into()));
        println!("tx is {tx:#?}");
        tx
    }

    /// Calls `debug_traceBlockByHash` via JSON-RPC returning a
    /// [`Vec<GethExecTrace>`] with each GethTrace corresponding to 1
    /// transaction of the block.
    pub async fn trace_block_by_hash(&self, hash: Hash) -> Result<Vec<GethExecTrace>, Error> {
        let hash = serialize(&hash);
        let cfg = serialize(&GethLoggerConfig::default());
        let resp: ResultGethExecTraces = self
            .0
            .request("debug_traceBlockByHash", [hash, cfg])
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))?;
        Ok(resp.0.into_iter().map(|step| step.result).collect())
    }

    /// Calls `debug_traceBlockByNumber` via JSON-RPC returning a
    /// [`Vec<GethExecTrace>`] with each GethTrace corresponding to 1
    /// transaction of the block.
    pub async fn trace_block_by_number(
        &self,
        block_num: BlockNumber,
    ) -> Result<Vec<GethExecTrace>, Error> {
        let num = serialize(&block_num);
        let cfg = serialize(&GethLoggerConfig::default());
        let resp: ResultGethExecTraces = self
            .0
            .request("debug_traceBlockByNumber", [num, cfg])
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))?;
        Ok(resp.0.into_iter().map(|step| step.result).collect())
    }
    /// ..
    pub async fn trace_tx_by_hash(&self, hash: H256) -> Result<Vec<GethExecTrace>, Error> {
        let hash = serialize(&hash);
        let cfg = GethLoggerConfig {
            enable_memory: *CHECK_MEM_STRICT,
            ..Default::default()
        };
        let cfg = serialize(&cfg);
        let resp: GethExecTrace = self
            .0
            .request("debug_traceTransaction", [hash, cfg])
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))?;
        Ok(vec![resp])
    }

    /// Calls `eth_getCode` via JSON-RPC returning a contract code
    pub async fn get_code(
        &self,
        contract_address: Address,
        block_num: BlockNumber,
    ) -> Result<Vec<u8>, Error> {
        let address = serialize(&contract_address);
        let num = serialize(&block_num);
        let resp: Bytes = self
            .0
            .request("eth_getCode", [address, num])
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))?;
        Ok(resp.to_vec())
    }

    /// Calls `eth_getProof` via JSON-RPC returning a
    /// [`EIP1186ProofResponse`] returning the account and
    /// storage-values of the specified account including the Merkle-proof.
    pub async fn get_proof(
        &self,
        account: Address,
        keys: Vec<Word>,
        block_num: BlockNumber,
    ) -> Result<EIP1186ProofResponse, Error> {
        let account = serialize(&account);
        let keys = serialize(&keys);
        let num = serialize(&block_num);
        self.0
            .request("eth_getProof", [account, keys, num])
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))
    }

    /// Calls `miner_stop` via JSON-RPC, which makes the node stop mining
    /// blocks.  Useful for integration tests.
    pub async fn miner_stop(&self) -> Result<(), Error> {
        self.0
            .request("miner_stop", ())
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))
    }

    /// Calls `miner_start` via JSON-RPC, which makes the node start mining
    /// blocks.  Useful for integration tests.
    pub async fn miner_start(&self) -> Result<(), Error> {
        self.0
            .request("miner_start", [serialize(&1)])
            .await
            .map_err(|e| Error::JSONRpcError(e.into()))
    }
}

// Integration tests found in `integration-tests/tests/rpc.rs`.
