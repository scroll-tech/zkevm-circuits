use eth_types::l2_types::BlockTrace;
use halo2_proofs::halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};
use zkevm_circuits::evm_circuit::witness::Block;

pub type WitnessBlock = Block<Fr>;

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct BlockTraceJsonRpcResult {
    pub result: BlockTrace,
}
pub use eth_types::base64;
