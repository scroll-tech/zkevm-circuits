use eth_types::l2_types::BlockTrace;
use halo2_proofs::halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};
use zkevm_circuits::evm_circuit::witness::Block;

pub type WitnessBlock = Block<Fr>;

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct BlockTraceJsonRpcResult {
    pub result: BlockTrace,
}

pub mod base64 {
    use base64::{decode, encode};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(data: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        String::serialize(&encode(data), s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}
