use crate::utils::read_env_var;
use once_cell::sync::Lazy;

pub static AGG_KECCAK_ROW: Lazy<usize> = Lazy::new(|| read_env_var("AGG_KECCAK_ROW", 50));
pub static AGG_VK_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("AGG_VK_FILENAME", "agg_vk.vkey".to_string()));
pub static CHUNK_PROTOCOL_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("CHUNK_PROTOCOL_FILENAME", "chunk.protocol".to_string()));
pub static CHUNK_VK_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("CHUNK_VK_FILENAME", "chunk_vk.vkey".to_string()));
pub static DEPLOYMENT_CODE_FILENAME: Lazy<String> =
    Lazy::new(|| read_env_var("DEPLOYMENT_CODE_FILENAME", "evm_verifier.bin".to_string()));
