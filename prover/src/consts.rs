use crate::utils::read_env_var;
use std::sync::LazyLock;

pub static AGG_KECCAK_ROW: LazyLock<usize> = LazyLock::new(|| read_env_var("AGG_KECCAK_ROW", 50));
pub static AGG_VK_FILENAME: LazyLock<String> =
    LazyLock::new(|| read_env_var("AGG_VK_FILENAME", "agg_vk.vkey".to_string()));
pub static CHUNK_PROTOCOL_FILENAME: LazyLock<String> =
    LazyLock::new(|| read_env_var("CHUNK_PROTOCOL_FILENAME", "chunk.protocol".to_string()));
pub static CHUNK_VK_FILENAME: LazyLock<String> =
    LazyLock::new(|| read_env_var("CHUNK_VK_FILENAME", "chunk_vk.vkey".to_string()));
pub static DEPLOYMENT_CODE_FILENAME: LazyLock<String> =
    LazyLock::new(|| read_env_var("DEPLOYMENT_CODE_FILENAME", "evm_verifier.bin".to_string()));
