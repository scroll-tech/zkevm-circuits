use crate::utils::read_env_var;
use std::sync::LazyLock;

// TODO: is it a good design to use LazyLock? Why not read env var each time?

pub fn agg_vk_filename() -> String {
    read_env_var("AGG_VK_FILENAME", "agg_vk.vkey".to_string())
}
pub fn chunk_vk_filename() -> String {
    read_env_var("CHUNK_VK_FILENAME", "chunk_vk.vkey".to_string())
}

// For our k=21 agg circuit, 12 means it can include 2**21 / (12 * 25) * 136.0 = 0.95M bytes
pub static AGG_KECCAK_ROW: LazyLock<usize> = LazyLock::new(|| read_env_var("AGG_KECCAK_ROW", 12));
pub static AGG_VK_FILENAME: LazyLock<String> = LazyLock::new(agg_vk_filename);
pub static CHUNK_PROTOCOL_FILENAME: LazyLock<String> =
    LazyLock::new(|| read_env_var("CHUNK_PROTOCOL_FILENAME", "chunk.protocol".to_string()));
pub static CHUNK_VK_FILENAME: LazyLock<String> = LazyLock::new(chunk_vk_filename);
pub static DEPLOYMENT_CODE_FILENAME: LazyLock<String> =
    LazyLock::new(|| read_env_var("DEPLOYMENT_CODE_FILENAME", "evm_verifier.bin".to_string()));
