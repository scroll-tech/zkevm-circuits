use crate::utils::read_env_var;
use std::sync::LazyLock;

// TODO: is it a good design to use LazyLock? Why not read env var each time?

pub fn bundle_vk_filename() -> String {
    read_env_var("BUNDLE_VK_FILENAME", "bundle_vk.vkey".to_string())
}
pub fn batch_vk_filename() -> String {
    read_env_var("BATCH_VK_FILENAME", "batch_vk.vkey".to_string())
}
pub fn chunk_vk_filename() -> String {
    read_env_var("CHUNK_VK_FILENAME", "chunk_vk.vkey".to_string())
}

pub static CHUNK_PROTOCOL_FILENAME: LazyLock<String> =
    LazyLock::new(|| read_env_var("CHUNK_PROTOCOL_FILENAME", "chunk.protocol".to_string()));
pub static BATCH_PROTOCOL_FILENAME: LazyLock<String> =
    LazyLock::new(|| read_env_var("BATCH_PROTOCOL_FILENAME", "batch.protocol".to_string()));

pub static CHUNK_VK_FILENAME: LazyLock<String> = LazyLock::new(chunk_vk_filename);
pub static BATCH_VK_FILENAME: LazyLock<String> = LazyLock::new(batch_vk_filename);
pub static BUNDLE_VK_FILENAME: LazyLock<String> = LazyLock::new(bundle_vk_filename);

pub static DEPLOYMENT_CODE_FILENAME: LazyLock<String> =
    LazyLock::new(|| read_env_var("DEPLOYMENT_CODE_FILENAME", "evm_verifier.bin".to_string()));

// For our k=21 agg circuit, 12 means it can include 2**21 / (12 * 25) * 136.0 = 0.95M bytes
pub static BATCH_KECCAK_ROW: LazyLock<usize> =
    LazyLock::new(|| read_env_var("BATCH_KECCAK_ROW", 12));
