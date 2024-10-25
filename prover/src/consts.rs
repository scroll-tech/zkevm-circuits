use std::sync::LazyLock;

use crate::utils::read_env_var;

// TODO: is it a good design to use LazyLock? Why not read env var each time?

pub fn bundle_vk_filename() -> String {
    read_env_var("BUNDLE_VK_FILENAME", "vk_bundle.vkey".to_string())
}
pub fn batch_vk_filename() -> String {
    read_env_var("BATCH_VK_FILENAME", "vk_batch.vkey".to_string())
}
pub fn chunk_vk_filename() -> String {
    read_env_var("CHUNK_VK_FILENAME", "vk_chunk.vkey".to_string())
}

/// The file descriptor for the JSON serialised SNARK [`protocol`][protocol] that
/// defines the [`CompressionCircuit`][compr_circuit] SNARK that uses halo2-based
/// [`SuperCircuit`][super_circuit].
///
/// [protocol]: snark_verifier::Protocol
/// [compr_circuit]: aggregator::CompressionCircuit
/// [super_circuit]: zkevm_circuits::super_circuit::SuperCircuit
pub static FD_HALO2_CHUNK_PROTOCOL: LazyLock<String> =
    LazyLock::new(|| read_env_var("HALO2_CHUNK_PROTOCOL", "chunk_halo2.protocol".to_string()));

/// The file descriptor for the JSON serialised SNARK [`protocol`][protocol] that
/// defines the [`CompressionCircuit`][compr_circuit] SNARK that uses sp1-based
/// STARK that is SNARKified using a halo2-backend.
///
/// [protocol]: snark_verifier::Protocol
/// [compr_circuit]: aggregator::CompressionCircuit
pub static FD_SP1_CHUNK_PROTOCOL: LazyLock<String> =
    LazyLock::new(|| read_env_var("SP1_CHUNK_PROTOCOL", "chunk_sp1.protocol".to_string()));

pub static CHUNK_VK_FILENAME: LazyLock<String> = LazyLock::new(chunk_vk_filename);
pub static BATCH_VK_FILENAME: LazyLock<String> = LazyLock::new(batch_vk_filename);
pub static BUNDLE_VK_FILENAME: LazyLock<String> = LazyLock::new(bundle_vk_filename);

pub static DEPLOYMENT_CODE_FILENAME: LazyLock<String> =
    LazyLock::new(|| read_env_var("DEPLOYMENT_CODE_FILENAME", "evm_verifier.bin".to_string()));

// For our k=21 agg circuit, 12 means it can include 2**21 / (12 * 25) * 136.0 = 0.95M bytes
pub static BATCH_KECCAK_ROW: LazyLock<usize> =
    LazyLock::new(|| read_env_var("BATCH_KECCAK_ROW", 12));
