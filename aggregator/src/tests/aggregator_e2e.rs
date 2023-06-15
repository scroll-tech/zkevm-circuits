use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{halo2curves::bn256::Bn256, poly::commitment::Params};
use itertools::Itertools;
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::{halo2_proofs, utils::fs::gen_srs},
    pcs::kzg::{Bdfg21, Kzg},
};
use snark_verifier_sdk::{
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier},
    gen_pk,
    halo2::{gen_snark_shplonk, verify_snark_shplonk},
    CircuitExt,
};

use crate::{
    aggregation_layer_snark, compression_layer_evm, compression_layer_snark, layer_0,
    tests::mock_chunk::MockChunkCircuit, AggregationCircuit, ChunkHash, CompressionCircuit,
};

const CHUNKS_PER_BATCH: usize = 2;

// This test takes about 1 hour on CPU
#[ignore = "it takes too much time"]
#[test]
fn test_e2e() {
    env_logger::init();

    let dir = format!("data/{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    // inner circuit: Mock circuit
    let k0 = 19;
    // wide compression
    let k1 = 21;
    // thin compression
    let k2 = 26;
    // aggregation
    let k3 = 26;
    // thin compression
    let k4 = 26;

    let mut rng = test_rng();
    let params = gen_srs(k4);

    let mut chunks = (0..CHUNKS_PER_BATCH)
        .map(|_| ChunkHash::mock_chunk_hash(&mut rng))
        .collect_vec();
    for i in 0..CHUNKS_PER_BATCH - 1 {
        chunks[i + 1].prev_state_root = chunks[i].post_state_root;
    }

    // Proof for test circuit
    let circuits = chunks
        .iter()
        .map(|&chunk| MockChunkCircuit { chunk })
        .collect_vec();
    let layer_0_snarks = circuits
        .iter()
        .map(|&circuit| layer_0!(circuit, MockChunkCircuit, params, k0, path))
        .collect_vec();

    // Layer 1 proof compression
    std::env::set_var("VERIFY_CONFIG", "./configs/compression_wide.config");
    let layer_1_snarks = layer_0_snarks
        .iter()
        .map(|layer_0_snark| compression_layer_snark!(layer_0_snark, params, k1, path, 1))
        .collect_vec();

    // Layer 2 proof compression
    std::env::set_var("VERIFY_CONFIG", "./configs/compression_thin.config");
    let layer_2_snarks = layer_1_snarks
        .iter()
        .map(|layer_1_snark| compression_layer_snark!(layer_1_snark, params, k2, path, 2))
        .collect_vec();

    // layer 3 proof aggregation
    std::env::set_var("VERIFY_CONFIG", "./configs/aggregation.config");
    let layer_3_snark = aggregation_layer_snark!(layer_2_snarks, params, k3, path, 3, chunks);

    // layer 4 proof compression and final evm verification
    std::env::set_var("VERIFY_CONFIG", "./configs/compression_thin.config");
    compression_layer_evm!(layer_3_snark, params, k4, path, 4);
}
