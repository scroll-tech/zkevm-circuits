use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{halo2curves::bn256::Bn256, poly::commitment::Params};
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
    compression_layer_evm, compression_layer_snark, layer_0, tests::mock_chunk::MockChunkCircuit,
    CompressionCircuit,
};

#[test]
fn test_proof_compression() {
    env_logger::init();

    let dir = format!("data/{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 19;
    let k1 = 25;

    let mut rng = test_rng();
    let layer_1_params = gen_srs(k1);

    // Proof for test circuit
    let circuit = MockChunkCircuit::random(&mut rng);
    let layer_0_snark = layer_0!(circuit, MockChunkCircuit, layer_1_params, k0, path);

    std::env::set_var("VERIFY_CONFIG", "./configs/compression_thin.config");
    compression_layer_evm!(layer_0_snark, layer_1_params, k1, path, 1)
}

// This test takes about 1 hour on CPU
#[ignore = "it takes too much time"]
#[test]
fn test_two_layer_proof_compression() {
    env_logger::init();

    let dir = format!("data/{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 19;
    let k1 = 25;
    let k2 = 25;

    let mut rng = test_rng();
    let layer_2_params = gen_srs(k2);

    let circuit = MockChunkCircuit::random(&mut rng);
    let layer_0_snark = layer_0!(circuit, MockChunkCircuit, layer_2_params, k0, path);

    std::env::set_var("VERIFY_CONFIG", "./configs/compression_wide.config");
    let layer_1_snark = compression_layer_snark!(layer_0_snark, layer_2_params, k1, path, 1);

    std::env::set_var("VERIFY_CONFIG", "./configs/compression_thin.config");
    compression_layer_evm!(layer_1_snark, layer_2_params, k2, path, 2);
}
