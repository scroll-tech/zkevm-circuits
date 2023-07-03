use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr},
    poly::commitment::Params,
};
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::{halo2_proofs, utils::fs::gen_srs},
    pcs::kzg::{Bdfg21, Kzg},
};
use snark_verifier_sdk::{
    evm_verify, gen_evm_proof_shplonk, gen_evm_verifier, gen_pk, gen_snark_shplonk,
    verify_snark_shplonk, CircuitExt,
};

use crate::{
    compression_layer_evm, compression_layer_snark, layer_0, tests::mock_chunk::MockChunkCircuit,
    CompressionCircuit,
};

#[ignore = "it takes too much time"]
#[test]
fn test_mock_compression() {
    env_logger::init();

    if std::path::Path::new("data").is_dir() {
        println!("data folder already exists\n");
    } else {
        println!("Generating data folder used for testing\n");
        std::fs::create_dir("data").unwrap();
    }

    let dir = format!("data/{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 8;
    let k1 = 22;

    let mut rng = test_rng();
    let params = gen_srs(k1);

    // Proof for test circuit
    let circuit = MockChunkCircuit::random(&mut rng, true);
    let layer_0_snark = layer_0!(circuit, MockChunkCircuit, params, k0, path);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_wide.config");
    // layer 1 proof compression
    {
        let param = {
            let mut param = params;
            param.downsize(k1);
            param
        };
        let compression_circuit =
            CompressionCircuit::new(&param, layer_0_snark, true, &mut rng).unwrap();
        let instance = compression_circuit.instances();
        println!("instance length {:?}", instance.len());

        let mock_prover = MockProver::<Fr>::run(k1, &compression_circuit, instance).unwrap();

        mock_prover.assert_satisfied_par()
    }
}

// This test takes about 1 hour on CPU
#[ignore = "it takes too much time"]
#[test]
fn test_two_layer_proof_compression() {
    env_logger::init();

    if std::path::Path::new("data").is_dir() {
        println!("data folder already exists\n");
    } else {
        println!("Generating data folder used for testing\n");
        std::fs::create_dir("data").unwrap();
    }

    let dir = format!("data/{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 19;
    let k1 = 25;
    let k2 = 25;

    let mut rng = test_rng();
    let layer_2_params = gen_srs(k2);

    let circuit = MockChunkCircuit::random(&mut rng, true);
    let layer_0_snark = layer_0!(circuit, MockChunkCircuit, layer_2_params, k0, path);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_wide.config");
    let layer_1_snark = compression_layer_snark!(layer_0_snark, layer_2_params, k1, path, 1);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_thin.config");
    compression_layer_evm!(layer_1_snark, layer_2_params, k2, path, 2);
}
