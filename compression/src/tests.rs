use crate::{circuit::to_ce_snark, CompressionCircuit};
use aggregator::MockChunkCircuit;
use ark_std::{end_timer, start_timer, test_rng};
use ce_snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::{halo2_proofs, utils::fs::gen_srs},
    pcs::kzg::{Bdfg21, KzgAs},
};
use ce_snark_verifier_sdk::{
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier},
    gen_pk,
    halo2::gen_snark_shplonk,
    CircuitExt, Snark,
};
use halo2_proofs::{dev::MockProver, poly::commitment::Params, poly::kzg::commitment::ParamsKZG};
use halo2curves::bn256::{Bn256, Fr};
use std::{fs, path::Path, process};

#[ignore = "it takes too much time"]
#[test]
fn test_mock_compression() {
    // env_logger::init();

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
    let circuit = MockChunkCircuit::random(&mut rng, false, false);
    let layer_0_snark = layer_0(&circuit, params.clone(), k0, path);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_wide.config");
    // layer 1 proof compression
    {
        let param = {
            let mut param = params;
            param.downsize(k1);
            param
        };
        let compression_circuit =
            CompressionCircuit::new_from_ce_snark(&param, layer_0_snark, true, &mut rng).unwrap();
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

    let circuit = MockChunkCircuit::random(&mut rng, false, false);
    let layer_0_snark = layer_0(&circuit, layer_2_params.clone(), k0, path);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_wide.config");
    let layer_1_snark = compression_layer_snark(layer_0_snark, layer_2_params.clone(), k1, 1);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_thin.config");
    verify_compression_layer_evm(layer_1_snark, layer_2_params, k2, path, 2);
}

#[test]
fn test_to_ce_snark() {
    let mut rng = test_rng();
    let k0 = 8;

    let path = Path::new("unused");

    let circuit = MockChunkCircuit::random(&mut rng, false, false);
    let base_snark = layer_0(&circuit, gen_srs(8), k0, path);
    assert_snark_roundtrip(&base_snark);
}

fn from_ce_snark(snark: &Snark) -> snark_verifier_sdk::Snark {
    serde_json::from_str(&serde_json::to_string(snark).unwrap()).unwrap()
}

fn assert_snark_roundtrip(snark: &Snark) {
    assert_eq!(
        serde_json::to_string(snark).unwrap(),
        serde_json::to_string(&to_ce_snark(&from_ce_snark(snark))).unwrap()
    );
}

fn layer_0(
    circuit: &MockChunkCircuit,
    param: ParamsKZG<Bn256>,
    degree: u32,
    _path: &Path,
) -> Snark {
    let timer = start_timer!(|| "gen layer 0 snark");

    let param = {
        let mut param = param;
        param.downsize(degree);
        param
    };

    let pk = gen_pk(&param, circuit, None);
    log::trace!("finished layer 0 pk generation for circuit");

    let snark = gen_snark_shplonk(&param, &pk, circuit.clone(), None::<String>);
    log::trace!("finished layer 0 snark generation for circuit");

    // assert!(verify_snark_shplonk(&param, snark.clone(), pk.get_vk()));

    log::trace!("finished layer 0 snark verification");
    log::trace!("proof size: {}", snark.proof.len());
    log::trace!(
        "pi size: {}",
        snark.instances.iter().map(|x| x.len()).sum::<usize>()
    );

    log::trace!("layer 0 circuit instances");
    for (i, e) in circuit.instances()[0].iter().enumerate() {
        log::trace!("{}-th public input: {:?}", i, e);
    }
    end_timer!(timer);
    snark
}

fn compression_layer_snark(
    previous_snark: Snark,
    param: ParamsKZG<Bn256>,
    degree: u32,
    layer_index: usize,
) -> Snark {
    let timer = start_timer!(|| format!("gen layer {} snark", layer_index));

    let param = {
        let mut param = param.clone();
        param.downsize(degree);
        param
    };

    let compression_circuit = CompressionCircuit::new_from_ce_snark(
        &param,
        previous_snark.clone(),
        layer_index == 1,
        test_rng(),
    )
    .unwrap();

    let pk = gen_pk(&param, &compression_circuit, None);
    // build the snark for next layer
    let snark = gen_snark_shplonk(
        &param,
        &pk,
        compression_circuit.clone(),
        // &mut rng,
        None::<String>, // Some(&$path.join(Path::new("layer_1.snark"))),
    );
    log::trace!(
        "finished layer {} snark generation for circuit",
        layer_index
    );

    // assert!(verify_snark_shplonk::<CompressionCircuit>(
    //     &param,
    //     snark.clone(),
    //     pk.get_vk()
    // ));

    end_timer!(timer);
    snark
}

fn verify_compression_layer_evm(
    previous_snark: Snark,
    param: ParamsKZG<Bn256>,
    degree: u32,
    path: &Path,
    layer_index: usize,
) {
    let timer = start_timer!(|| format!("gen layer {} snark", layer_index));

    let param = {
        let mut param = param.clone();
        param.downsize(degree);
        param
    };

    let compression_circuit =
        CompressionCircuit::new_from_ce_snark(&param, previous_snark, false, test_rng()).unwrap();

    let instances = compression_circuit.instances();

    let pk = gen_pk(&param, &compression_circuit, None);
    // build the snark for next layer
    let proof = gen_evm_proof_shplonk(&param, &pk, compression_circuit.clone(), instances.clone());

    log::trace!("finished layer 4 aggregation generation");
    log::trace!("proof size: {}", proof.len());

    // verify proof via EVM
    let deployment_code = gen_evm_verifier::<CompressionCircuit, KzgAs<Bn256, Bdfg21>>(
        &param,
        pk.get_vk(),
        compression_circuit.num_instance(),
        Some(&path.join(Path::new("contract.sol"))),
    );
    log::trace!("finished layer 4 bytecode generation");

    evm_verify(
        deployment_code,
        compression_circuit.instances(),
        proof.clone(),
    );
    log::trace!("layer 2 evm verification finished");

    end_timer!(timer);
}
