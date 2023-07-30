use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, poly::commitment::Params};
use itertools::Itertools;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};

use crate::{
    aggregation::AggregationCircuit, batch::BatchHash, constants::MAX_AGG_SNARKS, layer_0,
    ChunkHash,
};

use super::mock_chunk::MockChunkCircuit;

#[test]
fn test_aggregation_circuit() {
    env_logger::init();

    let k = 20;

    // This set up requires one round of keccak for chunk's data hash
    let circuit = build_new_aggregation_circuit(2);
    let instance = circuit.instances();
    let mock_prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
    mock_prover.assert_satisfied_par();
}

/// - Test aggregation proof generation and verification.
/// - Test a same pk can be used for various number of chunk proofs.
#[ignore = "it takes too much time"]
#[test]
fn test_aggregation_circuit_full() {
    env_logger::init();
    let process_id = process::id();

    let dir = format!("data/{process_id}",);
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    // This set up requires one round of keccak for chunk's data hash
    let circuit = build_new_aggregation_circuit(2);
    let instance = circuit.instances();
    let mock_prover = MockProver::<Fr>::run(25, &circuit, instance).unwrap();
    mock_prover.assert_satisfied_par();

    log::trace!("finished mock proving");

    let mut rng = test_rng();
    let param = gen_srs(20);

    let pk = gen_pk(&param, &circuit, None);
    log::trace!("finished pk generation for circuit");

    let snark = gen_snark_shplonk(&param, &pk, circuit.clone(), &mut rng, None::<String>);
    log::trace!("finished snark generation for circuit");

    assert!(verify_snark_shplonk::<AggregationCircuit>(
        &param,
        snark,
        pk.get_vk()
    ));
    log::trace!("finished verification for circuit");

    // This set up requires two rounds of keccak for chunk's data hash
    let circuit = build_new_aggregation_circuit(5);
    let snark = gen_snark_shplonk(&param, &pk, circuit, &mut rng, None::<String>);
    log::trace!("finished snark generation for circuit");

    assert!(verify_snark_shplonk::<AggregationCircuit>(
        &param,
        snark,
        pk.get_vk()
    ));
    log::trace!("finished verification for circuit");
}

fn build_new_aggregation_circuit(num_real_chunks: usize) -> AggregationCircuit {
    // inner circuit: Mock circuit
    let k0 = 8;

    let mut rng = test_rng();
    let params = gen_srs(k0);

    let mut chunks_without_padding = (0..num_real_chunks)
        .map(|_| ChunkHash::mock_random_chunk_hash_for_testing(&mut rng))
        .collect_vec();
    for i in 0..num_real_chunks - 1 {
        chunks_without_padding[i + 1].prev_state_root = chunks_without_padding[i].post_state_root;
    }
    let padded_chunk =
        ChunkHash::mock_padded_chunk_hash_for_testing(&chunks_without_padding[num_real_chunks - 1]);
    let chunks_with_padding = [
        chunks_without_padding,
        vec![padded_chunk; MAX_AGG_SNARKS - num_real_chunks],
    ]
    .concat();

    // ==========================
    // real chunks
    // ==========================
    let real_snarks = {
        let circuits = chunks_with_padding
            .iter()
            .take(num_real_chunks)
            .map(|&chunk| MockChunkCircuit::new(true, chunk))
            .collect_vec();
        circuits
            .iter()
            .map(|&circuit| layer_0!(circuit, MockChunkCircuit, params, k0, path))
            .collect_vec()
    };

    // ==========================
    // padded chunks
    // ==========================
    let padded_snarks = {
        let circuit = MockChunkCircuit::new(true, padded_chunk);
        let snark = layer_0!(circuit, MockChunkCircuit, params, k0, path);
        vec![snark; MAX_AGG_SNARKS - num_real_chunks]
    };

    // ==========================
    // batch
    // ==========================
    let batch_hash = BatchHash::construct(&chunks_with_padding);

    AggregationCircuit::new(
        &params,
        [real_snarks, padded_snarks].concat().as_ref(),
        rng,
        batch_hash,
    )
    .unwrap()
}
