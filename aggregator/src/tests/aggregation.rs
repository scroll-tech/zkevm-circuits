use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, poly::commitment::Params};
use itertools::Itertools;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};

use crate::{
    aggregation::AggregationCircuit, batch::BatchHash,
    chunk::dummy_chunk_circuit::DummyChunkHashCircuit, constants::MAX_AGG_SNARKS, layer_0,
    ChunkHash,
};

use super::mock_chunk::MockChunkCircuit;

#[ignore = "it takes too much time"]
#[test]
fn test_aggregation_circuit() {
    env_logger::init();
    // let process_id = process::id();

    // let dir = format!("data/{}", process_id);
    // let path = Path::new(dir.as_str());
    // fs::create_dir(path).unwrap();

    // let mut rng = test_rng();
    // let param = gen_srs(23);

    // {
    //     // This set up requires one round of keccak for chunk's data hash
    //     let circuit = build_new_aggregation_circuit(2);
    //     let instance = circuit.instances();
    //     let mock_prover = MockProver::<Fr>::run(25, &circuit, instance).unwrap();
    //     mock_prover.assert_satisfied_par();

    //     let pk = gen_pk(
    //         &param, &circuit, // Some(&$path.join(Path::new("layer_0.pkey"))),
    //         None,
    //     );
    //     log::trace!("finished layer 0 pk generation for circuit");

    //     let snark = gen_snark_shplonk(&param, &pk, circuit.clone(), &mut rng, None::<String>);
    //     log::trace!("finished layer 0 snark generation for circuit");

    //     assert!(verify_snark_shplonk::<AggregationCircuit>(
    //         &param,
    //         snark.clone(),
    //         pk.get_vk()
    //     ));
    // }

    {
        // This set up requires two rounds of keccak for chunk's data hash
        let circuit = build_new_aggregation_circuit(10);
        let instance = circuit.instances();

        let mock_prover = MockProver::<Fr>::run(19, &circuit, instance).unwrap();

        mock_prover.assert_satisfied_par();
    }
}

fn build_new_aggregation_circuit(num_chunks: usize) -> AggregationCircuit {
    // inner circuit: Mock circuit
    let k0 = 8;

    let mut rng = test_rng();
    let params = gen_srs(k0);

    let mut chunks_without_padding = (0..num_chunks)
        .map(|_| ChunkHash::mock_random_chunk_hash_for_testing(&mut rng))
        .collect_vec();
    for i in 0..num_chunks - 1 {
        chunks_without_padding[i + 1].prev_state_root = chunks_without_padding[i].post_state_root;
    }
    // ==========================
    // real chunks
    // ==========================
    let real_snarks = {
        let circuits = chunks_without_padding
            .iter()
            .map(|&chunk| MockChunkCircuit::new(false, 0, chunk))
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
        let dummy_chunk = ChunkHash::dummy_chunk_hash(&chunks_without_padding[num_chunks - 1]);
        let circuit = DummyChunkHashCircuit::new(dummy_chunk);
        let snark = layer_0!(circuit, DummyChunkHashCircuit, params, k0, path);
        vec![snark; MAX_AGG_SNARKS - num_chunks]
    };

    // ==========================
    // batch
    // ==========================
    let batch_hash = BatchHash::construct(&chunks_without_padding);

    AggregationCircuit::new(
        &params,
        [real_snarks, padded_snarks].concat().as_ref(),
        rng,
        batch_hash,
    )
}
