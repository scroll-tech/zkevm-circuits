use std::{fs, path::Path, process};

use ark_std::test_rng;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, poly::commitment::Params};
use itertools::Itertools;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{gen_snark_shplonk, verify_snark_shplonk},
    CircuitExt,
};

use crate::{AggregationCircuit, ChunkHash, CompressionCircuit};

use super::mock_chunk::MockChunkCircuit;

const CHUNKS_PER_BATCH: usize = 2;

// This test takes about 1 hour on CPU
#[ignore = "it takes too much time"]
#[test]
fn test_aggregation_circuit() {
    let process_id = process::id();

    let dir = format!("data/{}", process_id);
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 19;
    let k1 = 25;
    let k2 = 25;
    let layer_2_params = gen_srs(k2);

    let mut rng = test_rng();
    let mut chunks = (0..CHUNKS_PER_BATCH)
        .map(|_| ChunkHash::mock_chunk_hash(&mut rng))
        .collect_vec();
    for i in 0..CHUNKS_PER_BATCH - 1 {
        chunks[i + 1].prev_state_root = chunks[i].post_state_root;
    }

    // build layer 0 snarks
    let layer_0_snarks = {
        let layer_0_params = {
            let mut params = layer_2_params.clone();
            params.downsize(k0);
            params
        };

        let circuits = chunks
            .iter()
            .map(|&chunk| MockChunkCircuit { chunk })
            .collect_vec();
        log::trace!("finished layer 0 pk generation for circuit");
        let layer_0_pk = gen_pk(
            &layer_0_params,
            &circuits[0],
            Some(&path.join(Path::new("layer_0.pkey"))),
        );
        log::trace!("finished layer 0 pk generation for circuit");

        let layer_0_snarks = circuits
            .iter()
            .enumerate()
            .map(|(i, circuit)| {
                let snark = gen_snark_shplonk(
                    &layer_0_params,
                    &layer_0_pk,
                    *circuit,
                    &mut rng,
                    Some(&path.join(Path::new(format!("layer_0_{}.snark", i).as_str()))),
                );
                log::trace!("finished {}-th snark", i);
                snark
            })
            .collect_vec();
        log::trace!("finished layer 0 snark generation for circuit");

        // sanity checks
        layer_0_snarks.iter().for_each(|snark| {
            assert!(verify_snark_shplonk::<MockChunkCircuit>(
                &layer_0_params,
                snark.clone(),
                layer_0_pk.get_vk()
            ))
        });
        log::trace!("finished layer 0 snark verification");

        layer_0_snarks
    };

    // build layer 1 the compression circuit
    let layer_1_snarks = {
        std::env::set_var("VERIFY_CONFIG", "./configs/compression_wide.config");

        let layer_1_params = {
            let mut params = layer_2_params.clone();
            params.downsize(k1);
            params
        };

        let compression_circuit =
            CompressionCircuit::new(&layer_1_params, layer_0_snarks[0].clone(), true, &mut rng);

        let layer_1_pk = gen_pk(&layer_1_params, &compression_circuit, None);

        log::trace!("finished layer 1 pk gen");
        let mut layer_1_snarks = vec![];

        for (i, snark) in layer_0_snarks.iter().enumerate() {
            let compression_circuit =
                CompressionCircuit::new(&layer_1_params, snark.clone(), true, &mut rng);

            let layer_1_snark = gen_snark_shplonk(
                &layer_1_params,
                &layer_1_pk.clone(),
                compression_circuit.clone(),
                &mut rng,
                Some(&path.join(Path::new(format!("layer_1_{}.snark", i).as_str()))),
            );

            log::trace!("finished layer 1 {}-th snark gen", i);

            log::trace!("{}-th compression circuit instance:", i);
            for (i, e) in compression_circuit.instances()[0].iter().enumerate() {
                log::trace!("{}-th {:?}", i, e,)
            }

            layer_1_snarks.push(layer_1_snark)
        }
        layer_1_snarks
    };

    // build layer 2 the aggregation circuit
    {
        std::env::set_var("VERIFY_CONFIG", "./configs/aggregation.config");
        log::trace!("aggregation circuit");

        let aggregation_circuit =
            AggregationCircuit::new(&layer_2_params, &layer_1_snarks, rng, &chunks);
        log::trace!("snark");
        for (i, snark) in aggregation_circuit.snarks.iter().enumerate() {
            log::trace!("{:?} {:?}", i, snark.instances);
        }
        log::trace!("flattened instance");
        for (i, pi) in aggregation_circuit.flattened_instances.iter().enumerate() {
            log::trace!("{:?} {:?}", i, pi);
        }

        let instances = aggregation_circuit.instances();

        log::trace!("start mock proving");
        let mock_prover = MockProver::<Fr>::run(k1, &aggregation_circuit, instances).unwrap();

        mock_prover.assert_satisfied_par();
    }
}
