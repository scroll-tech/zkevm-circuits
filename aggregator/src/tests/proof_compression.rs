use std::{fs, path::Path, process};

use ark_std::test_rng;
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::verify_proof,
    poly::{
        commitment::Params,
        kzg::{multiopen::VerifierSHPLONK, strategy::AccumulatorStrategy},
        VerificationStrategy,
    },
    transcript::TranscriptReadBuffer,
};
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::{halo2_proofs, utils::fs::gen_srs},
    pcs::kzg::{Bdfg21, Kzg},
    system::halo2::transcript::evm::EvmTranscript,
};
use snark_verifier_sdk::{
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier},
    gen_pk,
    halo2::{gen_snark_shplonk, verify_snark_shplonk},
    CircuitExt,
};

use crate::{tests::mock_chunk::MockChunkCircuit, CompressionCircuit};

#[test]
fn test_proof_compression() {
    env_logger::init();

    let dir = format!("data/{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 19;
    let k1 = 23;

    let mut rng = test_rng();
    let layer_1_params = gen_srs(k1);

    // Proof for test circuit
    let layer_0_snark = {
        let layer_0_params = {
            let mut params = layer_1_params.clone();
            params.downsize(k0);
            params
        };

        let circuit = MockChunkCircuit::random(&mut rng);
        let layer_0_pk = gen_pk(
            &layer_0_params,
            &circuit,
            Some(&path.join(Path::new("layer_0.pkey"))),
        );
        log::trace!("finished layer 0 pk generation for circuit");

        let layer_0_snark = gen_snark_shplonk(
            &layer_0_params,
            &layer_0_pk,
            circuit,
            &mut rng,
            Some(&path.join(Path::new("layer_0.snark"))),
        );
        log::trace!("finished layer 0 snark generation for circuit");

        assert!(verify_snark_shplonk::<MockChunkCircuit>(
            &layer_0_params,
            layer_0_snark.clone(),
            layer_0_pk.get_vk()
        ));

        log::trace!("finished layer 0 snark verification");
        log::trace!("proof size: {}", layer_0_snark.proof.len());
        log::trace!(
            "pi size: {}",
            layer_0_snark
                .instances
                .iter()
                .map(|x| x.len())
                .sum::<usize>()
        );

        log::trace!("layer 0 circuit instances");
        for (i, e) in circuit.instances()[0].iter().enumerate() {
            log::trace!("{}-th public input: {:?}", i, e);
        }

        layer_0_snark
    };

    // Layer 1 proof compression
    {
        std::env::set_var("VERIFY_CONFIG", "./configs/compression_wide.config");

        let compression_circuit =
            CompressionCircuit::new(&layer_1_params, layer_0_snark, true, &mut rng);
        let instances = compression_circuit.instances();

        let mock_prover = MockProver::<Fr>::run(k1, &compression_circuit, instances).unwrap();

        mock_prover.assert_satisfied_par();
    }
}

#[test]
fn test_two_layer_proof_compression() {
    env_logger::init();

    let dir = format!("data/{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 19;
    let k1 = 23;
    let k2 = 23;

    let mut rng = test_rng();
    let layer_2_params = gen_srs(k2);

    // Proof for test circuit
    let layer_0_snark = {
        let layer_0_params = {
            let mut params = layer_2_params.clone();
            params.downsize(k0);
            params
        };

        let circuit = MockChunkCircuit::random(&mut rng);
        let layer_0_pk = gen_pk(
            &layer_0_params,
            &circuit,
            Some(&path.join(Path::new("layer_0.pkey"))),
        );
        log::trace!("finished layer 0 pk generation for circuit");

        let layer_0_snark = gen_snark_shplonk(
            &layer_0_params,
            &layer_0_pk,
            circuit,
            &mut rng,
            Some(&path.join(Path::new("layer_0.snark"))),
        );
        log::trace!("finished layer 0 snark generation for circuit");

        assert!(verify_snark_shplonk::<MockChunkCircuit>(
            &layer_0_params,
            layer_0_snark.clone(),
            layer_0_pk.get_vk()
        ));

        log::trace!("finished layer 0 snark verification");
        log::trace!("proof size: {}", layer_0_snark.proof.len());
        log::trace!(
            "pi size: {}",
            layer_0_snark
                .instances
                .iter()
                .map(|x| x.len())
                .sum::<usize>()
        );

        log::trace!("layer 0 circuit instances");
        for (i, e) in circuit.instances()[0].iter().enumerate() {
            log::trace!("{}-th public input: {:?}", i, e);
        }

        layer_0_snark
    };

    // Layer 1 proof compression
    let layer_1_snark = {
        std::env::set_var("VERIFY_CONFIG", "./configs/compression_wide.config");

        let layer_1_params = {
            let mut params = layer_2_params.clone();
            params.downsize(k1);
            params
        };

        let compression_circuit =
            CompressionCircuit::new(&layer_1_params, layer_0_snark, true, &mut rng);
        let instances = compression_circuit.instances();

        log::trace!("layer 1 circuit instances");
        for (i, e) in compression_circuit.instances()[0].iter().enumerate() {
            log::trace!("{}-th public input: {:?}", i, e);
        }

        let layer_1_pk = gen_pk(
            &layer_1_params,
            &compression_circuit,
            Some(&path.join(Path::new("layer_1.pkey"))),
        );
        log::trace!("finished layer 1 pk generation");

        let layer_1_proof = gen_evm_proof_shplonk(
            &layer_1_params,
            &layer_1_pk,
            compression_circuit.clone(),
            instances.clone(),
            &mut rng,
        );

        log::trace!("finished layer 1 aggregation generation");
        log::trace!("proof size: {}", layer_1_proof.len());
        log::trace!("pi size: {:?}", compression_circuit.num_instance());

        {
            let mut transcript =
                TranscriptReadBuffer::<_, G1Affine, _>::init(layer_1_proof.as_slice());
            let instances = instances
                .iter()
                .map(|instances| instances.as_slice())
                .collect::<Vec<_>>();

            let res = VerificationStrategy::<_, VerifierSHPLONK<_>>::finalize(
                verify_proof::<_, VerifierSHPLONK<_>, _, EvmTranscript<_, _, _, _>, _>(
                    &layer_1_params,
                    layer_1_pk.get_vk(),
                    AccumulatorStrategy::new(&layer_1_params),
                    &[instances.as_slice()],
                    &mut transcript,
                )
                .unwrap(),
            );
            log::trace!("sanity check layer 1 proof: {}", res);
        }

        // verify proof via EVM
        let deployment_code = gen_evm_verifier::<CompressionCircuit, Kzg<Bn256, Bdfg21>>(
            &layer_1_params,
            layer_1_pk.get_vk(),
            compression_circuit.num_instance(),
            Some(&path.join(Path::new("layer_1.sol"))),
        );
        log::trace!("finished layer 1 bytecode generation");

        evm_verify(
            deployment_code,
            compression_circuit.instances(),
            layer_1_proof,
        );
        log::trace!("layer 1 evm verification finished");

        // build the snark for next layer
        let layer_1_snark = gen_snark_shplonk(
            &layer_1_params,
            &layer_1_pk,
            compression_circuit,
            &mut rng,
            Some(&path.join(Path::new("layer_1.snark"))),
        );
        log::trace!("finished layer 1 snark generation for circuit");

        assert!(verify_snark_shplonk::<CompressionCircuit>(
            &layer_1_params,
            layer_1_snark.clone(),
            layer_1_pk.get_vk()
        ));
        layer_1_snark
    };

    // Layer 2 proof compression
    {
        std::env::set_var("VERIFY_CONFIG", "./configs/compression_thin.config");

        let compression_circuit =
            CompressionCircuit::new(&layer_2_params, layer_1_snark, false, &mut rng);

        let instances = compression_circuit.instances();
        let mock_prover =
            MockProver::<Fr>::run(k2, &compression_circuit, instances.clone()).unwrap();

        mock_prover.assert_satisfied_par();

        log::trace!("layer 2 circuit instances");
        for (i, e) in compression_circuit.instances()[0].iter().enumerate() {
            log::trace!("{}-th public input: {:?}", i, e);
        }
        let layer_2_pk = gen_pk(
            &layer_2_params,
            &compression_circuit,
            Some(&path.join(Path::new("layer_2.pkey"))),
        );
        log::trace!("finished layer 2 pk generation");

        let layer_2_proof = gen_evm_proof_shplonk(
            &layer_2_params,
            &layer_2_pk,
            compression_circuit.clone(),
            instances,
            &mut rng,
        );

        log::trace!("finished layer 2 aggregation generation");
        log::trace!("proof size: {}", layer_2_proof.len());

        // verify proof via EVM
        let deployment_code = gen_evm_verifier::<CompressionCircuit, Kzg<Bn256, Bdfg21>>(
            &layer_2_params,
            layer_2_pk.get_vk(),
            compression_circuit.num_instance(),
            Some(&path.join(Path::new("layer_2.sol"))),
        );
        log::trace!("finished layer 2 bytecode generation");

        evm_verify(
            deployment_code,
            compression_circuit.instances(),
            layer_2_proof,
        );
        log::trace!("layer 2 evm verification finished");
    }
}
