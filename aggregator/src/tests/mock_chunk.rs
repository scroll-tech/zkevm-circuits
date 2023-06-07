use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr},
};
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs,
    pcs::kzg::{Bdfg21, Kzg},
};
use snark_verifier_sdk::{
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier},
    gen_pk,
    halo2::{gen_snark_shplonk, verify_snark_shplonk},
    CircuitExt,
};

use crate::{ChunkHash, LOG_DEGREE};

mod circuit;
mod circuit_ext;
mod config;

#[derive(Debug, Default, Clone, Copy)]
/// A mock chunk circuit
///
/// This mock chunk circuit simulates a zkEVM circuit.
/// It's public inputs consists of 64 elements:
/// - data hash
/// - public input hash
pub struct MockChunkCircuit {
    pub(crate) chunk: ChunkHash,
}

#[test]
fn test_mock_chunk_prover() {
    env_logger::init();

    let mut rng = test_rng();

    let param = gen_srs(LOG_DEGREE);
    let circuit = MockChunkCircuit::random(&mut rng);
    let instance = circuit.instances();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par();

    let timer = start_timer!(|| format!("key generation for k = {}", LOG_DEGREE));
    let pk = gen_pk(&param, &circuit, None);
    end_timer!(timer);

    let timer = start_timer!(|| "proving");
    let snark = gen_snark_shplonk(&param, &pk, circuit, &mut rng, None::<String>);
    end_timer!(timer);

    log::trace!("{:?}", circuit.chunk.data_hash);
    log::trace!("{:?}", circuit.chunk.public_input_hash());
    for (i, e) in snark.instances[0].iter().enumerate() {
        log::trace!("{}-th: {:?}", i, e);
    }

    let timer = start_timer!(|| "verifying");
    assert!(verify_snark_shplonk::<MockChunkCircuit>(
        &param,
        snark.clone(),
        pk.get_vk()
    ));
    end_timer!(timer);

    let proof = gen_evm_proof_shplonk(
        &param,
        &pk,
        circuit.clone(),
        snark.instances.clone(),
        &mut rng,
    );
    log::trace!("proof size: {}", proof.len());

    // verify proof via EVM
    let deployment_code = gen_evm_verifier::<MockChunkCircuit, Kzg<Bn256, Bdfg21>>(
        &param,
        pk.get_vk(),
        circuit.num_instance(),
        None,
    );
    log::trace!("finished layer 2 bytecode generation");

    evm_verify(deployment_code, circuit.instances(), proof.clone());
    log::trace!("layer 2 evm verification finished");
}
