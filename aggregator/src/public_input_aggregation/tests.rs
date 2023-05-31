use ark_std::{end_timer, start_timer, test_rng};
use halo2_base::utils::fs::gen_srs;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{gen_snark_shplonk, verify_snark_shplonk},
};
use zkevm_circuits::util::SubCircuit;

use crate::{BatchHashCircuit, LOG_DEGREE};

#[test]
fn test_pi_aggregation_mock_prover() {
    env_logger::init();

    let mut rng = test_rng();
    let chunks_per_batch = 8;

    let circuit = BatchHashCircuit::<Fr>::mock_batch_hash_circuit(&mut rng, chunks_per_batch);
    let instance = circuit.instance();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par()
}

#[test]
fn test_pi_aggregation_real_prover() {
    let mut rng = test_rng();
    let param = gen_srs(LOG_DEGREE);

    let chunks_per_batch = 16;

    let circuit = BatchHashCircuit::<Fr>::mock_batch_hash_circuit(&mut rng, chunks_per_batch);

    let timer = start_timer!(|| format!("key generation for k = {}", LOG_DEGREE));
    let pk = gen_pk(&param, &circuit, None);
    end_timer!(timer);

    let timer = start_timer!(|| "proving");
    let snark = gen_snark_shplonk(&param, &pk, circuit, &mut rng, None::<String>);
    end_timer!(timer);

    let timer = start_timer!(|| "verifying");
    assert!(verify_snark_shplonk::<BatchHashCircuit<Fr>>(
        &param,
        snark,
        pk.get_vk()
    ));
    end_timer!(timer);
}
