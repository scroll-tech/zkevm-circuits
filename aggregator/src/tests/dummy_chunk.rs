use ark_std::test_rng;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::verify_snark_shplonk;

use crate::{chunk::dummy_circuit::DummyChunkHashCircuit, constants::LOG_DEGREE, ChunkHash};

#[test]
fn test_dynamic_chunk_prover() {
    env_logger::init();

    let mut rng = test_rng();
    let chunk = ChunkHash::mock_chunk_hash(&mut rng);
    let dummy_chunk = ChunkHash::dummy_chunk_hash(&chunk);
    let dummy_chunk_circuit = DummyChunkHashCircuit::new(dummy_chunk);
    let instance = dummy_chunk_circuit.instance();
    log::trace!("generated dummy circuit");

    let mock_prover = MockProver::<Fr>::run(6, &dummy_chunk_circuit, vec![instance]).unwrap();
    mock_prover.assert_satisfied_par();
    log::trace!("finished mock proving");

    let param = gen_srs(LOG_DEGREE);
    log::trace!("finished parameter generation");

    let (pk, snark) = dummy_chunk.dummy_snark(&param, &mut rng);
    log::trace!("finished dummy snark generation");

    assert!(verify_snark_shplonk::<DummyChunkHashCircuit>(
        &param,
        snark,
        pk.get_vk()
    ));
    log::trace!("verified dummy snark");
}
