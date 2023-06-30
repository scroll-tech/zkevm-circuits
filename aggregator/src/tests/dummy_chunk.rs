use ark_std::test_rng;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

use crate::{chunk::dummy_circuit::DummyChunkHashCircuit, ChunkHash};

#[test]
fn test_dummy_chunk_prover() {
    env_logger::init();

    let mut rng = test_rng();
    let chunk = ChunkHash::mock_chunk_hash(&mut rng);
    let dummy_chunk = ChunkHash::dummy_chunk_hash(&chunk);
    let dummy_chunk_circuit = DummyChunkHashCircuit::new(dummy_chunk);
    let instance = dummy_chunk_circuit.instance();

    let mock_prover = MockProver::<Fr>::run(6, &dummy_chunk_circuit, vec![instance]).unwrap();

    mock_prover.assert_satisfied_par();
}
