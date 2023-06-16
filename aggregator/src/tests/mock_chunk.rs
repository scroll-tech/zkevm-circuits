use ark_std::test_rng;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use snark_verifier_sdk::CircuitExt;

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

    let circuit = MockChunkCircuit::random(&mut rng);
    let instance = circuit.instances();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par();
}
