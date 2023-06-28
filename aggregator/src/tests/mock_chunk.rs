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
pub(crate) struct MockChunkCircuit {
    pub(crate) is_fresh: bool,
    pub(crate) chain_id: u64,
    pub(crate) chunk: ChunkHash,
}

impl MockChunkCircuit {
    #[allow(dead_code)]
    pub(crate) fn new(is_fresh: bool, chain_id: u64, chunk: ChunkHash) -> Self {
        MockChunkCircuit {
            is_fresh,
            chain_id,
            chunk,
        }
    }
}

#[test]
fn test_mock_chunk_prover() {
    let mut rng = test_rng();

    let circuit = MockChunkCircuit::random(&mut rng, true);
    let instance = circuit.instances();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par();

    let circuit = MockChunkCircuit::random(&mut rng, false);
    let instance = circuit.instances();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par();
}
