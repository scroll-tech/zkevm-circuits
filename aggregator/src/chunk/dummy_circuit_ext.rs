use halo2_proofs::{halo2curves::bn256::Fr, plonk::Selector};
use snark_verifier_sdk::CircuitExt;

use super::dummy_circuit::DummyChunkHashCircuit;

impl CircuitExt<Fr> for DummyChunkHashCircuit {
    fn num_instance(&self) -> Vec<usize> {
        vec![32]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instance()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        None
    }

    fn selectors(_config: &Self::Config) -> Vec<Selector> {
        vec![]
    }
}
